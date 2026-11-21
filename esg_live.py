"""Live runs of the reference evaluator behind a NATS JetStream broker.

Roles (each a separate process and broker user; see nats_test.conf.template):
  guard   subscribes to requests, reads substrate state from a JetStream KV
          bucket, evaluates the policy, and either publishes the command to the
          recipient's durable inbox or publishes a policy_block record. It also
          owns the state store and stamps sensor timestamps with its own clock.
  run     closed-loop load generator. One connection is the requesting agent
          (it can publish on its own request subject and nothing else); a
          second connection is the experimenter, who asks the guard host to set
          the substrate state before each request and observes outcomes.
  inproc  times evaluate() alone, no broker.

Nothing here talks to a device adapter. All subjects are under test.skillguard.
"""
import argparse, asyncio, json, os, platform, statistics, sys, time

from skillguard_ref import evaluate, load_policy
from workload import (ACTION, BENIGN, CLAIM, RECIPIENT, SENDER, VARIANTS, build_state, envelope)

HERE = os.path.dirname(os.path.abspath(__file__))
TYPES = {"register", "heartbeat", "status", "command", "result", "delegation", "cancel", "log",
         "broadcast", "task.progress"}


def policies():
    full = load_policy(json.load(open(os.path.join(HERE, "policy_unlock_front_door.json"))))
    lo = load_policy({"action": full["action"], "deny": [],
                      "guards": [g for g in full["guards"] if g["id"] in ("G1", "G2", "G3", "G4")]})
    table = {"full": {full["action"]: full}, "lo": {lo["action"]: lo}}
    extra = os.path.join(HERE, "policies")
    if os.path.isdir(extra):
        table["multi"] = {}
        for f in sorted(os.listdir(extra)):
            if f.endswith(".json") and f != "accepting_states.json":
                p = load_policy(json.load(open(os.path.join(extra, f))))
                table["multi"][p["action"]] = p
    return table


def envelope_error(env):
    if not isinstance(env, dict):
        return "envelope is not an object"
    for k in ("id", "type", "sender_id", "recipient_id", "task_id", "payload"):
        if k not in env:
            return f"envelope lacks {k}"
    if env["type"] not in TYPES:
        return f"unknown envelope type {env['type']!r}"
    if env["type"] != "command":
        return "only command envelopes may actuate"
    if not isinstance(env["payload"], dict) or not isinstance(env["payload"].get("action"), str):
        return "payload lacks a string action"
    return None


def quantiles(xs):
    xs = sorted(xs)
    q = lambda p: xs[min(len(xs) - 1, int(round(p * (len(xs) - 1))))]
    return {"n": len(xs), "median": statistics.median(xs), "p95": q(0.95), "p99": q(0.99), "max": xs[-1]}


async def connect(url, user, pw):
    import nats
    return await nats.connect(url, user=user, password=pw, name=user, max_reconnect_attempts=2)


# ---------------------------------------------------------------- guard ----
async def guard(args):
    from nats.js.errors import KeyNotFoundError
    nc = await connect(args.nats, "guard", args.pw_guard)
    js = nc.jetstream()
    kv = await js.create_key_value(bucket="ESG_TEST_STATE", history=1)
    try:
        await js.add_stream(name="ESG_TEST_INBOX", subjects=["test.skillguard.*.inbox.>"], max_msgs=200000)
    except Exception as e:  # already exists
        print("stream:", e, file=sys.stderr)
    table = policies()

    async def set_state(msg):  # experimenter control channel; timestamps use this host's clock
        spec = json.loads(msg.data)
        if "raw" in spec:  # full document; {"$age": s} becomes (this host's clock - s)
            from esg_breadth import resolve
            await kv.put(spec.get("key", "home"), json.dumps(resolve(spec["raw"], time.time())).encode())
            await msg.respond(b"ok")
            return
        state = build_state(time.time(), **{k: (tuple(v) if k == "scope" and isinstance(v, list) else v)
                                           for k, v in spec.get("state", {}).items()})
        state.update(spec.get("extra", {}))
        await kv.put(spec.get("key", "home"), json.dumps(state).encode())
        await msg.respond(b"ok")
    await nc.subscribe("test.skillguard.ctl.set_state", cb=set_state)

    sub = await nc.subscribe("test.skillguard.*.req.*")
    print("guard ready", flush=True)
    async for msg in sub.messages:
        t0 = time.perf_counter_ns()
        _, _, ns, _, attested = msg.subject.split(".")
        if ns == "relay":  # unguarded reference path: forward to the inbox with no check at all
            try:
                rid = json.loads(msg.data).get("id")
            except Exception:
                rid = None
            await js.publish("test.skillguard.relay.inbox.iot_agent",
                             json.dumps({"req": rid, "allow": True, "failed": [], "ns": ns, "t_kv_ns": 0,
                                         "t_eval_ns": 0, "t_guard_ns": time.perf_counter_ns() - t0}).encode())
            continue
        out = {"allow": False, "failed": [], "ns": ns}
        t_kv = t_eval = 0
        try:
            env = json.loads(msg.data)
        except Exception:
            env = None
        err = envelope_error(env)
        if err:
            out["failed"] = [("envelope", err)]
        elif env["sender_id"] != attested:
            out["failed"] = [("identity", f"sender_id {env['sender_id']!r} does not match connection identity {attested!r}")]
        elif env["payload"]["action"] not in table.get(ns, {}):
            out["failed"] = [("policy", f"no policy for {env['payload']['action']!r}: default deny")]
        else:
            policy = table[ns][env["payload"]["action"]]
            k0 = time.perf_counter_ns()
            try:
                state = json.loads((await kv.get(env["payload"].get("state_key", "home"))).value)
            except KeyNotFoundError:
                state = None
            k1 = time.perf_counter_ns()
            if state is None:
                out["failed"] = [("state", "substrate state unavailable")]
            else:
                out["allow"], out["failed"] = evaluate(policy, env, state, time.time())
            t_kv, t_eval = k1 - k0, time.perf_counter_ns() - k1
        out["req"] = env.get("id") if isinstance(env, dict) else None
        out["t_kv_ns"], out["t_eval_ns"] = t_kv, t_eval
        out["t_guard_ns"] = time.perf_counter_ns() - t0
        body = json.dumps(out).encode()
        if out["allow"]:  # durable per-agent inbox, plus the audit mirror
            await js.publish(f"test.skillguard.{ns}.inbox.{env['recipient_id']}", body)
            await nc.publish(f"test.skillguard.{ns}.outbox.guard", body)
        else:
            await nc.publish(f"test.skillguard.{ns}.policy_block", body)


# ------------------------------------------------------------------ run ----
class Client:
    def __init__(self, agent, exp):
        self.agent, self.exp, self.wait = agent, exp, {}

    async def start(self):
        async def seen(msg):
            d = json.loads(msg.data)
            f = self.wait.pop(d.get("req"), None)
            if f and not f.done():
                f.set_result((time.perf_counter_ns(), d, msg.subject))
        await self.exp.subscribe("test.skillguard.*.inbox.>", cb=seen)
        await self.exp.subscribe("test.skillguard.*.policy_block", cb=seen)
        await self.exp.flush()

    async def set_state(self, state=None, extra=None, key="home"):
        await self.exp.request("test.skillguard.ctl.set_state",
                               json.dumps({"state": state or {}, "extra": extra or {}, "key": key}).encode(), timeout=5)

    async def ask(self, ns, env, subject_sender=SENDER, timeout=5):
        fut = asyncio.get_running_loop().create_future()
        self.wait[env["id"]] = fut
        t0 = time.perf_counter_ns()
        await self.agent.publish(f"test.skillguard.{ns}.req.{subject_sender}", json.dumps(env).encode())
        t1, d, subj = await asyncio.wait_for(fut, timeout)
        return (t1 - t0) / 1e3, d, subj  # microseconds


def jsonable(over):
    return {k: (list(v) if isinstance(v, tuple) else v) for k, v in over.items()}


async def run(args):
    agent = await connect(args.nats, "manager_agent", args.pw_mgr)
    exp = await connect(args.nats, "experimenter", args.pw_exp)
    c = Client(agent, exp)
    await c.start()
    res = {"label": args.label, "scale": args.scale, "publisher_host_role": args.label,
           "python": platform.python_version(), "started": time.time()}
    n = 0
    for _ in range(50):  # warm-up, not recorded
        await c.set_state()
        n += 1
        await c.ask("full", envelope(f"w{n}"))

    for ns in (("full", "lo") if args.scale == 1 else ("full",)):
        r = {"per_variant": {}, "lat_us": [], "t_eval_ns": [], "t_kv_ns": [], "t_guard_ns": [],
             "benign_admitted": 0, "benign_n": 0, "reason_ids": {}}
        for rep in range(args.scale):
            for name, muts in VARIANTS.items():
                for i, m in enumerate(muts):
                    await c.set_state(jsonable(m))
                    lat, d, _ = await c.ask(ns, envelope(f"{ns}-a{rep}-{name[:5]}-{i}"))
                    pv = r["per_variant"].setdefault(name, {"n": 0, "admitted": 0})
                    pv["n"] += 1; pv["admitted"] += d["allow"]
                    for rid, _why in d["failed"]:
                        r["reason_ids"].setdefault(name, {}).setdefault(rid, 0)
                        r["reason_ids"][name][rid] += 1
                    r["lat_us"].append(lat)
                    for k in ("t_eval_ns", "t_kv_ns", "t_guard_ns"):
                        r[k].append(d[k])
            for i, m in enumerate(BENIGN):
                await c.set_state(jsonable(m))
                lat, d, _ = await c.ask(ns, envelope(f"{ns}-b{rep}-{i}"))
                r["benign_n"] += 1; r["benign_admitted"] += d["allow"]
                r["lat_us"].append(lat)
                for k in ("t_eval_ns", "t_kv_ns", "t_guard_ns"):
                    r[k].append(d[k])
        r["attack_n"] = sum(v["n"] for v in r["per_variant"].values())
        r["attack_admitted"] = sum(v["admitted"] for v in r["per_variant"].values())
        r["latency_us"] = quantiles(r.pop("lat_us"))
        r["guard_internal_us"] = quantiles([x / 1e3 for x in r.pop("t_guard_ns")])
        r["state_read_us"] = quantiles([x / 1e3 for x in r.pop("t_kv_ns")])
        r["evaluate_us"] = quantiles([x / 1e3 for x in r.pop("t_eval_ns")])
        res[ns] = r

    # Identity and boundary probes (accepting state throughout).
    await c.set_state()
    probes = {}
    env = envelope("p-spoof", sender="root_agent")           # payload claims to be root
    _, d, _ = await c.ask("full", env)
    probes["payload_sender_spoof"] = {"allow": d["allow"], "failed": d["failed"]}
    env = envelope("p-noaction", action="unlock(back_door)")  # no policy for this action
    _, d, _ = await c.ask("full", env)
    probes["unpoliced_action"] = {"allow": d["allow"], "failed": d["failed"]}
    env = envelope("p-type"); env["type"] = "broadcast"       # wrong envelope type
    _, d, _ = await c.ask("full", env)
    probes["non_command_type"] = {"allow": d["allow"], "failed": d["failed"]}
    errors = []
    async def on_err(e):
        errors.append(str(e))
    agent._error_cb = on_err
    for subj in ("test.skillguard.full.req.root_agent", "test.skillguard.ctl.set_state",
                 "test.skillguard.full.inbox.iot_agent", "$KV.ESG_TEST_STATE.home"):
        await agent.publish(subj, json.dumps(envelope("p-x", sender="root_agent")).encode())
    await agent.flush()
    await asyncio.sleep(0.5)
    probes["broker_permission_violations"] = {"attempted": 4, "refused": len(errors)}
    _, d, _ = await c.ask("full", envelope("p-after"))        # state untouched by the refused writes
    probes["still_accepting_after_refused_writes"] = d["allow"]
    res["probes"] = probes
    res["finished"] = time.time()
    json.dump(res, open(args.out, "w"), indent=1)
    show = {k: {kk: res[k][kk] for kk in ("attack_admitted", "attack_n", "benign_admitted", "benign_n",
                                          "latency_us", "state_read_us", "evaluate_us")}
            for k in ("full", "lo") if k in res}
    print(json.dumps(show, indent=1)); print(json.dumps(probes, indent=1))
    await agent.close(); await exp.close()


async def relay(args):
    """Latency of the same exchange with the guard replaced by an unconditional forward."""
    agent = await connect(args.nats, "manager_agent", args.pw_mgr)
    exp = await connect(args.nats, "experimenter", args.pw_exp)
    c = Client(agent, exp); await c.start()
    for i in range(50):
        await c.ask("relay", envelope(f"rw{i}"))
    lats, guard = [], []
    for i in range(600):
        lat, d, _ = await c.ask("relay", envelope(f"r{i}"))
        lats.append(lat); guard.append(d["t_guard_ns"] / 1e3)
    res = {"label": args.label, "latency_us": quantiles(lats), "relay_internal_us": quantiles(guard)}
    json.dump(res, open(args.out, "w"), indent=1); print(json.dumps(res, indent=1))
    await agent.close(); await exp.close()


# --------------------------------------------------------------- inproc ----
def inproc(args):
    table = policies()
    now = time.time()
    cases = [(envelope("x"), build_state(now, **m)) for muts in VARIANTS.values() for m in muts]
    cases += [(envelope("x"), build_state(now, **m)) for m in BENIGN]
    res = {}
    for ns in ("full", "lo"):
        pol = table[ns][ACTION]
        for _ in range(200):
            for env, st in cases:
                evaluate(pol, env, st, now)
        ts = []
        for _ in range(args.reps):
            for env, st in cases:
                t0 = time.perf_counter_ns(); evaluate(pol, env, st, now); ts.append((time.perf_counter_ns() - t0) / 1e3)
        res[ns] = quantiles(ts)
    res["python"] = platform.python_version(); res["machine"] = platform.machine()
    json.dump(res, open(args.out, "w"), indent=1)
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("role", choices=["guard", "run", "relay", "inproc"])
    ap.add_argument("--nats", default="nats://127.0.0.1:14222")
    ap.add_argument("--pw-guard", default=os.environ.get("ESG_PW_GUARD", ""))
    ap.add_argument("--pw-exp", default=os.environ.get("ESG_PW_EXP", ""))
    ap.add_argument("--pw-mgr", default=os.environ.get("ESG_PW_MGR", ""))
    ap.add_argument("--scale", type=int, default=1)
    ap.add_argument("--reps", type=int, default=500)
    ap.add_argument("--label", default="local")
    ap.add_argument("--out", default="live_results.json")
    a = ap.parse_args()
    if a.role == "inproc":
        inproc(a)
    else:
        asyncio.run({"guard": guard, "run": run, "relay": relay}[a.role](a))
