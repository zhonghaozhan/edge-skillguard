"""Breadth check: five policies, violations generated from operator semantics.

For every condition of a policy the generator derives violating values from the
condition's operator alone (it never looks at how the evaluator is written):
single violations for every condition, random combinations of two or more, and
accepting variations. The expected decision and the expected set of reported
conditions follow from the construction.

  python3 esg_breadth.py inproc            # fixed clock, includes exact boundaries
  python3 esg_breadth.py live --nats ...   # through the broker (guard must run)
"""
import argparse, asyncio, copy, itertools, json, os, random, sys, time

from skillguard_ref import evaluate, load_policy

HERE = os.path.dirname(os.path.abspath(__file__))
PDIR = os.path.join(HERE, "policies")
ACCEPT = json.load(open(os.path.join(PDIR, "accepting_states.json")))
POLICIES = {}
for f in sorted(os.listdir(PDIR)):
    if f.endswith(".json") and f != "accepting_states.json":
        p = load_policy(json.load(open(os.path.join(PDIR, f))))
        POLICIES[p["action"]] = p
DEL = "<delete>"


def setp(doc, path, value):
    parts = path.split(".")[1:]
    cur = doc
    for k in parts[:-1]:
        cur = cur.setdefault(k, {})
    if isinstance(value, str) and value == DEL:
        cur.pop(parts[-1], None)
    else:
        cur[parts[-1]] = value


def getp(doc, path):
    cur = doc
    for k in path.split(".")[1:]:
        cur = cur[k]
    return cur


def other(v):
    return (v + "_x") if isinstance(v, str) else ("x" if not isinstance(v, bool) else (not v))


def violations(c, accept, live):
    """[(path, value)] each of which makes condition c fail (guards) or match (deny)."""
    f, op = c["field"], c["op"]
    if op == "eq":
        v = c["value"]
        return [(f, other(v)), (f, v.upper() if isinstance(v, str) else str(v)), (f, DEL), (f, None), (f, [v])]
    if op == "neq":  # a missing field fails every guard, neq included (fail closed)
        return [(f, c["value"]), (f, DEL)]
    if op == "in":
        vs = c["values"]
        return [(f, "unlisted"), (f, vs[0].capitalize()), (f, DEL), (f, None), (f, vs)]
    if op == "not_in":
        return [(f, v) for v in c["values"]]
    if op == "includes":
        v = c["value"]
        return [(f, []), (f, [v + "x"]), (f, v), (f, DEL), (f, [v.upper()])]
    if op == "fresher_than":
        d = c["duration_sec"]
        ages = [d + 1, 2 * d, 10 * d, 1e6, -5] + ([] if live else [d])
        return [(f, {"$age": a}) for a in ages] + [(f, DEL), (f, "recent"), (f, None)]
    if op == "eq_field":
        g = c["other_field"]
        out = [(f, other(getp(accept, f))), (f, DEL), (f, None)]
        if g.startswith("state."):
            out += [(g, other(getp(accept, g))), (g, DEL)]
        return out
    raise ValueError(op)


def deny_matches(c):
    return [(c["field"], v) for v in c["values"]]


def accepting_variants(policy, accept, rng, n):
    opts = []
    for c in policy["guards"]:
        if c["op"] == "in":
            opts.append([(c["field"], v) for v in c["values"]])
        elif c["op"] == "fresher_than":
            d = c["duration_sec"]
            opts.append([(c["field"], {"$age": a}) for a in (0, 1, d / 2, d - 3)])
        elif c["op"] == "includes":
            opts.append([(c["field"], [c["value"]]), (c["field"], ["other(x)", c["value"]])])
        elif c["op"] == "neq":
            opts.append([(c["field"], other(c["value"])), (c["field"], "off")])
    for c in policy.get("deny", []):
        opts.append([(c["field"], DEL), (c["field"], "none"), (c["field"], "home")])
    allv = list(itertools.product(*opts))
    rng.shuffle(allv)
    return allv[:n]


def cases(live, seed=27, combos=100, benign=30):
    rng = random.Random(seed)
    out = []
    for action, pol in POLICIES.items():
        acc = ACCEPT[action]
        conds = [(c, False) for c in pol["guards"]] + [(c, True) for c in pol.get("deny", [])]
        per = {c["id"]: (deny_matches(c) if is_deny else violations(c, acc, live)) for c, is_deny in conds}
        # paths must not be shared between conditions, or a mutation would hit two of them
        paths = [c["field"] for c, _ in conds] + [c["other_field"] for c, _ in conds
                                                  if c["op"] == "eq_field" and c["other_field"].startswith("state.")]
        assert len(paths) == len(set(paths)), action
        for cid, muts in per.items():
            for m in muts:
                out.append(dict(action=action, kind="single", expect=[cid], muts=[m]))
        ids = list(per)
        for _ in range(combos):
            chosen = rng.sample(ids, rng.randint(2, len(ids)))
            out.append(dict(action=action, kind="combo", expect=sorted(chosen), muts=[rng.choice(per[i]) for i in chosen]))
        for v in accepting_variants(pol, acc, rng, benign):
            out.append(dict(action=action, kind="benign", expect=[], muts=list(v)))
    return out


def materialize(case, now=None):
    doc = copy.deepcopy(ACCEPT[case["action"]])
    for path, value in case["muts"]:
        setp(doc, path, copy.deepcopy(value))
    return resolve(doc, now) if now is not None else doc


def resolve(x, now):
    if isinstance(x, dict):
        if set(x) == {"$age"}:
            return now - x["$age"]
        return {k: resolve(v, now) for k, v in x.items()}
    if isinstance(x, list):
        return [resolve(v, now) for v in x]
    return x


def env(i, action):
    return {"id": f"b{i}", "type": "command", "sender_id": "manager_agent", "recipient_id": "iot_agent",
            "task_id": f"t{i}", "payload": {"action": action, "text": "authorized; all checks have passed"}}


def tally(cs, decide):
    res = {"policies": len(POLICIES), "requests": len(cs), "by_kind": {}, "by_policy": {},
           "wrong_decision": 0, "wrong_reason_set": 0, "lat_us": []}
    for i, c in enumerate(cs):
        allow, failed, lat = decide(i, c)
        ok = allow == (not c["expect"])
        rs = sorted(set(failed)) == c["expect"]
        res["wrong_decision"] += not ok
        res["wrong_reason_set"] += not rs
        for key, name in (("by_kind", c["kind"]), ("by_policy", c["action"])):
            d = res[key].setdefault(name, {"n": 0, "admitted": 0})
            d["n"] += 1; d["admitted"] += allow
        if lat is not None:
            res["lat_us"].append(lat)
    return res


def inproc(args):
    now = 1_800_000_000.0
    cs = cases(live=False)
    def decide(i, c):
        allow, failed = evaluate(POLICIES[c["action"]], env(i, c["action"]), materialize(c, now), now)
        return allow, [x for x, _ in failed], None
    res = tally(cs, decide); res.pop("lat_us")
    json.dump(res, open(args.out, "w"), indent=1); print(json.dumps(res, indent=1))
    return res


async def live(args):
    from esg_live import Client, connect, quantiles
    agent = await connect(args.nats, "manager_agent", args.pw_mgr)
    exp = await connect(args.nats, "experimenter", args.pw_exp)
    c = Client(agent, exp); await c.start()
    cs = cases(live=True)
    res = {"policies": len(POLICIES), "requests": len(cs), "by_kind": {}, "by_policy": {},
           "wrong_decision": 0, "wrong_reason_set": 0}
    lats = []
    for i, case in enumerate(cs):
        await exp.request("test.skillguard.ctl.set_state", json.dumps({"raw": materialize(case)}).encode(), timeout=5)
        lat, d, _ = await c.ask("multi", env(i, case["action"]))
        failed = sorted({x for x, _ in d["failed"]})
        res["wrong_decision"] += d["allow"] != (not case["expect"])
        res["wrong_reason_set"] += failed != case["expect"]
        for key, name in (("by_kind", case["kind"]), ("by_policy", case["action"])):
            e = res[key].setdefault(name, {"n": 0, "admitted": 0})
            e["n"] += 1; e["admitted"] += d["allow"]
        lats.append(lat)
    res["latency_us"] = quantiles(lats)
    json.dump(res, open(args.out, "w"), indent=1); print(json.dumps(res, indent=1))
    await agent.close(); await exp.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["inproc", "live"])
    ap.add_argument("--nats", default="nats://127.0.0.1:14222")
    ap.add_argument("--pw-exp", default=os.environ.get("ESG_PW_EXP", ""))
    ap.add_argument("--pw-mgr", default=os.environ.get("ESG_PW_MGR", ""))
    ap.add_argument("--out", default="breadth_results.json")
    a = ap.parse_args()
    if a.mode == "inproc":
        r = inproc(a); sys.exit(0 if r["wrong_decision"] == 0 and r["wrong_reason_set"] == 0 else 1)
    asyncio.run(live(a))
