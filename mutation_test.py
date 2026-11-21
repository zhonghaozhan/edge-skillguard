"""Check the checks: each faulty evaluator below must fail run_checks.py.

Run:  python3 mutation_test.py     (copies files to a temp dir; edits nothing here)
"""
import os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = open(os.path.join(HERE, "skillguard_ref.py")).read()
MUTANTS = {
    "future timestamps accepted": ('return 0 <= age < c["duration_sec"]', 'return age < c["duration_sec"]'),
    "30 s boundary accepted": ('return 0 <= age < c["duration_sec"]', 'return 0 <= age <= c["duration_sec"]'),
    "equality coerces types": ("return type(a) is type(b) and a == b", "return str(a) == str(b)"),
    "deny conditions ignored": ('        if ok:\n            failed.append((c.get("id", c["field"]), f"deny',
                                '        if False:\n            failed.append((c.get("id", c["field"]), f"deny'),
    "missing path passes": ("    if v is _MISSING:\n        return False, f\"{c['field']} is missing\"\n    if op == \"eq\":",
                            "    if v is _MISSING:\n        return True, ''\n    if op == \"eq\":"),
    "includes accepts a string": ('ok = isinstance(v, list) and any(_same(x, c["value"]) for x in v)',
                                  'ok = c["value"] in v if isinstance(v, (list, str)) else False'),
    "sender read from payload": ('w = _resolve(c["other_field"], envelope, state)',
                                 'w = envelope.get("payload", {}).get("sender_id", _resolve(c["other_field"], envelope, state))'),
    "load accepts missing operand": ("            if need not in c:\n                raise PolicyError(f\"operator {op!r} requires '{need}'\")",
                                     "            pass"),
}
base = subprocess.run([sys.executable, os.path.join(HERE, "run_checks.py")], capture_output=True).returncode
assert base == 0, "the unmodified evaluator must pass run_checks.py first"
killed = 0
for name, (old, new) in MUTANTS.items():
    assert old in SRC, name
    with tempfile.TemporaryDirectory() as d:
        for f in ("run_checks.py", "policy_unlock_front_door.json"):
            shutil.copy(os.path.join(HERE, f), d)
        open(os.path.join(d, "skillguard_ref.py"), "w").write(SRC.replace(old, new))
        rc = subprocess.run([sys.executable, "run_checks.py"], cwd=d, capture_output=True).returncode
    killed += rc != 0
    print(f"{'caught' if rc else 'MISSED':7s} {name}")
print(f"{killed}/{len(MUTANTS)} faulty evaluators caught")
raise SystemExit(0 if killed == len(MUTANTS) else 1)
