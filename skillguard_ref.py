"""Reference evaluator for the typed invocation policy described in the paper.

This file is a dependency-free re-implementation written from the paper's
specification (seven guard operators over dot-separated paths into `envelope`
or `state`; all guards must hold; no deny condition may match). It is the
evaluator behind every guard-side number in version 2 of the paper; version 1
used an earlier implementation that is not part of this repository.

Semantics fixed here, where the paper's text leaves a choice:
  * a guard whose path is missing, or whose value has the wrong type, FAILS;
  * a deny condition whose path is missing does not match;
  * `fresher_than` requires 0 <= now - t < duration_sec, so a timestamp from
    the future fails;
  * `eq`/`eq_field`/`in` compare without type coercion ("30" != 30, True != 1).
"""

OPERAND = {
    "eq": "value", "neq": "value", "includes": "value",
    "in": "values", "not_in": "values",
    "fresher_than": "duration_sec", "eq_field": "other_field",
}
_MISSING = object()


class PolicyError(ValueError):
    pass


def load_policy(doc):
    """Validate a policy document; raise PolicyError before any request is seen."""
    if not isinstance(doc, dict) or not isinstance(doc.get("action"), str):
        raise PolicyError("policy needs a string 'action'")
    for section in ("guards", "deny"):
        conds = doc.get(section, [])
        if not isinstance(conds, list):
            raise PolicyError(f"'{section}' must be a list")
        for c in conds:
            if not isinstance(c, dict):
                raise PolicyError("condition must be an object")
            op, field = c.get("op"), c.get("field")
            if op not in OPERAND:
                raise PolicyError(f"unknown operator {op!r}")
            if not _is_path(field):
                raise PolicyError(f"bad path {field!r}")
            need = OPERAND[op]
            if need not in c:
                raise PolicyError(f"operator {op!r} requires '{need}'")
            if need == "values" and not isinstance(c[need], list):
                raise PolicyError("'values' must be a list")
            if need == "other_field" and not _is_path(c[need]):
                raise PolicyError(f"bad path {c[need]!r}")
            if need == "duration_sec" and not _is_num(c[need]):
                raise PolicyError("'duration_sec' must be a number")
            extra = set(c) - {"id", "field", "op", need}
            if extra:
                raise PolicyError(f"unexpected keys {sorted(extra)}")
    if not doc.get("guards"):
        raise PolicyError("a policy with no guard would admit everything")
    return doc


def _is_path(p):
    return (isinstance(p, str) and p.split(".")[0] in ("envelope", "state")
            and all(part for part in p.split(".")) and len(p.split(".")) >= 2)


def _is_num(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _same(a, b):
    """Equality without coercion across types (bool is not int, "1" is not 1)."""
    if _is_num(a) and _is_num(b):
        return a == b
    return type(a) is type(b) and a == b


def _resolve(path, envelope, state):
    root, *rest = path.split(".")
    cur = envelope if root == "envelope" else state
    for part in rest:
        if not isinstance(cur, dict) or part not in cur:
            return _MISSING
        cur = cur[part]
    return cur


def _holds(c, envelope, state, now):
    """Return (holds, reason). `reason` explains a failure."""
    v = _resolve(c["field"], envelope, state)
    op = c["op"]
    if v is _MISSING:
        return False, f"{c['field']} is missing"
    if op == "eq":
        return _same(v, c["value"]), f"{c['field']} is {v!r}, expected {c['value']!r}"
    if op == "neq":
        return not _same(v, c["value"]), f"{c['field']} must not be {c['value']!r}"
    if op == "in":
        return any(_same(v, x) for x in c["values"]), f"{c['field']} is {v!r}, not in {c['values']!r}"
    if op == "not_in":
        return not any(_same(v, x) for x in c["values"]), f"{c['field']} is {v!r}, which is excluded"
    if op == "includes":
        ok = isinstance(v, list) and any(_same(x, c["value"]) for x in v)
        return ok, f"{c['field']} does not include {c['value']!r}"
    if op == "fresher_than":
        if not _is_num(v):
            return False, f"{c['field']} is not a timestamp"
        age = now - v
        return 0 <= age < c["duration_sec"], f"{c['field']} is {age:.1f} s old (limit {c['duration_sec']} s)"
    if op == "eq_field":
        w = _resolve(c["other_field"], envelope, state)
        if w is _MISSING:
            return False, f"{c['other_field']} is missing"
        return _same(v, w), f"{c['field']} is {v!r}, {c['other_field']} is {w!r}"
    raise PolicyError(op)


def evaluate(policy, envelope, state, now):
    """Pure decision function. Returns (allow, failed), failed = [(id, reason)]."""
    failed = []
    for c in policy["guards"]:
        ok, why = _holds(c, envelope, state, now)
        if not ok:
            failed.append((c.get("id", c["field"]), why))
    for c in policy.get("deny", []):
        v = _resolve(c["field"], envelope, state)
        if v is _MISSING:
            continue
        ok, _ = _holds(c, envelope, state, now)
        if ok:
            failed.append((c.get("id", c["field"]), f"deny condition matched: {c['field']} is {v!r}"))
    return (not failed), failed


def _cond_implies(cs, cw):
    """True if condition `cs` holding implies condition `cw` holds on every (envelope, state, now)."""
    if cs["field"] != cw["field"]:
        return False
    ops, opw = cs["op"], cw["op"]
    if ops == opw in ("eq", "neq", "includes"):
        return _same(cs["value"], cw["value"])
    if ops == opw == "eq_field":
        return cs["other_field"] == cw["other_field"]
    if ops == opw == "fresher_than":
        return 0 < cs["duration_sec"] <= cw["duration_sec"]
    if ops in ("eq", "in") and opw in ("eq", "in"):
        vs = [cs["value"]] if ops == "eq" else cs["values"]
        vw = [cw["value"]] if opw == "eq" else cw["values"]
        return bool(vs) and all(any(_same(x, y) for y in vw) for x in vs)
    if ops in ("neq", "not_in") and opw in ("neq", "not_in"):
        vs = [cs["value"]] if ops == "neq" else cs["values"]
        vw = [cw["value"]] if opw == "neq" else cw["values"]
        return bool(vw) and all(any(_same(y, x) for x in vs) for y in vw)
    return False


def is_tightening(old, new):
    """True if `new` is at least as strict as `old` on every (envelope, state, now).

    Checks operator-lattice subsumption: every guard of `old` is implied by a guard
    of `new`, and every deny condition of `old` implies a deny condition of `new`.
    Such an update never admits a request that `old` rejected."""
    return (old["action"] == new["action"]
            and all(any(_cond_implies(cn, co) for cn in new["guards"]) for co in old["guards"])
            and all(any(_cond_implies(do, dn) for dn in new.get("deny", [])) for do in old.get("deny", [])))
