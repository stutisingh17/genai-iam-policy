"""Stage 6: deterministic validation engine. Gates G1-G6 are plain rules; no LLM judgement.

All gates run even after a failure so the reviewer gets the full report. Findings are graded:
critical blocks the draft, advisory is shown to the reviewer only.
"""
import re

GATES = ["G1", "G2", "G3", "G4", "G5", "G6"]
GATE_NAMES = {"G1": "Schema / syntax", "G2": "Completeness", "G3": "Least privilege",
              "G4": "Separation of duties", "G5": "Conflicts", "G6": "Traceability"}
REQUIRED = ["id", "subject", "action", "resource", "effect", "source"]
ALLOWED = set(REQUIRED) | {"condition", "purpose"}
PLACEHOLDERS = {"", "*", "tbd", "todo", "xxx", "any", "all", "?", "none", "null"}
COND_RE = re.compile(r"^(\w+) != (\w+)$")


def _f(gate, sev, msg, ids=()):
    return {"gate": gate, "severity": sev, "message": msg, "rules": list(ids)}


def closure(role, hierarchy):
    """role plus every role it inherits from."""
    seen, stack = set(), [role]
    while stack:
        r = stack.pop()
        if r not in seen:
            seen.add(r)
            stack.extend(hierarchy.get(r, []))
    return seen


def _role(subject):
    return subject.split(":", 1)[1] if isinstance(subject, str) and subject.startswith("role:") else None


def _is_wild(v):
    return isinstance(v, str) and (v.strip().lower() in PLACEHOLDERS or "*" in v or re.search(r"<.*>", v))


def g1_schema(draft, ctx):
    cat, out = ctx["catalogue"], []
    if not isinstance(draft, list) or not draft:
        return [_f("G1", "critical", "Draft is empty or not a JSON array of rules.")]
    seen = set()
    for r in draft:
        if not isinstance(r, dict):
            out.append(_f("G1", "critical", "Rule is not an object.")); continue
        rid = r.get("id", "?")
        if rid in seen: out.append(_f("G1", "critical", "Duplicate rule id.", [rid]))
        seen.add(rid)
        extra = set(r) - ALLOWED
        if extra: out.append(_f("G1", "critical", f"Unknown fields {sorted(extra)}.", [rid]))
        for k in ALLOWED & set(r):
            if not isinstance(r[k], str): out.append(_f("G1", "critical", f"Field '{k}' must be a string.", [rid]))
        if r.get("effect") not in ("permit", "deny") and not _is_wild(r.get("effect")):
            out.append(_f("G1", "critical", f"effect must be permit|deny, got {r.get('effect')!r}.", [rid]))
        role = _role(r.get("subject"))
        if r.get("subject") and not _is_wild(r.get("subject")) and (role is None or role not in cat["subjects"]):
            out.append(_f("G1", "critical", f"Subject {r.get('subject')!r} is not in the approved vocabulary.", [rid]))
        for k, vocab in (("action", cat["actions"]), ("resource", cat["resources"])):
            v = r.get(k)
            if isinstance(v, str) and not _is_wild(v) and v not in vocab:
                out.append(_f("G1", "critical", f"{k} {v!r} is not in the approved vocabulary.", [rid]))
        c = r.get("condition")
        if c is not None:
            m = COND_RE.match(c) if isinstance(c, str) else None
            if not m or not {m.group(1), m.group(2)} <= set(cat["attributes"].values()):
                out.append(_f("G1", "critical", f"condition {c!r} uses unapproved syntax or attributes.", [rid]))
    return out


def g2_complete(draft, ctx):
    out = []
    for r in draft if isinstance(draft, list) else []:
        if not isinstance(r, dict): continue
        for k in REQUIRED:
            v = r.get(k)
            if v is None or (isinstance(v, str) and not v.strip()):
                out.append(_f("G2", "critical", f"Required field '{k}' is missing.", [r.get("id", "?")]))
        for k in ("subject", "action", "resource", "effect"):
            if _is_wild(r.get(k)) and r.get(k) not in (None, ""):
                out.append(_f("G2", "critical", f"Wildcard or placeholder in '{k}': {r.get(k)!r}.", [r.get("id", "?")]))
    return out


def _tuples(draft):
    return [(r.get("subject"), r.get("action"), r.get("resource"), r.get("effect"), r.get("id"))
            for r in draft if isinstance(r, dict)]


def g3_least_privilege(draft, req, ctx):
    ref = {(p["subject"], p["action"], p["resource"], p["effect"]) for p in req["permissions"]}
    out = []
    for s, a, r, e, rid in _tuples(draft):
        if _is_wild(s) or _is_wild(a) or _is_wild(r):
            out.append(_f("G3", "critical", "Wildcard expands beyond the requirement (excess privilege).", [rid]))
        elif (s, a, r, e) not in ref:
            sev = "critical" if e == "permit" else "advisory"
            out.append(_f("G3", sev, f"({s}, {a}, {r}, {e}) is not entailed by the requirement.", [rid]))
    return out


def _all_sod(req, ctx):
    items = []
    for r in ctx["constraints"]["sod"]:
        items.append((r["actions"][0], r["actions"][1], None, r["guard"], r["condition"], r["id"]))
    for c in req["sod"]:
        a, b = c["actions"]
        repo = next((r for r in ctx["constraints"]["sod"] if set(r["actions"]) == {a, b}), None)
        guard = repo["guard"] if repo else b
        cond = repo["condition"] if repo else f"{ctx['catalogue']['attributes'][a]} != {ctx['catalogue']['attributes'][b]}"
        items.append((a, b, c["resource"], guard, cond, f"clause {c['clause']}"))
    return items


def g4_sod(draft, req, ctx):
    ex, out, hier = ctx["existing"], [], ctx["existing"].get("role_hierarchy", {})
    rules = [r for r in draft if isinstance(r, dict)] + ex["rules"]
    permits = [r for r in rules if r.get("effect") == "permit"]
    roles = {_role(r["subject"]) for r in permits if _role(r.get("subject"))}
    groups = {f"role {x}": {x} for x in roles}
    for u, rl in ex.get("users", {}).items():
        groups[f"user {u}"] = set().union(*(closure(x, hier) for x in rl)) if rl else set()
    for name, held in list(groups.items()):
        if name.startswith("role "): groups[name] = closure(next(iter(held)), hier)
    seen = set()
    for a, b, res, guard, cond, src in _all_sod(req, ctx):
        resources = [res] if res else list(ctx["catalogue"]["resources"])
        for rs in resources:
            for name, held in groups.items():
                eff = [r for r in permits if _role(r.get("subject")) in held and r.get("resource") == rs]
                acts = {r.get("action") for r in eff}
                if a in acts and b in acts:
                    guarded = [r for r in eff if r.get("action") == guard]
                    bad = [r for r in guarded if r.get("condition") != cond]
                    if bad:
                        key = (name, rs, a, b, tuple(sorted(str(r.get("id")) for r in bad)))
                        if key in seen: continue
                        seen.add(key)
                        out.append(_f("G4", "critical",
                                      f"{name} can obtain both '{a}' and '{b}' on {rs} ({src}) but "
                                      f"'{guard}' is not guarded by condition '{cond}'.", [r.get("id") for r in bad]))
    return out


def _overlap(s1, s2, hier):
    r1, r2 = _role(s1), _role(s2)
    return bool(r1 and r2 and (r1 in closure(r2, hier) or r2 in closure(r1, hier)))


def g5_conflicts(draft, ctx):
    ex, hier, out = ctx["existing"], ctx["existing"].get("role_hierarchy", {}), []
    cand = [r for r in draft if isinstance(r, dict)]
    pairs = [(c, o, "existing policy") for c in cand for o in ex["rules"]]
    pairs += [(cand[i], cand[j], "candidate") for i in range(len(cand)) for j in range(i + 1, len(cand))]
    for c, o, where in pairs:
        if c.get("action") == o.get("action") and c.get("resource") == o.get("resource") \
                and _overlap(c.get("subject"), o.get("subject"), hier):
            if c.get("effect") != o.get("effect"):
                out.append(_f("G5", "critical", f"{c.get('id')} contradicts {o.get('id')} ({where}) on "
                              f"{c.get('action')} {c.get('resource')}.", [c.get("id"), o.get("id")]))
            elif c.get("effect") == o.get("effect") and c.get("condition") == o.get("condition") and c is not o:
                out.append(_f("G5", "advisory", f"{c.get('id')} is redundant with/shadowed by {o.get('id')} ({where}).",
                              [c.get("id"), o.get("id")]))
    return out


def _clause_ids(src):
    ids = set()
    for a, b in re.findall(r"(\d+)\s*-\s*(\d+)", src or ""):
        ids |= set(range(int(a), int(b) + 1))
    ids |= {int(n) for n in re.findall(r"\d+", re.sub(r"\d+\s*-\s*\d+", "", src or ""))}
    return ids


def g6_trace(draft, req, ctx):
    out, covered = [], set()
    by_clause = {}
    for p in req["permissions"]:
        by_clause.setdefault((p["subject"], p["action"], p["resource"], p["effect"]), set()).add(p["clause"])
    sod_conds = {x[4] for x in _all_sod(req, ctx)}
    for r in [x for x in draft if isinstance(x, dict)]:
        cited = _clause_ids(r.get("source"))
        key = (r.get("subject"), r.get("action"), r.get("resource"), r.get("effect"))
        if not cited:
            out.append(_f("G6", "critical", "Rule cites no source clause.", [r.get("id")]))
        elif not (by_clause.get(key, set()) & cited):
            out.append(_f("G6", "critical", f"Cited clause(s) {sorted(cited)} do not support this rule (unsupported).", [r.get("id")]))
        else:
            covered.add(key)
        if r.get("condition") and r["condition"] not in sod_conds:
            out.append(_f("G6", "critical", f"Condition {r['condition']!r} has no supporting SoD clause or constraint.", [r.get("id")]))
    for key, cl in by_clause.items():
        if key not in covered and key[3] == "permit":
            out.append(_f("G6", "advisory", f"Requirement clause(s) {sorted(cl)} not covered by any rule: {key[:3]}.", []))
    return out


def validate(draft, req, ctx):
    findings = []
    findings += g1_schema(draft, ctx)
    findings += g2_complete(draft, ctx)
    ok_shape = isinstance(draft, list) and all(isinstance(r, dict) for r in draft)
    if ok_shape:
        findings += g3_least_privilege(draft, req, ctx)
        findings += g4_sod(draft, req, ctx)
        findings += g5_conflicts(draft, ctx)
        findings += g6_trace(draft, req, ctx)
    gates = {}
    for g in GATES:
        fs = [f for f in findings if f["gate"] == g]
        gates[g] = {"name": GATE_NAMES[g], "status": "FAIL" if any(f["severity"] == "critical" for f in fs) else "PASS",
                    "findings": fs}
    if not ok_shape:  # semantic gates cannot be evaluated -> fail closed
        for g in GATES[2:]:
            gates[g]["status"] = "FAIL"
            gates[g]["findings"].append(_f(g, "critical", "Not evaluable: draft is not a list of rule objects."))
    crit = [f for f in findings if f["severity"] == "critical"] + \
           [f for g in GATES[2:] for f in gates[g]["findings"] if f["message"].startswith("Not evaluable")]
    return {"gates": gates, "critical": len(crit), "advisory": sum(f["severity"] == "advisory" for f in findings),
            "passed": not crit}
