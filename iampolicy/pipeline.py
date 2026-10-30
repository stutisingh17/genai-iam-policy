"""Algorithm 1 (policy-constrained generation) with deny-by-default.

Every exit path other than an explicit human approval ends without deployment.
"""
import json
import os
import time

from . import load_context
from .audit import AuditLog
from .parser import parse, completeness_check
from .validator import validate, GATES


def build_report(draft, req, result):
    """Stage 7: validation report with a traceability matrix (rule -> source clauses -> clause text)."""
    texts = {c["id"]: c["text"] for c in req["clauses"]}
    from .validator import _clause_ids
    trace = [{"rule": r.get("id"), "source": r.get("source"),
              "clauses": {n: texts.get(n, "<missing>") for n in sorted(_clause_ids(r.get("source")))}}
             for r in draft if isinstance(r, dict)]
    return {"proposed_policy": draft, "validation": result, "traceability": trace,
            "intake_flags": req["intake_flags"]}


def deploy(rules, ctx, deploy_dir, approver, audit):
    """Stage 9: write a versioned policy set to the (sandbox) policy administration point."""
    os.makedirs(deploy_dir, exist_ok=True)
    version = len([f for f in os.listdir(deploy_dir) if f.startswith("policy_set_v")]) + 1
    pset = {"version": version, "approved_by": approver, "deployed_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "role_hierarchy": ctx["existing"].get("role_hierarchy", {}),
            "rules": ctx["existing"]["rules"] + rules}
    path = os.path.join(deploy_dir, f"policy_set_v{version}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(pset, f, indent=2)
    audit.log("deploy", {"deployment_id": f"policy_set_v{version}", "path": path})
    return path


def run(text, generator, reviewer, ctx=None, audit_path="audit.jsonl", deploy_dir="sandbox_pap", retries=3):
    """Returns {"status": APPROVED|REJECT|CLARIFY, ...}. `reviewer(report) -> {"decision","reviewer"}`."""
    ctx = ctx or load_context()
    audit = AuditLog(audit_path)
    req = parse(text, ctx["catalogue"])                                   # stages 2-3
    audit.log("input", {"requirement": req["text"], "intake_flags": req["intake_flags"]})
    questions = completeness_check(req)                                   # stage 4
    if questions or not req["permissions"]:
        questions = questions or ["No permission could be extracted. Please restate the requirement."]
        audit.log("clarify", {"questions": questions})
        return {"status": "CLARIFY", "questions": questions, "requirement": req}
    feedback, draft, result = None, None, None
    for attempt in range(retries):                                        # stages 5-6, bounded retries
        draft = generator.generate(req, ctx, feedback=feedback, attempt=attempt)
        result = validate(draft, req, ctx)
        audit.log("generate_validate", {"attempt": attempt + 1, "generator": generator.settings(), "draft": draft,
                                        "gates": {g: result["gates"][g]["status"] for g in GATES},
                                        "critical": result["critical"], "advisory": result["advisory"]})
        if result["passed"]:
            break
        feedback = [f for g in GATES for f in result["gates"][g]["findings"] if f["severity"] == "critical"]
    if not result["passed"]:                                              # deny-by-default
        audit.log("reject", {"reason": "critical findings unresolved after retries"})
        return {"status": "REJECT", "reason": "unresolved critical findings", "report": build_report(draft, req, result)}
    report = build_report(draft, req, result)                             # stage 7
    decision = reviewer(report)                                           # stage 8 (G7)
    audit.log("human_review", {"decision": decision.get("decision"), "reviewer": decision.get("reviewer")})
    if decision.get("decision") != "approve" or not decision.get("reviewer"):
        audit.log("reject", {"reason": "not approved by an authorised reviewer"})
        return {"status": "REJECT", "reason": "no explicit human approval", "report": report}
    path = deploy(draft, ctx, deploy_dir, decision["reviewer"], audit)    # stage 9
    return {"status": "APPROVED", "deployed": path, "report": report}
