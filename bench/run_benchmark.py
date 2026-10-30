"""Harness for the Section VII evaluation design (Condition A: no validation, Condition B: gates G1-G6).

IMPORTANT: with --llm simulated the 'LLM' is a scripted fault injector, so the printed numbers only show that
the harness and gates work. They are NOT evidence about real LLMs and must not be reported as findings.
Use --llm anthropic with a real, documented benchmark to obtain reportable numbers.
"""
import argparse
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from iampolicy import load_context
from iampolicy.generator import SimulatedGenerator, FLAWS
from iampolicy.parser import parse, completeness_check
from iampolicy.validator import validate

CTX = load_context()
HERE = os.path.dirname(os.path.abspath(__file__))


def oracle(draft, case):
    """Independent ground truth from the case file (not from the validator)."""
    if not isinstance(draft, list):
        return {"correct": False, "violation": True, "unsafe": True}
    got = {(r.get("subject"), r.get("action"), r.get("resource"), r.get("effect")) for r in draft if isinstance(r, dict)}
    exp = {tuple(t) for t in case["expected"]}
    excess = bool(got - exp)
    guard = case.get("guarded")  # [action, resource, condition]
    sod_missing = bool(guard) and any(r.get("action") == guard[0] and r.get("resource") == guard[1]
                                      and r.get("effect") == "permit" and r.get("condition") != guard[2] for r in draft)
    return {"correct": got == exp and not sod_missing, "violation": excess or sod_missing,
            "unsafe": got != exp or sod_missing}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--llm", choices=["simulated", "anthropic"], default="simulated")
    ap.add_argument("--flaw", choices=FLAWS, default=None, help="simulated mode: fault injected into every draft")
    a = ap.parse_args()
    cases = json.load(open(os.path.join(HERE, "cases.json")))
    mk = (lambda: SimulatedGenerator(a.flaw, persistent=True)) if a.llm == "simulated" else None
    if mk is None:
        from iampolicy.generator import AnthropicGenerator
        mk = AnthropicGenerator
    gen = mk()
    stats = {c: dict(N=0, ok=0, viol=0, unsafe=0, false_appr=0, times=[]) for c in "AB"}
    clarify_ok = clarify_n = 0
    for case in cases:
        req = parse(case["text"], CTX["catalogue"])
        if case.get("expect_clarify"):
            clarify_n += 1
            clarify_ok += bool(completeness_check(req))
            continue
        t0 = time.perf_counter()
        draft = gen.generate(req, CTX)
        dt = time.perf_counter() - t0
        truth = oracle(draft, case)
        accepted_by_gates = validate(draft, req, CTX)["passed"]
        for cond in "AB":
            s = stats[cond]
            s["N"] += 1; s["times"].append(dt)
            s["ok"] += truth["correct"]; s["viol"] += truth["violation"]; s["unsafe"] += truth["unsafe"]
            accepted = True if cond == "A" else accepted_by_gates
            s["false_appr"] += (truth["unsafe"] and accepted)
    print(f"generator={a.llm} flaw={a.flaw}  (simulated numbers are NOT findings about real LLMs)")
    print(f"clarification requested on {clarify_ok}/{clarify_n} deliberately incomplete requirements")
    print(f"{'cond':<8}{'N':>2}{'correct':>9}{'viol.rate':>10}{'unsafe':>8}{'false-appr':>11}{'median s':>10}")
    for cond, label in (("A", "A raw"), ("B", "B gates")):
        s = stats[cond]
        n = s["N"]
        fa = f"{s['false_appr']}/{s['unsafe']}" if s["unsafe"] else "n/a"
        print(f"{label:<8}{n:>2}{s['ok'] / n:>9.2f}{s['viol'] / n:>10.2f}{s['unsafe']:>8}{fa:>11}"
              f"{statistics.median(s['times']):>10.4f}")


if __name__ == "__main__":
    main()
