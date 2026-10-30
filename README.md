# Generative AI for Secure IAM Policy Engineering

A policy-constrained framework for generating and verifying least-privilege access policies.
Course project: Identity and Access Management (IAM), B.Tech. CSE (Cybersecurity and Forensics),
Dr. Vishwanath Karad MIT World Peace University, Pune.

**Authors:** Kanak Patil, Nikhil Mishra, Stuti Singh, Yuval Shah

**Core idea:** the language model only *drafts* a policy. Deterministic validation gates (G1–G6) and a named
human reviewer (G7) decide. Anything not explicitly approved is denied (deny-by-default).

## Contents

| Path | What it is |
|---|---|
| `paper/IEEE_GenAI_IAM_Policy_Engineering.pdf` | The IEEE-format article, including Section IX (Results and Analysis) |
| `iampolicy/` | Prototype: parser, simulated/real LLM generator, gates G1–G6, pipeline, sandbox PDP, audit log, CLI |
| `data/` | Demo attribute catalogue, constraint repository, existing policy store (synthetic) |
| `tests/` | 16 unit tests |
| `bench/` | Evaluation harness (Condition A no validation vs B gates) and test cases |
| `results/` | Scripts, raw results (`results.json`) and Figs. 4–6 used in the paper |

## Quick start (Python 3.9+, no dependencies)

```bash
git clone <your-repo-url> && cd <repo-folder>
python -m iampolicy demo                      # six scripted scenarios, no input needed
python -m unittest discover -s tests          # 16 tests, should end with OK
python -m iampolicy run "Finance staff can view invoices, but only a finance manager can approve them, and the same person must not create and approve an invoice."
python -m iampolicy run "..." --flaw missing_sod --persistent --auto-approve   # simulate an LLM error
python -m iampolicy verify-audit audit.jsonl
python -m iampolicy decide sandbox_pap/policy_set_v1.json --roles finance_manager --action approve --resource invoice --ctx '{"creator":"alice","approver":"bob"}'
```
Use `python3` if `python` is not found. Exit codes: 0 approved, 1 rejected, 2 clarification needed.
`--auto-approve` skips the human reviewer and is for testing only.

## Reproduce the results

```bash
python results/collect.py     # runs the demo scenarios and fault-injection experiment -> results/results.json
pip install matplotlib && python results/figs.py   # regenerates Figs. 4-6 (run from inside results/)
```

## Map to the article

| Article | Code |
|---|---|
| Stages 2–4 intake, parser, completeness check | `iampolicy/parser.py` |
| Stage 5 generator (untrusted) | `iampolicy/generator.py` |
| Stage 6 gates G1–G6 | `iampolicy/validator.py` |
| Stages 7–9, Algorithm 1 | `iampolicy/pipeline.py` |
| Stage 10 enforcement (sandbox) | `iampolicy/pdp.py` |
| Stage 11 audit log (hash-chained) | `iampolicy/audit.py` |

## Important limitations

* The generator used for the results is a **deterministic simulator** that injects known faults. The results show the
  gates behave as designed; they are **not** measurements of a real LLM. A real model can be plugged in with
  `--llm anthropic` (needs `ANTHROPIC_API_KEY`); that backend has not been run.
* The parser is rule-based and only understands the demo vocabulary in `data/catalogue.json`.
* Seven synthetic test cases. Sandbox only, never use against a production IAM system.
* Known weakness found in testing: a draft that *omits* a required rule is only an advisory finding in G6, so 4 of 7
  such drafts were accepted. See Section IX of the paper.
