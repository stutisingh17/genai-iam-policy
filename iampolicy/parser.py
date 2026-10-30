"""Stages 2-4: requirement intake, requirement parser, completeness check.

Everything submitted is treated as data. The parser is rule-based and deterministic so the
reference set used by gate G3 does not depend on the LLM.
"""
import re

MAX_LEN = 2000
SOD_CUES = re.compile(r"\b(same (person|user|employee|individual)|no single|no one (person|user)|"
                      r"must not both|separation of duties|segregat\w+)\b")
NEG_CUES = re.compile(r"\b(cannot|can't|can not|must not|may not|not allowed|should not|never)\b")
MODAL_VERB = re.compile(r"\b(?:can|may|should be able to|allowed to|are allowed to|is allowed to)\s+(\w+(?: \w+)?)")
SPLIT = re.compile(r"(?<=[.;])\s+|,?\s+but\s+(?=only\b|the\b|no\b)|,\s+and\s+(?=the same\b|no single\b|no one\b|no employee\b)")


def redact(text):
    """Data minimisation: strip obvious secrets / personal data before anything reaches a model."""
    text = re.sub(r"[\w.+-]+@[\w-]+\.[\w.-]+", "[REDACTED-EMAIL]", text)
    text = re.sub(r"\bAKIA[0-9A-Z]{16}\b", "[REDACTED-KEY]", text)
    text = re.sub(r"(?i)\b(password|passwd|secret|token|api[_ -]?key)\s*[:=]\s*\S+", r"\1=[REDACTED]", text)
    return text


def intake(text, catalogue):
    """Normalise, limit length, flag embedded instructions. Flagged sentences are dropped, never obeyed."""
    flags = []
    if len(text) > MAX_LEN:
        flags.append({"type": "too_long", "detail": f"input truncated to {MAX_LEN} chars"})
        text = text[:MAX_LEN]
    text = redact(re.sub(r"\s+", " ", text).strip())
    kept = []
    pats = [re.compile(p, re.I) for p in catalogue["injection_patterns"]]
    for sent in re.split(r"(?<=[.!?;])\s+", text):
        hit = next((p.pattern for p in pats if p.search(sent)), None)
        if hit:
            flags.append({"type": "embedded_instruction", "detail": sent})
        else:
            kept.append(sent)
    return " ".join(kept), flags


def _alias_regex(alias):
    return re.compile(r"\b" + re.escape(alias) + r"(?:s|es|d|ed)?\b")


def _find(clause, vocab):
    """Return vocabulary keys whose aliases occur in clause (longest alias first, no overlaps)."""
    hits, taken = [], []
    cands = sorted(((a, k) for k, al in vocab.items() for a in al), key=lambda t: -len(t[0]))
    for alias, key in cands:
        for m in _alias_regex(alias).finditer(clause):
            if any(not (m.end() <= s or m.start() >= e) for s, e in taken):
                continue
            taken.append((m.start(), m.end()))
            hits.append((m.start(), key))
    found = []
    for _, key in sorted(hits):  # keep order of appearance in the sentence
        if key not in found:
            found.append(key)
    return found


def parse(text, catalogue):
    clean, flags = intake(text, catalogue)
    low = clean.lower()
    clauses, perms, sod, issues = [], [], [], []
    last_res = None
    pieces = [p.strip(" .") for p in SPLIT.split(low) if p and p.strip(" .")]
    for i, piece in enumerate(pieces, start=1):
        subj = _find(piece, catalogue["subjects"])
        acts = _find(piece, catalogue["actions"])
        ress = _find(piece, catalogue["resources"])
        kind = "sod" if SOD_CUES.search(piece) else "permission"
        clause = {"id": i, "text": piece, "kind": kind, "subjects": subj, "actions": acts, "resources": ress}
        clauses.append(clause)
        for term in catalogue["ambiguous_terms"]:
            if re.search(r"\b" + re.escape(term) + r"\b", piece):
                issues.append({"clause": i, "question": f"Clause {i} uses the vague term '{term}'. Which exact actions and resources are meant?"})
        if ress:
            last_res = ress[0]
        eff_res = ress or ([last_res] if last_res else [])
        if kind == "sod":
            if len(acts) < 2 or not eff_res:
                issues.append({"clause": i, "question": f"Clause {i} states a separation-of-duties rule: which two actions and which resource?"})
            else:
                sod.append({"clause": i, "actions": acts[:2], "resource": eff_res[0]})
            continue
        m = MODAL_VERB.search(piece)
        if m and not acts:
            issues.append({"clause": i, "question": f"Clause {i}: '{m.group(1)}' is not in the approved action vocabulary. Which of {sorted(catalogue['actions'])} is meant?"})
            continue
        if not subj:
            issues.append({"clause": i, "question": f"Clause {i}: which role is this permission for?"})
        if not acts:
            issues.append({"clause": i, "question": f"Clause {i}: which action (one of {sorted(catalogue['actions'])}) is allowed?"})
        if not eff_res:
            issues.append({"clause": i, "question": f"Clause {i}: which resource does this apply to?"})
        if subj and acts and eff_res:
            effect = "deny" if NEG_CUES.search(piece) else "permit"
            for s in subj:
                for a in acts:
                    for r in eff_res:
                        perms.append({"subject": f"role:{s}", "action": a, "resource": r, "effect": effect, "clause": i})
    if not pieces:
        issues.append({"clause": 0, "question": "No usable requirement text was found. Please restate the access requirement."})
    return {"text": clean, "intake_flags": flags, "clauses": clauses, "permissions": perms, "sod": sod, "issues": issues}


def completeness_check(req):
    """Stage 4. Returns clarification questions; empty list means the requirement is complete."""
    return [i["question"] for i in req["issues"]]
