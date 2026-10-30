"""Sandbox enforcement engine (PDP) used only to demonstrate run-time decisions on deployed policies.

Deny by default; an explicit deny wins; a condition that cannot be evaluated denies.
The generative component never calls this.
"""
import re
from .validator import closure

COND_RE = re.compile(r"^(\w+) != (\w+)$")


def _cond_ok(cond, context):
    if not cond:
        return True
    m = COND_RE.match(cond)
    if not m or m.group(1) not in context or m.group(2) not in context:
        return False  # fail safe: unknown / missing attribute -> not satisfied
    return context[m.group(1)] != context[m.group(2)]


def decide(policy_set, user_roles, action, resource, context=None):
    context = context or {}
    hier = policy_set.get("role_hierarchy", {})
    held = set().union(*(closure(r, hier) for r in user_roles)) if user_roles else set()
    permit = deny = False
    for r in policy_set["rules"]:
        role = r["subject"].split(":", 1)[-1]
        if role in held and r["action"] == action and r["resource"] == resource:
            if r["effect"] == "deny":
                deny = True
            elif _cond_ok(r.get("condition"), context):
                permit = True
    return "permit" if permit and not deny else "deny"
