"""Policy-constrained Generative AI framework for IAM policy engineering (prototype).

The LLM only drafts; deterministic gates G1-G6 and a human reviewer (G7) decide.
Deny-by-default: every exit other than explicit human approval ends undeployed.
"""
import json
import os

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def load_json(name, data_dir=None):
    with open(os.path.join(data_dir or DATA_DIR, name), encoding="utf-8") as f:
        return json.load(f)


def load_context(data_dir=None):
    """Knowledge stores of Fig. 1: attribute catalogue, constraint repository, existing policy store."""
    return {
        "catalogue": load_json("catalogue.json", data_dir),
        "constraints": load_json("constraints.json", data_dir),
        "existing": load_json("existing_policies.json", data_dir),
    }
