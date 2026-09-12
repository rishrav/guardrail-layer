import os

# Keep the default test run deterministic and fast: the LLM classifier (local Ollama) is
# opt-in with LIVE_MODELS=1. Heuristics and the ONNX classifier still run.
if os.environ.get("LIVE_MODELS") != "1":
    os.environ.setdefault("LLM_CLASSIFIER_ENABLED", "false")
    # Deterministic adjudicator checks (provenance, budgets, invariants) still run.
    os.environ.setdefault("ADJUDICATOR_MODELS_ENABLED", "false")
