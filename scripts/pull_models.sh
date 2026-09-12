#!/usr/bin/env bash
# Download local models used by the guardrail. Weights are gitignored (models/weights/).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLF_DIR="$ROOT/models/weights/deberta-v3-prompt-injection-v2"
HF="https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/resolve/main/onnx"

echo "==> Injection classifier (ProtectAI DeBERTa-v3, Apache-2.0, ONNX ~740MB)"
mkdir -p "$CLF_DIR"
for f in config.json tokenizer.json special_tokens_map.json tokenizer_config.json model.onnx; do
  if [[ -s "$CLF_DIR/$f" ]]; then echo "    $f (cached)"; continue; fi
  curl -fL --progress-bar -o "$CLF_DIR/$f" "$HF/$f"
done

echo "==> Ollama models (judge + guardian)"
if command -v ollama >/dev/null 2>&1; then
  ollama pull "${JUDGE_MODEL:-qwen3:8b}"
  ollama pull "${GUARDIAN_MODEL:-granite3-guardian:2b}"
else
  echo "    ollama not found; install it (brew install ollama) and re-run" >&2
fi
echo "done."
