"""Layer 2: local transformer injection classifier (ProtectAI DeBERTa-v3, ONNX on CPU).

Long texts are split into overlapping 512-token windows that together cover every token,
and the most suspicious window decides the score. An injection buried deep in a long
document can't hide past the model's context limit.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer

from gateway.pipeline.detection_types import AttackType, DetectionResult

MAX_WINDOWS = 64  # about 30k tokens; heuristics still scan the full text beyond this
BATCH_SIZE = 8


def window_starts(n_tokens: int, body: int, stride: int) -> list[int]:
    """Start offsets of overlapping windows that cover all ``n_tokens``."""
    step = body - stride
    starts = list(range(0, max(n_tokens - body, 0) + 1, step))
    if starts[-1] + body < n_tokens:
        starts.append(n_tokens - body)
    return starts


class OnnxInjectionClassifier:
    name = "deberta_injection"

    def __init__(
        self, model_dir: str | Path, *, max_length: int = 512, stride: int = 64, threads: int = 2
    ) -> None:
        model_dir = Path(model_dir)
        self.tokenizer = Tokenizer.from_file(str(model_dir / "tokenizer.json"))
        self.tokenizer.no_truncation()
        self.tokenizer.no_padding()
        self.body = max_length - 2  # room for [CLS] and [SEP]
        self.stride = stride
        self.cls_id = self.tokenizer.token_to_id("[CLS]")
        self.sep_id = self.tokenizer.token_to_id("[SEP]")
        self.pad_id = self.tokenizer.token_to_id("[PAD]") or 0

        options = ort.SessionOptions()
        options.intra_op_num_threads = threads
        self.session = ort.InferenceSession(
            str(model_dir / "model.onnx"), options, providers=["CPUExecutionProvider"]
        )
        self.input_names = {i.name for i in self.session.get_inputs()}

        config = json.loads((model_dir / "config.json").read_text())
        labels = {int(k): str(v).upper() for k, v in config["id2label"].items()}
        self.injection_index = next(i for i, label in labels.items() if "INJECTION" in label)
        self.model_id = model_dir.name

    def _batch_scores(self, windows: list[list[int]]) -> np.ndarray:
        width = max(len(w) for w in windows)
        input_ids = np.full((len(windows), width), self.pad_id, dtype=np.int64)
        attention = np.zeros((len(windows), width), dtype=np.int64)
        for row, window in enumerate(windows):
            input_ids[row, : len(window)] = window
            attention[row, : len(window)] = 1
        feeds = {"input_ids": input_ids, "attention_mask": attention}
        if "token_type_ids" in self.input_names:
            feeds["token_type_ids"] = np.zeros_like(input_ids)
        outputs = self.session.run(None, {k: v for k, v in feeds.items() if k in self.input_names})
        logits = outputs[0]
        shifted = logits - logits.max(axis=1, keepdims=True)
        probs = np.exp(shifted) / np.exp(shifted).sum(axis=1, keepdims=True)
        return probs[:, self.injection_index]

    def detect(self, text: str) -> DetectionResult:
        start = time.perf_counter()
        if not text.strip():
            return DetectionResult(self.name, 0.0)

        ids = self.tokenizer.encode(text, add_special_tokens=False).ids
        starts = window_starts(len(ids), self.body, self.stride)
        truncated = len(starts) > MAX_WINDOWS
        starts = starts[:MAX_WINDOWS]
        windows = [[self.cls_id, *ids[s : s + self.body], self.sep_id] for s in starts]

        scores = np.concatenate(
            [
                self._batch_scores(windows[i : i + BATCH_SIZE])
                for i in range(0, len(windows), BATCH_SIZE)
            ]
        )
        worst = int(np.argmax(scores))
        score = round(float(scores[worst]), 3)
        return DetectionResult(
            self.name,
            score,
            AttackType.INDIRECT_INSTRUCTION if score >= 0.5 else AttackType.NONE,
            latency_ms=int((time.perf_counter() - start) * 1000),
            meta={
                "model": self.model_id,
                "tokens": len(ids),
                "windows": len(windows),
                "worst_window": worst,
                "truncated": truncated,
            },
        )
