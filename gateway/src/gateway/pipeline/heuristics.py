"""Layer 1: fast, deterministic injection heuristics (well under 5 ms).

The text is normalized first, so simple obfuscation can't dodge the signatures:
- Unicode NFKC normalization.
- Zero-width and bidi characters removed.
- Common Cyrillic/Greek homoglyphs folded to Latin.
- base64 / hex blobs decoded and scanned too.
"""

from __future__ import annotations

import base64
import binascii
import re
import time
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass

from gateway.pipeline.detection_types import AttackType, DetectionResult

_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤﻿­]")
_HOMOGLYPHS = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
        "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "α": "a", "ε": "e", "ο": "o",
        "ρ": "p", "τ": "t", "υ": "u", "ι": "i", "κ": "k", "ν": "v",
    }
)  # fmt: skip
_BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_BLOB = re.compile(r"\b(?:[0-9a-fA-F]{2}){16,}\b")

DEFAULT_TOOL_NAMES = (
    "transfer_funds",
    "send_email",
    "http_post",
    "exec_shell",
    "delete_records",
    "run_sql",
)


@dataclass(frozen=True)
class Signature:
    name: str
    pattern: re.Pattern[str]
    weight: float
    attack_type: AttackType


def _sig(name: str, regex: str, weight: float, attack: AttackType) -> Signature:
    return Signature(name, re.compile(regex, re.IGNORECASE | re.DOTALL), weight, attack)


BASE_SIGNATURES: tuple[Signature, ...] = (
    _sig(
        "override_instructions",
        r"\b(ignore|disregard|forget|override|bypass)\b.{0,40}?\b(previous|prior|above|earlier|all|any|your)\b"
        r".{0,25}?\b(instructions?|rules|prompts?|directions|guidelines|guardrails)\b",
        0.9,
        AttackType.DIRECT_OVERRIDE,
    ),
    _sig(
        "fake_system_message",
        r"(<\|?\s*(system|im_start|endoftext)\s*\|?>|\[/?(system|inst)\]|^\s*#{0,3}\s*system\s*:"
        r"|\b(important|urgent|new)\s+(system|admin|developer)\s+(update|message|notice|instruction)s?\b)",
        0.6,
        AttackType.INDIRECT_INSTRUCTION,
    ),
    _sig(
        "addressed_to_assistant",
        r"(\b(dear|attention|note to|hey)\s+(ai|assistant|llm|agent|chatbot)\b|<!--.{0,200}?\b(assistant|ai|llm)\b)",
        0.55,
        AttackType.INDIRECT_INSTRUCTION,
    ),
    _sig(
        "secrecy",
        r"\b(do not|don't|never|without)\s+(tell|telling|mention|mentioning|inform|informing|reveal|revealing|alert|alerting)"
        r"\b.{0,20}?\b(the\s+)?(user|anyone|them|human)\b",
        0.6,
        AttackType.INDIRECT_INSTRUCTION,
    ),
    _sig(
        "markdown_image_exfil",
        r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&][^)\s]*=[^)\s]*\)",
        0.75,
        AttackType.EXFILTRATION,
    ),
    _sig(
        "exfil_instruction",
        # Imperative only: "Email sent to x@y.com" / "email was forwarded to" are confirmations.
        # Weight sits below the ambiguous band on its own (S-015); it only adds up with others.
        r"\b(send|e-?mail|forward|post|upload|leak|exfiltrate)\b(?!\s+(sent|was|has|had|is)\b)"
        r".{0,60}?\b(to|at)\b\s*([\w.+-]+@[\w-]+\.[\w.]+|https?://\S+)",
        0.25,
        AttackType.EXFILTRATION,
    ),
    _sig(
        "roleplay_jailbreak",
        r"\b(you are now|from now on you|act as (an? )?(unrestricted|unfiltered|jailbroken)|developer mode"
        r"|\bDAN\b|do anything now|pretend (that )?you have no (rules|restrictions))",
        0.7,
        AttackType.JAILBREAK_ROLEPLAY,
    ),
)  # fmt: skip


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE.sub("", text)
    return text.translate(_HOMOGLYPHS)


def _decoded_payloads(text: str) -> Iterable[str]:
    for blob in _BASE64_BLOB.findall(text):
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        if decoded and sum(32 <= b < 127 for b in decoded) / len(decoded) > 0.9:
            yield decoded.decode("ascii", errors="ignore")
    for blob in _HEX_BLOB.findall(text):
        try:
            decoded = bytes.fromhex(blob)
        except ValueError:
            continue
        if sum(32 <= b < 127 for b in decoded) / len(decoded) > 0.9:
            yield decoded.decode("ascii", errors="ignore")


class HeuristicDetector:
    name = "heuristics"

    def __init__(self, tool_names: Iterable[str] = DEFAULT_TOOL_NAMES) -> None:
        names = "|".join(re.escape(n) for n in tool_names)
        self.signatures = (
            *BASE_SIGNATURES,
            _sig(
                "tool_hijack",
                rf"\b(call|invoke|use|run|execute|trigger)\b.{{0,40}}?\b({names})\b",
                0.7,
                AttackType.TOOL_HIJACK,
            ),
        )

    def _scan(self, text: str) -> list[tuple[Signature, str]]:
        hits = []
        for signature in self.signatures:
            match = signature.pattern.search(text)
            if match:
                hits.append((signature, match.group(0)[:160]))
        return hits

    def detect(self, text: str) -> DetectionResult:
        start = time.perf_counter()
        normalized = normalize(text)
        hits = self._scan(normalized)

        obfuscated = False
        for payload in _decoded_payloads(normalized):
            decoded_hits = self._scan(normalize(payload))
            if decoded_hits:
                obfuscated = True
                hits.extend(decoded_hits)

        invisible_count = len(_INVISIBLE.findall(text))
        if not hits and invisible_count < 3:
            return DetectionResult(self.name, 0.0, latency_ms=_ms(start))

        weights = sorted((sig.weight for sig, _ in hits), reverse=True)
        score = (weights[0] if weights else 0.0) + 0.1 * (len(weights) - 1)
        if obfuscated or (invisible_count >= 3 and hits):
            score += 0.2
        elif invisible_count >= 3:
            score = max(score, 0.3)
        score = round(min(score, 1.0), 3)

        if obfuscated:
            attack = AttackType.OBFUSCATED
        elif hits:
            attack = max(hits, key=lambda h: h[0].weight)[0].attack_type
        else:
            attack = AttackType.OBFUSCATED
        evidence = tuple(dict.fromkeys(span for _, span in hits))[:5]
        return DetectionResult(
            self.name,
            score,
            attack,
            evidence,
            latency_ms=_ms(start),
            meta={"signatures": sorted({sig.name for sig, _ in hits}), "obfuscated": obfuscated},
        )


def _ms(start: float) -> int:
    return int((time.perf_counter() - start) * 1000)
