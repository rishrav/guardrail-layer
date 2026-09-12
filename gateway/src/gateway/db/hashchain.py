"""Tamper-evident hash chain for audit rows.

Each audit row stores ``row_hash = sha256(prev_hash || canonical_json(row))``. Editing,
deleting or reordering any earlier row changes every hash after it, so ``verify_chain``
can point to the first broken link.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

GENESIS_HASH = "0" * 64
HASH_FIELDS_EXCLUDED = frozenset({"row_hash", "prev_hash"})


def _default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    raise TypeError(f"unhashable audit field type: {type(value).__name__}")


def canonicalize(record: Mapping[str, Any]) -> bytes:
    """Deterministic JSON encoding: sorted keys, no whitespace, chain fields removed."""
    body = {k: v for k, v in record.items() if k not in HASH_FIELDS_EXCLUDED}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=_default).encode()


def compute_row_hash(prev_hash: str, record: Mapping[str, Any]) -> str:
    return hashlib.sha256(prev_hash.encode() + canonicalize(record)).hexdigest()


@dataclass(frozen=True)
class ChainVerification:
    ok: bool
    checked: int
    broken_at: int | None = None
    reason: str | None = None


def verify_chain(records: Iterable[Mapping[str, Any]]) -> ChainVerification:
    """Walk records in chain order and confirm every link."""
    expected_prev = GENESIS_HASH
    count = 0
    for index, record in enumerate(records):
        count += 1
        if record["prev_hash"] != expected_prev:
            return ChainVerification(False, count, index, "prev_hash does not match previous row")
        if compute_row_hash(record["prev_hash"], record) != record["row_hash"]:
            return ChainVerification(False, count, index, "row content was modified")
        expected_prev = record["row_hash"]
    return ChainVerification(True, count)
