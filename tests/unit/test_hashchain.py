from datetime import UTC, datetime
from uuid import uuid4

from gateway.db.hashchain import GENESIS_HASH, compute_row_hash, verify_chain


def _build_chain(n: int) -> list[dict]:
    rows, prev = [], GENESIS_HASH
    for i in range(n):
        row = {
            "id": uuid4(),
            "decision": "ALLOW" if i % 2 else "DENY",
            "reasons": {"rule": f"r{i}"},
            "created_at": datetime(2026, 9, 12, 12, i, tzinfo=UTC),
            "prev_hash": prev,
        }
        row["row_hash"] = compute_row_hash(prev, row)
        prev = row["row_hash"]
        rows.append(row)
    return rows


def test_valid_chain_verifies() -> None:
    result = verify_chain(_build_chain(5))
    assert result.ok and result.checked == 5


def test_modified_row_is_detected() -> None:
    rows = _build_chain(5)
    rows[2]["decision"] = "ALLOW_TAMPERED"
    result = verify_chain(rows)
    assert not result.ok and result.broken_at == 2
    assert result.reason == "row content was modified"


def test_deleted_row_is_detected() -> None:
    rows = _build_chain(5)
    del rows[1]
    result = verify_chain(rows)
    assert not result.ok and result.broken_at == 1


def test_hash_is_independent_of_key_order() -> None:
    a = {"x": 1, "y": 2}
    b = {"y": 2, "x": 1}
    assert compute_row_hash(GENESIS_HASH, a) == compute_row_hash(GENESIS_HASH, b)
