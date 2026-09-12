from pathlib import Path

import pytest

from gateway.pipeline.policy import Policy, PolicyDocument, load_policy

POLICY_PATH = Path(__file__).parents[2] / "policies" / "default.yaml"


@pytest.fixture(scope="module")
def policy() -> Policy:
    return load_policy(POLICY_PATH)


def codes(result) -> list[str]:
    return [v.code for v in result.violations]


def test_default_policy_loads_with_version(policy: Policy) -> None:
    assert policy.version
    assert len(policy.source_sha256) == 64


def test_unknown_tool_is_denied_and_treated_as_tier_3(policy: Policy) -> None:
    result = policy.evaluate_tool_call("launch_missiles", {})
    assert not result.allowed
    assert result.tier == 3 and codes(result) == ["unknown_tool"]


def test_clean_read_only_call_is_allowed(policy: Policy) -> None:
    result = policy.evaluate_tool_call("search_docs", {"query": "Q3 revenue"})
    assert result.allowed and result.tier == 0


def test_missing_and_unexpected_args(policy: Policy) -> None:
    result = policy.evaluate_tool_call("search_docs", {"q": "x"})
    assert sorted(codes(result)) == ["missing_arg", "unexpected_arg"]


@pytest.mark.parametrize(
    "url, allowed",
    [
        ("https://api.company.com/v1/items", True),
        ("https://eu.api.company.com/v1/items", True),
        ("https://api.company.com.evil.io/steal", False),
        ("https://evil.io/?next=api.company.com", False),
        ("ftp://api.company.com/file", False),
    ],
)
def test_http_post_strict_allowlist(policy: Policy, url: str, allowed: bool) -> None:
    result = policy.evaluate_tool_call("http_post", {"url": url, "payload": {}})
    assert result.allowed is allowed


def test_email_allowlist_is_deferred_not_denied(policy: Policy) -> None:
    result = policy.evaluate_tool_call("send_email", {"to": "me@gmail.com", "subject": "hi"})
    assert result.allowed
    assert result.deferred_allowlist_args == ["to"]


@pytest.mark.parametrize(
    "query",
    ["DROP TABLE users", "select 1; delete from users", "SELECT * FROM t; SELECT 2"],
)
def test_sql_write_and_stacked_statements_denied(policy: Policy, query: str) -> None:
    result = policy.evaluate_tool_call("run_sql", {"query": query})
    assert "denied_pattern" in codes(result)


def test_sql_read_allowed(policy: Policy) -> None:
    assert policy.evaluate_tool_call("run_sql", {"query": "SELECT region, sum(x) FROM s"}).allowed


@pytest.mark.parametrize("amount", [0, -5, 10_000, float("inf"), "100", True])
def test_transfer_amount_bounds_and_types(policy: Policy, amount) -> None:
    result = policy.evaluate_tool_call(
        "transfer_funds", {"account": "ACC-123456", "amount": amount}
    )
    assert not result.allowed


def test_sensitive_args_are_exposed(policy: Policy) -> None:
    tool = policy.document.tools["transfer_funds"]
    assert set(tool.sensitive_args) == {"account", "amount"}


def test_policy_rejects_dangling_budget_reference() -> None:
    with pytest.raises(ValueError, match="unknown budget"):
        PolicyDocument.model_validate(
            {"version": "x", "tools": {"t": {"tier": 1, "description": "d", "budget": "nope"}}}
        )
