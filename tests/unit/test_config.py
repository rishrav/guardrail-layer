import pytest

from gateway.config import Settings


def test_fail_open_tiers_parsed_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDRAIL_FAIL_OPEN_TIERS", "0")
    settings = Settings(_env_file=None)
    assert settings.fail_open_tiers == frozenset({0})


def test_api_key_is_not_leaked_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDRAIL_API_KEY", "super-secret-value")
    settings = Settings(_env_file=None)
    assert "super-secret-value" not in repr(settings)
    assert settings.api_key.get_secret_value() == "super-secret-value"
