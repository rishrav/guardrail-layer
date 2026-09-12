from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Gateway configuration loaded from environment variables (and `.env` in dev).

    Secrets are typed as SecretStr so they never show up in reprs or logs.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", populate_by_name=True)

    env: str = Field("dev", alias="GUARDRAIL_ENV")
    api_key: SecretStr = Field(SecretStr("change-me-local-dev-key"), alias="GUARDRAIL_API_KEY")
    policy_path: str = Field("policies/default.yaml", alias="GUARDRAIL_POLICY_PATH")
    fail_open_tiers_raw: str = Field("0,1", alias="GUARDRAIL_FAIL_OPEN_TIERS")

    database_url: str = Field(
        "postgresql+asyncpg://guardrail:change-me@localhost:5432/guardrail", alias="DATABASE_URL"
    )
    redis_url: str = Field("redis://localhost:6379/0", alias="REDIS_URL")

    model_base_url: str = Field("http://localhost:11434", alias="MODEL_BASE_URL")
    model_timeout_s: float = Field(30.0, alias="MODEL_TIMEOUT_S")
    judge_model: str = Field("qwen3:8b", alias="JUDGE_MODEL")
    guardian_model: str = Field("granite3-guardian:2b", alias="GUARDIAN_MODEL")

    injection_model_dir: str = Field(
        "models/weights/deberta-v3-prompt-injection-v2", alias="INJECTION_MODEL_DIR"
    )
    llm_classifier_enabled: bool = Field(True, alias="LLM_CLASSIFIER_ENABLED")
    ambiguous_low: float = Field(0.3, alias="DETECTION_AMBIGUOUS_LOW")
    ambiguous_high: float = Field(0.8, alias="DETECTION_AMBIGUOUS_HIGH")

    adjudicator_enabled: bool = Field(True, alias="ADJUDICATOR_ENABLED")
    adjudicator_models_enabled: bool = Field(True, alias="ADJUDICATOR_MODELS_ENABLED")
    adjudicator_timeout_s: float = Field(60.0, alias="ADJUDICATOR_TIMEOUT_S")
    guardian_risk: str = Field("unethical_behavior", alias="GUARDIAN_RISK")

    @property
    def fail_open_tiers(self) -> frozenset[int]:
        """Risk tiers allowed to proceed when the gateway itself is unreachable."""
        return frozenset(int(t) for t in self.fail_open_tiers_raw.split(",") if t.strip())


@lru_cache
def get_settings() -> Settings:
    return Settings()
