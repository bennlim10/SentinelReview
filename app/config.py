from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    github_token: SecretStr | None = None
    github_timeout_seconds: float = Field(default=20, gt=0)
    scan_timeout_seconds: float = Field(default=30, gt=0)
    semgrep_timeout_seconds: float = Field(default=120, gt=0)
    max_python_files: int = Field(default=50, gt=0, le=3000)
    max_file_bytes: int = Field(default=500_000, gt=0)
    max_total_bytes: int = Field(default=5_000_000, gt=0)

    ai_enabled: bool = False
    ai_provider: str | None = None
    ai_model: str | None = None
    ai_endpoint: str | None = None
    ai_api_key: SecretStr | None = None
    ai_timeout_seconds: float = Field(default=30, gt=0)
    ai_max_findings: int = Field(default=3, ge=0, le=50)
    ai_max_context_chars: int = Field(default=12000, ge=1000, le=100000)
    ai_context_lines: int = Field(default=15, ge=0, le=100)
    ai_changed_lines_only: bool = False
    ai_max_output_tokens: int = Field(default=1200, ge=100, le=10000)
    ai_max_response_bytes: int = Field(default=65536, ge=1024, le=1000000)
    ai_evaluation_output: str | None = None
