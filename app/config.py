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
