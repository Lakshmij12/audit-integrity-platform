"""Service configuration from environment variables (prefix ``AIP_``)."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings. Secrets are never stored here in clear: API keys are SHA-256 hashes."""

    model_config = SettingsConfigDict(env_prefix="AIP_", extra="ignore")

    db_path: str = "data/audit.db"
    busy_timeout_ms: int = Field(default=5000, ge=0)
    # Comma-separated "role:sha256hex" entries; generate with `python -m aip.cli new-api-key`.
    api_keys: str = ""
    max_body_bytes: int = Field(default=131_072, ge=1024)  # 128 KiB raw request body
    # Ed25519 private key (PEM) for signed checkpoints; create with `python -m aip.cli
    # new-signing-key`. Optional: without it, verification works but checkpoints return 503.
    signing_key_path: str | None = None
    # Retention: records whose recordedAt is older than this many days can be archived.
    retention_window_days: int = Field(default=365, ge=1)
    # Archive files written by retention runs (plaintext payloads; keep access restricted).
    archive_dir: str = "archives"
