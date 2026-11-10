from pathlib import Path
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="MALBOX_",
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    PROJECT_NAME: str = "malbox-ai"
    VERSION: str = "0.1.0"
    DESCRIPTION: str = "AI-Driven Dynamic Malware Analysis & Behavioral Intelligence Platform"
    ENV: str = "development"
    DEBUG: bool = True
    SECRET_KEY: str = "malbox-development-secret-key-32chars-minimum"
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]

    # Anchored directories (workspace root)
    WORKSPACE_ROOT: Path = Path(__file__).resolve().parent.parent.parent.parent
    DATA_DIR: Path = Field(default_factory=lambda: Path(__file__).resolve().parent.parent.parent.parent / "data")
    QUARANTINE_DIR: Path = Field(default_factory=lambda: Path(__file__).resolve().parent.parent.parent.parent / "data" / "quarantine")
    ARTIFACTS_DIR: Path = Field(default_factory=lambda: Path(__file__).resolve().parent.parent.parent.parent / "data" / "artifacts")
    FIXTURES_DIR: Path = Field(default_factory=lambda: Path(__file__).resolve().parent.parent.parent.parent / "fixtures" / "replay")
    
    # SQLite DB URL dynamically based on DATA_DIR
    DATABASE_URL: str = ""

    # Upload & Security Limits
    MAX_UPLOAD_SIZE_BYTES: int = 33554432  # 32 MB
    LIVE_MODE_ENABLED: bool = False
    REQUIRE_EXPLICIT_APPROVAL: bool = True
    OPERATOR_TOKEN: str = ""  # Must be explicitly configured via MALBOX_OPERATOR_TOKEN to enable live operations
    WORKER_CONCURRENCY: int = 1
    DEFAULT_ANALYSIS_TIMEOUT_SECONDS: int = 120
    JOB_POLL_INTERVAL_SECONDS: float = 0.5

    # AI Orchestration & Phase 2A/2B Reporting Security
    AI_PROVIDER: str = "mock"  # mock, real, openai, ollama
    AI_REPORTING_MODE: str = "opt_in"  # opt_in, deterministic, llm, opencode
    AI_MODEL: str = "gpt-4o-mini"
    AI_API_KEY: str = ""
    AI_BASE_URL: str = "https://api.openai.com/v1"
    AI_TIMEOUT_SECONDS: float = 30.0
    AI_MAX_TOKENS: int = 2048
    AI_TEMPERATURE: float = 0.1

    # Reporting Enrichment Authorization, Consent & Budget (No hardcoded secrets; fail closed)
    REPORTING_AUTH_TOKEN: str = ""  # Required via X-Reporting-Token for POST .../report/intelligence
    REPORTING_EXTERNAL_AI_CONSENT: bool = False  # Server-level consent for sending evidence to external providers
    REPORTING_RATE_LIMIT_REQUESTS: int = 10
    REPORTING_RATE_LIMIT_WINDOW_SECONDS: int = 60
    REPORTING_MAX_CONCURRENT_JOBS: int = 2
    REPORTING_ENRICHMENT_TIMEOUT_SECONDS: float = 35.0

    # OpenCode Restricted Reporting Adapter (Disabled & opt-in by default; requires bwrap OS sandbox)
    OPENCODE_ENABLED: bool = False
    OPENCODE_BIN: str = "opencode"
    OPENCODE_SANDBOX_BIN: str = "bwrap"
    OPENCODE_AGENT_NAME: str = "report-analyst"
    OPENCODE_MODEL: str = ""
    OPENCODE_ALLOW_NETWORK: bool = False
    OPENCODE_ALLOWED_PROVIDER_URL: str = ""
    OPENCODE_TIMEOUT_SECONDS: float = 30.0
    OPENCODE_MAX_OUTPUT_BYTES: int = 262144
    OPENCODE_MAX_CPU_SECONDS: int = 25
    OPENCODE_MAX_MEMORY_MB: int = 2048
    OPENCODE_MAX_DATA_MB: int = 512
    OPENCODE_MAX_SANDBOX_TMPFS_BYTES: int = 16777216
    OPENCODE_PROVIDER_API_KEY: str = ""
    OPENCODE_PROVIDER_ENV_NAME: str = "OPENAI_API_KEY"

    # Pluggable Sandbox Settings
    DEFAULT_SANDBOX_BACKEND: str = "replay"  # replay, cape
    CAPE_API_URL: str = "http://127.0.0.1:8008"  # Distinct from application port 8000
    CAPE_API_TOKEN: str = ""
    CAPE_TIMEOUT_SECONDS: int = 300
    CAPE_POLL_INTERVAL_SECONDS: int = 5

    def get_database_url(self) -> str:
        if self.DATABASE_URL:
            return self.DATABASE_URL
        return f"sqlite:///{self.DATA_DIR}/malbox.db"

    def setup_directories(self) -> None:
        """Ensure private data, quarantine, and artifact directories exist with safe permissions."""
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        self.ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
        self.FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
        try:
            self.QUARANTINE_DIR.chmod(0o700)
        except OSError:
            pass

settings = Settings()
settings.setup_directories()
