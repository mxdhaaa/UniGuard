"""
UniGuard Centralized Application Configuration (Milestone 15 Hardened)
Loads settings from environment variables with safe development defaults.
"""

import os
from typing import List
from pydantic import BaseModel, Field


class Settings(BaseModel):
    """Application settings for UniGuard backend."""

    environment: str = Field(default_factory=lambda: os.getenv("ENVIRONMENT", "development"))
    api_host: str = Field(default_factory=lambda: os.getenv("API_HOST", "127.0.0.1"))
    api_port: int = Field(default_factory=lambda: int(os.getenv("API_PORT", "8000")))
    log_level: str = Field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO").upper())
    enable_docs: bool = Field(
        default_factory=lambda: os.getenv("ENABLE_DOCS", "true").lower() in ("true", "1", "yes")
    )

    # CORS origins: comma-separated list of allowed origins.
    cors_origins: List[str] = Field(
        default_factory=lambda: [
            origin.strip()
            for origin in os.getenv(
                "CORS_ORIGINS",
                "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,http://127.0.0.1:3000",
            ).split(",")
            if origin.strip()
        ]
    )

    app_name: str = "UniGuard Passive Network Intelligence API"
    app_version: str = "0.1.0"
    service_name: str = "uniguard-backend"
    
    # Database Configuration
    database_url: str = Field(default_factory=lambda: os.getenv("DATABASE_URL", ""))

    # Live Ingestion Configuration
    capture_interface: str = Field(default_factory=lambda: os.getenv("CAPTURE_INTERFACE", ""))
    capture_filter: str = Field(default_factory=lambda: os.getenv("CAPTURE_FILTER", "ip and (tcp or udp or icmp)"))
    flow_idle_timeout: float = Field(default_factory=lambda: float(os.getenv("FLOW_IDLE_TIMEOUT", "30.0")))
    flow_max_duration: float = Field(default_factory=lambda: float(os.getenv("FLOW_MAX_DURATION", "120.0")))

    # PCAP Ingestion Configuration
    pcap_upload_dir: str = Field(default_factory=lambda: os.getenv("PCAP_UPLOAD_DIR", "./pcap_uploads"))
    pcap_max_file_size_mb: int = Field(default_factory=lambda: int(os.getenv("PCAP_MAX_FILE_SIZE_MB", "50")))

    @property
    def is_production(self) -> bool:
        """Return True if running in production environment."""
        return self.environment.lower() == "production"


settings = Settings()
