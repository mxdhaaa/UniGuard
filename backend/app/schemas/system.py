"""
System & Health Schemas for UniGuard API
"""

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Health check response schema."""

    status: str = Field(..., description="Service status indicator")
    service: str = Field(..., description="Name of the service")
    version: str = Field(..., description="Application semantic version")


class SystemStatusResponse(BaseModel):
    """Component status indicators across subsystems."""

    backend: str = Field(..., description="Backend operational status")
    database: str = Field(..., description="Database connectivity status")
    ml_engine: str = Field(..., description="ML inference engine status")
    ingestion: str = Field(..., description="Traffic telemetry ingestion status")
