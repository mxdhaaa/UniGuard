"""
System Health & Diagnostics API Routes (Milestone 2, Hardened in Milestone 15)
"""

from fastapi import APIRouter
from backend.app.config import settings
from backend.app.schemas.system import HealthResponse, SystemStatusResponse

router = APIRouter(tags=["System"])


@router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """Returns basic liveness status of the UniGuard backend service."""
    return HealthResponse(
        status="ok",
        service=settings.service_name,
        version=settings.app_version,
    )


@router.get("/system/status", response_model=SystemStatusResponse)
def get_system_status() -> SystemStatusResponse:
    """
    Returns subsystem readiness status for deployment health checks.
    Database health is verified via a live connection test.
    """
    from backend.app.db.database import check_db_health
    from backend.app.ml.model_manager import get_state
    from backend.app.schemas.ml import ModelReadinessState
    from backend.app.services.ingestion_service import ingestion_service
    
    db_ok = check_db_health()
    ml_state = get_state()
    
    ingestion_status = ingestion_service.get_status()
    ingestion_str = "ready" if ingestion_status.state == "RUNNING" else "not_ready"
    
    return SystemStatusResponse(
        backend="healthy",
        database="healthy" if db_ok else "unavailable",
        ml_engine="ready" if ml_state == ModelReadinessState.READY else "not_ready",
        ingestion=ingestion_str,
    )
