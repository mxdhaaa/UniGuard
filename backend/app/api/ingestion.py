"""
UniGuard Ingestion API (Milestone 10)
"""
from fastapi import APIRouter
from backend.app.schemas.ingestion import IngestionStatusResponse
from backend.app.services.ingestion_service import ingestion_service

router = APIRouter(prefix="/ingestion", tags=["Live Ingestion"])

@router.get("/status", response_model=IngestionStatusResponse)
def get_ingestion_status() -> IngestionStatusResponse:
    """Get the operational status of the live traffic collector."""
    return ingestion_service.get_status()

@router.post("/start", response_model=IngestionStatusResponse)
def start_ingestion() -> IngestionStatusResponse:
    """Start live traffic capture in the background."""
    return ingestion_service.start()

@router.post("/stop", response_model=IngestionStatusResponse)
def stop_ingestion() -> IngestionStatusResponse:
    """Stop live traffic capture safely and flush active flows."""
    return ingestion_service.stop()
