"""
Demo Mode API Endpoints
Provides control endpoints for the safe synthetic traffic simulator.
"""

from typing import List, Optional
from fastapi import APIRouter, HTTPException
from backend.app.schemas.demo import (
    DemoStatusResponse,
    DemoStartRequest,
    DemoBatchRequest,
    DemoResultItem,
)
from backend.app.services.demo_service import demo_service

router = APIRouter(prefix="/demo", tags=["Demo Simulation"])


@router.get("/status", response_model=DemoStatusResponse)
def get_demo_status() -> DemoStatusResponse:
    """Returns current state and statistics of the demo traffic engine."""
    return demo_service.get_status()


@router.post("/start", response_model=DemoStatusResponse)
def start_demo(request: Optional[DemoStartRequest] = None) -> DemoStatusResponse:
    """Starts or resumes synthetic flow simulation with optional PRNG seed."""
    seed = request.seed if request else None
    profile_mix = request.profile_mix if request else None
    try:
        return demo_service.start(seed=seed, profile_mix=profile_mix)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/pause", response_model=DemoStatusResponse)
def pause_demo() -> DemoStatusResponse:
    """Pauses synthetic flow simulation."""
    return demo_service.pause()


@router.post("/stop", response_model=DemoStatusResponse)
def stop_demo() -> DemoStatusResponse:
    """Stops synthetic flow simulation."""
    return demo_service.stop()


@router.post("/clear", response_model=DemoStatusResponse)
def clear_demo() -> DemoStatusResponse:
    """Resets synthetic flow simulation counter and PRNG state."""
    return demo_service.clear()


@router.post("/batch", response_model=List[DemoResultItem])
def generate_batch(request: DemoBatchRequest) -> List[DemoResultItem]:
    """
    Generates a batch of synthetic unidirectional flows and processes them
    through the feature extraction and preprocessing pipeline.
    """
    try:
        return demo_service.generate_batch(
            count=request.count,
            profile_mix=request.profile_mix,
            seed=request.seed,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
