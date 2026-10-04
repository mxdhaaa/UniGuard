"""
UniGuard Ingestion API Schemas
"""
from typing import Optional
from pydantic import BaseModel, Field

class IngestionStatusResponse(BaseModel):
    state: str = Field(..., description="Current collector state: RUNNING or STOPPED")
    interface: str = Field(..., description="Configured network interface")
    capture_filter: str = Field(..., description="Active BPF capture filter")
    active_flows: int = Field(..., description="Number of flows currently being tracked")
    packets_captured: int = Field(..., description="Total packets captured in this session")
    flows_completed: int = Field(..., description="Total flows expired and processed")
    errors: int = Field(..., description="Number of processing or persistence errors encountered")
