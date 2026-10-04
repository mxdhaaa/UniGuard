"""
UniGuard PCAP API Schemas
"""
from pydantic import BaseModel, Field
from typing import Optional

class PcapJobUploadResponse(BaseModel):
    job_id: str = Field(..., description="Unique identifier for the PCAP processing job")
    status: str = Field(..., description="Initial job status (e.g., PROCESSING)")
    message: str = Field(..., description="Human readable message")

class PcapJobStatusResponse(BaseModel):
    job_id: str = Field(..., description="Unique identifier for the PCAP processing job")
    status: str = Field(..., description="Current status: PROCESSING, COMPLETED, or FAILED")
    filename: str = Field(..., description="Original uploaded filename")
    total_packets: int = Field(0, description="Number of packets read so far")
    flows_completed: int = Field(0, description="Number of flows successfully aggregated and processed")
    errors: int = Field(0, description="Number of malformed packets or pipeline errors encountered")
    message: Optional[str] = Field(None, description="Detailed error message if failed")
