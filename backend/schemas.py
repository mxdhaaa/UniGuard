"""
UniGuard Data Schemas & API Request/Response Models
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
import uuid
from datetime import datetime, timezone


class FlowRecord(BaseModel):
    flow_id: str
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_count: int
    byte_count: int
    duration: float
    packet_sizes: List[int] = Field(default_factory=list)
    inter_arrival_times: List[float] = Field(default_factory=list)
    dns_query: Optional[str] = None


class EvidenceItem(BaseModel):
    feature: str
    value: Any
    interpretation: str


class DetectionResult(BaseModel):
    id: str = Field(default_factory=lambda: f"DET-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    flow_id: str
    threat_class: str  # C2_BEACONING, DDoS, DNS_TUNNELLING_DGA, RECONNAISSANCE
    severity: str      # CRITICAL, HIGH, MEDIUM, LOW
    confidence: float  # 0.0 to 1.0
    source: str        # e.g., "10.24.8.21:49812"
    destination: str   # e.g., "185.220.101.5:443"
    protocol: str
    evidence: List[EvidenceItem] = Field(default_factory=list)
    detector: str
    status: str = "NEW"


class IngestResponse(BaseModel):
    flows_processed: int
    detections: int
    processing_time_ms: float


class StatsResponse(BaseModel):
    total_flows_analyzed: int
    total_detections: int
    active_detectors: List[str]
    threat_counts: Dict[str, int]
