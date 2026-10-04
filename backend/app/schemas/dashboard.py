from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class PaginationMeta(BaseModel):
    page: int
    page_size: int
    total_items: int
    total_pages: int

# Flow Responses
class DashboardFlowSummary(BaseModel):
    flow_id: str
    timestamp: str
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    protocol: str
    threat_type: str
    classifier_confidence: float
    anomaly_score: float
    is_anomaly: bool
    risk_score: float
    severity: str

class PaginatedFlowResponse(BaseModel):
    data: List[DashboardFlowSummary]
    meta: PaginationMeta

class DashboardFlowDetail(BaseModel):
    flow: Dict[str, Any]
    features: Dict[str, Any]
    ml_result: Dict[str, Any]
    risk_assessment: Dict[str, Any]
    evidence: List[Dict[str, Any]]
    alert: Optional[Dict[str, Any]] = None

# Alert Responses
class DashboardAlertSummary(BaseModel):
    alert_id: str
    flow_id: str
    threat_type: str
    risk_score: float
    severity: str
    status: str
    summary: str
    created_at: str
    updated_at: str

class PaginatedAlertResponse(BaseModel):
    data: List[DashboardAlertSummary]
    meta: PaginationMeta

class DashboardAlertDetail(BaseModel):
    alert: DashboardAlertSummary
    flow: Dict[str, Any]
    ml_result: Dict[str, Any]
    risk_assessment: Dict[str, Any]
    evidence: List[Dict[str, Any]]

# Analytics & Overview
class ThreatAnalytics(BaseModel):
    threat_type_distribution: Dict[str, int]
    severity_distribution: Dict[str, int]
    anomaly_count: int

class DashboardOverview(BaseModel):
    total_flows: int
    total_alerts: int
    high_alerts: int
    critical_alerts: int
    anomaly_count: int
    threat_type_distribution: Dict[str, int]
    severity_distribution: Dict[str, int]
    ingestion_state: str
    ml_readiness: str

# Timeline Responses
class TimelineBucket(BaseModel):
    bucket_time: str
    flow_count: int
    alert_count: int
    high_alert_count: int
    critical_alert_count: int
    anomaly_count: int

class DashboardTimeline(BaseModel):
    interval: str
    buckets: List[TimelineBucket]
