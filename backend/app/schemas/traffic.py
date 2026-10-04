"""
Directional Flow & Feature Vector Schemas
Represents unidirectional network telemetry and extracted behavioral feature vectors.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class DirectionalFlowRecord(BaseModel):
    """
    Directional (one-way) flow representation (A -> B).
    Strictly does not require reverse-direction (B -> A) traffic.
    """

    flow_id: str = Field(..., description="Unique deterministic or generated flow identifier")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp of initial packet observation")
    source_ip: str = Field(..., description="Source IPv4/IPv6 address")
    source_port: int = Field(..., ge=0, le=65535, description="Source transport port")
    destination_ip: str = Field(..., description="Destination IPv4/IPv6 address")
    destination_port: int = Field(..., ge=0, le=65535, description="Destination transport port")
    protocol: str = Field(..., description="Transport/application protocol (TCP, UDP, ICMP, DNS, etc.)")
    duration: float = Field(default=0.0, ge=0.0, description="Flow duration in seconds")
    packet_count: int = Field(default=0, ge=0, description="Total packet count in this directional flow")
    byte_count: int = Field(default=0, ge=0, description="Total byte volume in this directional flow")
    packet_sizes: List[int] = Field(default_factory=list, description="Ordered list of individual packet sizes in bytes")
    packet_timestamps: List[float] = Field(default_factory=list, description="Ordered epoch timestamps for packet arrivals")
    inter_arrival_times: List[float] = Field(default_factory=list, description="Gaps between consecutive packets in seconds")
    dns_query: Optional[str] = Field(default=None, description="Extracted DNS query name if applicable")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Auxiliary flow telemetry metadata")


class FeatureVector(BaseModel):
    """
    Deterministic 16-feature vector extracted from unidirectional flow telemetry.
    All fields are finite numerics with safe mathematical defaults.
    """

    flow_duration: float = Field(..., description="Flow duration in seconds")
    packet_count: int = Field(..., description="Total packet count")
    byte_count: int = Field(..., description="Total byte count")
    packets_per_second: float = Field(..., description="Packet rate (pps)")
    bytes_per_second: float = Field(..., description="Byte rate (Bps)")
    average_packet_size: float = Field(..., description="Arithmetic mean packet size in bytes")
    packet_size_std: float = Field(..., description="Sample standard deviation of packet sizes")
    unique_destination_count: int = Field(..., description="Count of distinct destination IPs from source")
    unique_destination_port_count: int = Field(..., description="Count of distinct destination ports from source")
    destination_port_entropy: float = Field(..., description="Shannon entropy of destination port distribution (bits)")
    packet_size_entropy: float = Field(..., description="Shannon entropy of packet size distribution (bits)")
    burst_score: float = Field(..., description="Deterministic temporal burst score in [0.0, 1.0]")
    source_activity_rate: float = Field(..., description="Flow initiation rate from source IP (flows/second)")
    destination_diversity: float = Field(..., description="Ratio of unique destinations to total context flows in [0.0, 1.0]")
    port_diversity: float = Field(..., description="Ratio of unique destination ports to total context flows in [0.0, 1.0]")
    protocol_indicator: float = Field(..., description="Numeric encoding of protocol (1.0=TCP, 2.0=UDP, 3.0=ICMP, 4.0=DNS, 0.0=OTHER)")


class PreprocessedFeatureVector(BaseModel):
    """
    Sanitized, ordered feature vector suitable for direct consumption by ML models.
    """

    feature_names: List[str] = Field(..., description="Ordered list of feature names")
    values: List[float] = Field(..., description="Ordered list of numeric feature values (no NaN or Inf)")
    is_valid: bool = Field(default=True, description="True if feature vector passed numerical validation")
