"""
UniGuard Backend Configuration
Centralized detection thresholds and system parameters.
"""

from pydantic import BaseModel


class C2BeaconingConfig(BaseModel):
    max_cv_threshold: float = 0.25      # Inter-arrival CV below 0.25 indicates high periodicity
    min_packets: int = 5                # Minimum packets in flow to analyze periodicity
    min_confidence: float = 0.60
    high_confidence: float = 0.85


class DDoSConfig(BaseModel):
    min_pps_threshold: float = 500.0    # Packets per second threshold for flood
    min_bps_threshold: float = 1_000_000.0  # 1 MB/s threshold
    min_packets: int = 100
    min_confidence: float = 0.65


class DNSTunnellingConfig(BaseModel):
    min_shannon_entropy: float = 3.8     # Domain entropy threshold (bits/char)
    min_query_length: int = 35          # Suspicious query length
    min_digit_ratio: float = 0.25       # Ratio of digits in domain string
    min_confidence: float = 0.60


class ReconnaissanceConfig(BaseModel):
    min_unique_ports: int = 8           # Unique destination ports probed by single source
    min_unique_hosts: int = 8           # Unique destination IPs probed
    min_scan_rate_pps: float = 5.0      # Probes per second
    min_confidence: float = 0.60


class SensorConfig(BaseModel):
    flow_idle_timeout_sec: float = 30.0
    c2: C2BeaconingConfig = C2BeaconingConfig()
    ddos: DDoSConfig = DDoSConfig()
    dns: DNSTunnellingConfig = DNSTunnellingConfig()
    recon: ReconnaissanceConfig = ReconnaissanceConfig()


CONFIG = SensorConfig()
