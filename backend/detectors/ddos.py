"""
DDoS Volumetric Detector
Detects traffic flood & volumetric anomalies using multi-indicator packet and byte rate features.
"""

from typing import Optional, List, Dict, Any
from .base import BaseDetector
from ..schemas import FlowRecord, DetectionResult, EvidenceItem
from ..config import CONFIG


class DDoSDetector(BaseDetector):
    @property
    def name(self) -> str:
        return "DDoSDetector"

    def analyze(self, flow: FlowRecord, features: Dict[str, Any], context_flows: Optional[List[FlowRecord]] = None) -> Optional[DetectionResult]:
        pps = features.get("packets_per_second", 0.0)
        bps = features.get("bytes_per_second", 0.0)
        packet_count = flow.packet_count

        # Must meet minimum volumetric criteria
        if pps < CONFIG.ddos.min_pps_threshold and bps < CONFIG.ddos.min_bps_threshold:
            return None

        if packet_count < CONFIG.ddos.min_packets:
            return None

        # Multi-indicator score
        pps_factor = min(1.0, pps / (CONFIG.ddos.min_pps_threshold * 2))
        bps_factor = min(1.0, bps / (CONFIG.ddos.min_bps_threshold * 2))
        pkt_factor = min(1.0, packet_count / (CONFIG.ddos.min_packets * 5))

        confidence = round(0.50 * pps_factor + 0.30 * bps_factor + 0.20 * pkt_factor, 4)

        if confidence < CONFIG.ddos.min_confidence:
            return None

        severity = "CRITICAL" if confidence >= 0.85 else "HIGH"

        evidence = [
            EvidenceItem(
                feature="packets_per_second",
                value=round(pps, 2),
                interpretation=f"Sustained packet rate of {round(pps, 1)} pps exceeds volumetric threshold ({CONFIG.ddos.min_pps_threshold} pps)"
            ),
            EvidenceItem(
                feature="bytes_per_second",
                value=round(bps, 2),
                interpretation=f"Egress throughput of {round(bps / 1024, 1)} KB/s"
            ),
            EvidenceItem(
                feature="packet_count",
                value=packet_count,
                interpretation=f"High total packet volume ({packet_count} packets) within {flow.duration}s window"
            )
        ]

        return DetectionResult(
            flow_id=flow.flow_id,
            threat_class="DDoS",
            severity=severity,
            confidence=confidence,
            source=f"{flow.src_ip}:{flow.src_port}",
            destination=f"{flow.dst_ip}:{flow.dst_port}",
            protocol=flow.protocol,
            evidence=evidence,
            detector=self.name,
            status="NEW"
        )
