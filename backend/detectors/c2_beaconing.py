"""
C2 Beaconing Detector
Detects periodic outbound communication patterns based on inter-arrival regularity and destination concentration.
"""

from typing import Optional, List, Dict, Any
from .base import BaseDetector
from ..schemas import FlowRecord, DetectionResult, EvidenceItem
from ..config import CONFIG


class C2BeaconingDetector(BaseDetector):
    @property
    def name(self) -> str:
        return "C2BeaconingDetector"

    def analyze(self, flow: FlowRecord, features: Dict[str, Any], context_flows: Optional[List[FlowRecord]] = None) -> Optional[DetectionResult]:
        cv_iat = features.get("inter_arrival_coefficient_of_variation")
        packet_count = flow.packet_count
        # DNS tunnelling/DGA has a dedicated detector.
        if flow.protocol == "DNS":
            return None
        # Volumetric floods have a dedicated DDoS detector.
        packets_per_second = features.get("packets_per_second", 0.0)
        if packets_per_second >= CONFIG.ddos.min_pps_threshold:
            return None

        # Require minimum packets to evaluate periodicity
        if cv_iat is None or packet_count < CONFIG.c2.min_packets:
            return None

        # Calculate Periodicity Score (0.0 to 1.0)
        # Low CV (e.g. 0.05) -> High Periodicity (0.95)
        periodicity_score = max(0.0, min(1.0, 1.0 - cv_iat))
        dst_concentration = features.get("destination_concentration", 1.0)

        # Combined confidence calculation
        confidence = round(0.70 * periodicity_score + 0.30 * dst_concentration, 4)

        if confidence < CONFIG.c2.min_confidence:
            return None

        # Derive severity strictly from confidence score
        if confidence >= CONFIG.c2.high_confidence:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        evidence = [
            EvidenceItem(
                feature="inter_arrival_cv",
                value=round(cv_iat, 4),
                interpretation="Low inter-arrival coefficient of variation indicates highly periodic beaconing intervals"
            ),
            EvidenceItem(
                feature="periodicity_score",
                value=round(periodicity_score, 4),
                interpretation=f"Periodicity score of {round(periodicity_score * 100, 1)}% across {packet_count} packets"
            ),
            EvidenceItem(
                feature="destination_concentration",
                value=round(dst_concentration, 4),
                interpretation=f"Destination concentration ratio of {round(dst_concentration * 100, 1)}%"
            )
        ]

        return DetectionResult(
            flow_id=flow.flow_id,
            threat_class="C2_BEACONING",
            severity=severity,
            confidence=confidence,
            source=f"{flow.src_ip}:{flow.src_port}",
            destination=f"{flow.dst_ip}:{flow.dst_port}",
            protocol=flow.protocol,
            evidence=evidence,
            detector=self.name,
            status="NEW"
        )

