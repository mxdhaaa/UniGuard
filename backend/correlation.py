"""
UniGuard Risk & Correlation Layer
Combines multiple suspicious signals for the same source endpoint or flow window.
"""
from typing import List, Dict
from .schemas import DetectionResult, EvidenceItem
class RiskCorrelationEngine:
    """
    Lightweight correlation layer that:
    1. Consolidates repeated reconnaissance detections into one incident.
    2. Boosts confidence when multiple distinct threat signals come from the same source.
    """
    @classmethod
    def correlate(cls, detections: List[DetectionResult]) -> List[DetectionResult]:
        if not detections:
            return []
        # First consolidate repeated reconnaissance alerts.
        recon_groups: Dict[str, List[DetectionResult]] = {}
        other_detections: List[DetectionResult] = []
        for det in detections:
            if det.threat_class == "RECONNAISSANCE":
                src_ip = det.source.split(":")[0]
                dst_ip = det.destination.split(":")[0]
                group_key = f"{src_ip}|{dst_ip}"
                recon_groups.setdefault(group_key, []).append(det)
            else:
                other_detections.append(det)
        consolidated: List[DetectionResult] = list(other_detections)
        for group in recon_groups.values():
            representative = group[0]
            unique_ports = sorted({
                int(det.destination.split(":")[1])
                for det in group
                if ":" in det.destination
            })
            representative.flow_id = f"RECON-GROUP-{representative.source.split(':')[0]}"
            representative.evidence.append(
                EvidenceItem(
                    feature="correlated_scan_flows",
                    value=len(group),
                    interpretation=f"Grouped {len(group)} reconnaissance flows from the same source to the same destination"
                )
            )
            representative.evidence.append(
                EvidenceItem(
                    feature="unique_destination_ports",
                    value=len(unique_ports),
                    interpretation=f"Observed connection attempts across {len(unique_ports)} destination ports"
                )
            )
            representative.confidence = min(
                0.99,
                round(
                    max(
                        det.confidence for det in group
                    ) + min(0.15, 0.01 * max(0, len(unique_ports) - 8)),
                    4
                )
            )
            if len(unique_ports) >= 20:
                representative.severity = "HIGH"
            else:
                representative.severity = "MEDIUM"
            consolidated.append(representative)
        # Group remaining detections by source IP for multi-signal correlation.
        src_groups: Dict[str, List[DetectionResult]] = {}
        for det in consolidated:
            src_ip = det.source.split(":")[0]
            src_groups.setdefault(src_ip, []).append(det)
        correlated_results: List[DetectionResult] = []
        for src_ip, group in src_groups.items():
            if len(group) == 1:
                correlated_results.append(group[0])
                continue
            distinct_threats = set(d.threat_class for d in group)
            boost = min(0.15, 0.05 * (len(distinct_threats) - 1))
            for det in group:
                if boost > 0 and not any(
                    e.feature == "multi_signal_correlation_boost"
                    for e in det.evidence
                ):
                    det.confidence = min(
                        0.99,
                        round(det.confidence + boost, 4)
                    )
                    det.evidence.append(
                        EvidenceItem(
                            feature="multi_signal_correlation_boost",
                            value=f"+{int(boost * 100)}%",
                            interpretation=f"Correlated with {len(distinct_threats)} distinct threat indicators from source {src_ip}"
                        )
                    )
                    if det.confidence >= 0.85:
                        det.severity = (
                            "CRITICAL"
                            if det.threat_class in ["DDoS", "C2_BEACONING"]
                            else "HIGH"
                        )
                correlated_results.append(det)
        return correlated_results
