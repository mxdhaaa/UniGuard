"""
Reconnaissance / Port Scanning Detector
Detects sequential host sweeps and multi-port probes across internal subnets.
"""

from typing import Optional, List, Dict, Any
from .base import BaseDetector
from ..schemas import FlowRecord, DetectionResult, EvidenceItem
from ..config import CONFIG


class ReconnaissanceDetector(BaseDetector):
    @property
    def name(self) -> str:
        return "ReconnaissanceDetector"

    def analyze(self, flow: FlowRecord, features: Dict[str, Any], context_flows: Optional[List[FlowRecord]] = None) -> Optional[DetectionResult]:
        unique_ports = features.get("unique_destination_port_count", 1)
        unique_hosts = features.get("unique_destination_count", 1)
        scan_rate = features.get("connection_frequency", 0.0)

        # Trigger if single source targets multiple ports or multiple hosts
        port_scan_triggered = unique_ports >= CONFIG.recon.min_unique_ports
        host_sweep_triggered = unique_hosts >= CONFIG.recon.min_unique_hosts

        if not (port_scan_triggered or host_sweep_triggered):
            return None

        port_factor = min(1.0, unique_ports / (CONFIG.recon.min_unique_ports * 2))
        host_factor = min(1.0, unique_hosts / (CONFIG.recon.min_unique_hosts * 2))
        rate_factor = min(1.0, scan_rate / (CONFIG.recon.min_scan_rate_pps * 2))

        confidence = round(0.40 * port_factor + 0.40 * host_factor + 0.20 * rate_factor, 4)

        if confidence < CONFIG.recon.min_confidence:
            return None

        severity = "HIGH" if (unique_hosts >= 20 or unique_ports >= 20) else "MEDIUM"

        evidence = [
            EvidenceItem(
                feature="unique_destination_port_count",
                value=unique_ports,
                interpretation=f"Source probed {unique_ports} unique destination ports"
            ),
            EvidenceItem(
                feature="unique_destination_count",
                value=unique_hosts,
                interpretation=f"Source probed {unique_hosts} unique host endpoints"
            ),
            EvidenceItem(
                feature="scan_rate",
                value=round(scan_rate, 2),
                interpretation=f"Connection probe frequency of {round(scan_rate, 1)} attempts/sec"
            )
        ]

        return DetectionResult(
            flow_id=flow.flow_id,
            threat_class="RECONNAISSANCE",
            severity=severity,
            confidence=confidence,
            source=f"{flow.src_ip}:{flow.src_port}",
            destination=f"{flow.dst_ip}:{flow.dst_port}",
            protocol=flow.protocol,
            evidence=evidence,
            detector=self.name,
            status="NEW"
        )
