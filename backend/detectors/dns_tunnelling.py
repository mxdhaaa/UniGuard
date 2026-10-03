"""
DNS Tunnelling / DGA Detector
Detects encoded binary payload tunnelling and algorithmically generated domain (DGA) queries.
"""

from typing import Optional, List, Dict, Any
from .base import BaseDetector
from ..schemas import FlowRecord, DetectionResult, EvidenceItem
from ..config import CONFIG


class DNSTunnellingDetector(BaseDetector):
    @property
    def name(self) -> str:
        return "DNSTunnellingDetector"

    def analyze(self, flow: FlowRecord, features: Dict[str, Any], context_flows: Optional[List[FlowRecord]] = None) -> Optional[DetectionResult]:
        domain_entropy = features.get("domain_entropy")
        query_length = features.get("query_length")
        digit_ratio = features.get("digit_ratio")
        label_length = features.get("label_length")

        # Non-DNS or missing DNS features -> skip
        if domain_entropy is None or query_length is None:
            return None

        # Check thresholds
        entropy_trigger = domain_entropy >= CONFIG.dns.min_shannon_entropy
        length_trigger = query_length >= CONFIG.dns.min_query_length
        digit_trigger = (digit_ratio or 0.0) >= CONFIG.dns.min_digit_ratio

        if not (entropy_trigger or length_trigger):
            return None

        # Calculate score
        entropy_score = min(1.0, domain_entropy / 5.5)
        length_score = min(1.0, query_length / 100)
        digit_score = min(1.0, (digit_ratio or 0.0) / 0.5)

        confidence = round(0.50 * entropy_score + 0.35 * length_score + 0.15 * digit_score, 4)

        if confidence < CONFIG.dns.min_confidence:
            return None

        severity = "HIGH" if confidence >= 0.80 else "MEDIUM"

        evidence = [
            EvidenceItem(
                feature="domain_shannon_entropy",
                value=round(domain_entropy, 4),
                interpretation=f"High Shannon entropy ({round(domain_entropy, 2)} bits/char) indicates encoded payload or DGA"
            ),
            EvidenceItem(
                feature="query_length",
                value=query_length,
                interpretation=f"Subdomain label length of {query_length} characters exceeds baseline"
            ),
            EvidenceItem(
                feature="digit_ratio",
                value=round(digit_ratio or 0.0, 4),
                interpretation=f"Digit composition ratio of {round((digit_ratio or 0.0) * 100, 1)}%"
            )
        ]

        if flow.dns_query:
            evidence.append(
                EvidenceItem(
                    feature="dns_query_string",
                    value=flow.dns_query[:60] + "..." if len(flow.dns_query) > 60 else flow.dns_query,
                    interpretation="Observed DNS query label"
                )
            )

        return DetectionResult(
            flow_id=flow.flow_id,
            threat_class="DNS_TUNNELLING_DGA",
            severity=severity,
            confidence=confidence,
            source=f"{flow.src_ip}:{flow.src_port}",
            destination=f"{flow.dst_ip}:{flow.dst_port}",
            protocol=flow.protocol,
            evidence=evidence,
            detector=self.name,
            status="NEW"
        )
