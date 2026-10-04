"""
UniGuard Deterministic Feature Engine
Extracts 16 temporal, statistical, behavioral, and diversity features from directional flow records.
Strictly defensive: calculates deterministic network behavioral measurements without making threat decisions.
"""

from typing import List, Dict, Any, Optional, Sequence
import math
from collections import Counter
from backend.app.schemas.traffic import DirectionalFlowRecord, FeatureVector

EPSILON = 1e-6  # Minimum positive divisor for rate calculations (1 microsecond)


class FeatureEngine:
    """
    Computes a deterministic 16-feature vector from a DirectionalFlowRecord.
    Handles mathematical edge cases (zero packets, zero duration, single packet, extreme values) safely.
    """

    PROTOCOL_MAP: Dict[str, float] = {
        "TCP": 1.0,
        "UDP": 2.0,
        "ICMP": 3.0,
        "DNS": 4.0,
        "HTTP": 5.0,
        "HTTPS": 6.0,
    }

    @staticmethod
    def calculate_shannon_entropy(elements: Sequence[Any]) -> float:
        """
        Calculates Shannon entropy: H(X) = -sum(p(x) * log2(p(x))).
        Returns 0.0 for empty or single-element inputs.
        """
        if not elements or len(elements) <= 1:
            return 0.0

        counts = Counter(elements)
        total = float(len(elements))
        if total <= 0.0:
            return 0.0

        entropy = 0.0
        for count in counts.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)

        return round(max(0.0, float(entropy)), 6)

    @classmethod
    def calculate_burst_score(cls, inter_arrival_times: Sequence[float]) -> float:
        """
        Computes a deterministic temporal burst score in [0.0, 1.0].
        Based on the coefficient of variation (CV = std / mean) of inter-packet arrival times.
        Formula: CV / (CV + 1.0).
        - 0.0: Perfectly periodic traffic (std = 0) or insufficient packets (<2).
        - 0.5: Poisson arrival pattern (CV = 1.0).
        - -> 1.0: Highly bursty traffic with large variance.
        If mean inter-arrival is 0.0 with multiple packets (all simultaneous), returns 1.0.
        """
        if not inter_arrival_times or len(inter_arrival_times) < 1:
            return 0.0

        valid_iats = [max(0.0, float(t)) for t in inter_arrival_times]
        n = len(valid_iats)
        mean_iat = sum(valid_iats) / float(n)

        if mean_iat == 0.0:
            # Multiple packets observed with 0 inter-arrival indicates maximal simultaneous burst
            return 1.0

        variance = sum((x - mean_iat) ** 2 for x in valid_iats) / float(n)
        std_iat = math.sqrt(variance)

        cv = std_iat / mean_iat
        burst_score = cv / (cv + 1.0)
        return round(max(0.0, min(1.0, float(burst_score))), 6)

    @classmethod
    def extract_features(
        cls,
        flow: DirectionalFlowRecord,
        context_flows: Optional[List[DirectionalFlowRecord]] = None,
    ) -> FeatureVector:
        """
        Extracts the canonical 16-feature vector from a single directional flow.
        Optional context_flows allows multi-flow window-level behavioral aggregation.
        """
        # 1. Flow Duration
        flow_duration = max(0.0, float(flow.duration))

        # 2. Packet Count
        packet_count = max(0, int(flow.packet_count))

        # 3. Byte Count
        byte_count = max(0, int(flow.byte_count))

        # 4. Packets Per Second
        safe_duration = max(flow_duration, EPSILON)
        if packet_count == 0:
            packets_per_second = 0.0
        else:
            packets_per_second = float(packet_count) / safe_duration

        # 5. Bytes Per Second
        if byte_count == 0:
            bytes_per_second = 0.0
        else:
            bytes_per_second = float(byte_count) / safe_duration

        # 6. Average Packet Size
        # 7. Packet Size Standard Deviation
        sizes = [max(0, int(s)) for s in (flow.packet_sizes or [])]
        if sizes and len(sizes) > 0:
            avg_packet_size = float(sum(sizes)) / float(len(sizes))
            if len(sizes) > 1:
                variance = sum((s - avg_packet_size) ** 2 for s in sizes) / float(len(sizes))
                packet_size_std = math.sqrt(variance)
            else:
                packet_size_std = 0.0
        elif packet_count > 0 and byte_count > 0:
            avg_packet_size = float(byte_count) / float(packet_count)
            packet_size_std = 0.0
        else:
            avg_packet_size = 0.0
            packet_size_std = 0.0

        # Context-based behavioral window aggregation
        same_src_flows: List[DirectionalFlowRecord] = []
        if context_flows:
            same_src_flows = [f for f in context_flows if f.source_ip == flow.source_ip]

        if same_src_flows:
            unique_dsts = set(f.destination_ip for f in same_src_flows)
            unique_dst_ports = set(f.destination_port for f in same_src_flows)
            unique_dst_count = len(unique_dsts)
            unique_dst_port_count = len(unique_dst_ports)
            dst_port_entropy = cls.calculate_shannon_entropy([f.destination_port for f in same_src_flows])

            total_src_flows = float(len(same_src_flows))
            destination_diversity = unique_dst_count / total_src_flows
            port_diversity = unique_dst_port_count / total_src_flows

            context_duration = max(1.0, sum(f.duration for f in same_src_flows))
            source_activity_rate = total_src_flows / context_duration
        else:
            # Standalone flow fallback defaults
            unique_dst_count = 1 if flow.destination_ip else 0
            unique_dst_port_count = 1 if flow.destination_port > 0 else 0
            dst_port_entropy = 0.0
            destination_diversity = 1.0 if unique_dst_count > 0 else 0.0
            port_diversity = 1.0 if unique_dst_port_count > 0 else 0.0
            source_activity_rate = 1.0 / max(flow_duration, 1.0)

        # 11. Packet Size Shannon Entropy
        packet_size_entropy = cls.calculate_shannon_entropy(sizes) if sizes else 0.0

        # 12. Burst Score
        iats = flow.inter_arrival_times
        if not iats and len(flow.packet_timestamps) > 1:
            # Reconstruct iats if timestamps were supplied
            pts = sorted(flow.packet_timestamps)
            iats = [pts[i] - pts[i - 1] for i in range(1, len(pts))]
        burst_score = cls.calculate_burst_score(iats)

        # 16. Protocol Indicator
        proto_key = flow.protocol.upper().strip()
        protocol_indicator = cls.PROTOCOL_MAP.get(proto_key, 0.0)

        return FeatureVector(
            flow_duration=round(flow_duration, 6),
            packet_count=packet_count,
            byte_count=byte_count,
            packets_per_second=round(packets_per_second, 4),
            bytes_per_second=round(bytes_per_second, 4),
            average_packet_size=round(avg_packet_size, 4),
            packet_size_std=round(packet_size_std, 4),
            unique_destination_count=unique_dst_count,
            unique_destination_port_count=unique_dst_port_count,
            destination_port_entropy=round(dst_port_entropy, 6),
            packet_size_entropy=round(packet_size_entropy, 6),
            burst_score=round(burst_score, 6),
            source_activity_rate=round(source_activity_rate, 4),
            destination_diversity=round(destination_diversity, 6),
            port_diversity=round(port_diversity, 6),
            protocol_indicator=protocol_indicator,
        )
