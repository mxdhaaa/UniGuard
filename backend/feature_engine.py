"""
UniGuard Feature Engine
Extracts temporal, statistical, behavioral, and DNS features from one-way flow records.
"""

from typing import Dict, Any, List, Optional
import math
import numpy as np
from .schemas import FlowRecord


class FeatureEngine:
    """
    Computes reusable feature vectors from one-way flow records.
    """

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """Calculates Shannon entropy of string (bits/char)."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        entropy = -sum(p * math.log2(p) for p in prob)
        return round(entropy, 4)

    @classmethod
    def extract_flow_features(cls, flow: FlowRecord, context_flows: Optional[List[FlowRecord]] = None) -> Dict[str, Any]:
        """
        Extracts temporal, statistical, behavioral, and DNS features for a single flow.
        """
        features: Dict[str, Any] = {}

        # 1. Temporal Features
        duration = max(0.001, flow.duration)
        features["duration"] = round(duration, 4)
        features["packets_per_second"] = round(flow.packet_count / duration, 2)
        features["bytes_per_second"] = round(flow.byte_count / duration, 2)

        iat = flow.inter_arrival_times
        if iat and len(iat) > 0:
            mean_iat = float(np.mean(iat))
            std_iat = float(np.std(iat))
            cv_iat = float(std_iat / mean_iat) if mean_iat > 0 else 0.0
            features["mean_inter_arrival"] = round(mean_iat, 4)
            features["std_inter_arrival"] = round(std_iat, 4)
            features["inter_arrival_coefficient_of_variation"] = round(cv_iat, 4)
        else:
            features["mean_inter_arrival"] = None
            features["std_inter_arrival"] = None
            features["inter_arrival_coefficient_of_variation"] = None

        # 2. Statistical Features (Packet Sizes)
        sizes = flow.packet_sizes
        if sizes and len(sizes) > 0:
            features["mean_packet_size"] = round(float(np.mean(sizes)), 2)
            features["packet_size_std"] = round(float(np.std(sizes)), 2)
            features["min_packet_size"] = int(np.min(sizes))
            features["max_packet_size"] = int(np.max(sizes))
            features["packet_size_entropy"] = cls.calculate_shannon_entropy("".join(str(s) for s in sizes))
        else:
            features["mean_packet_size"] = None
            features["packet_size_std"] = None
            features["min_packet_size"] = None
            features["max_packet_size"] = None
            features["packet_size_entropy"] = None

        # 3. Behavioral Features (aggregated across context flows from same src_ip if available)
        if context_flows:
            same_src_flows = [f for f in context_flows if f.src_ip == flow.src_ip]
            unique_dsts = set(f.dst_ip for f in same_src_flows)
            unique_dst_ports = set(f.dst_port for f in same_src_flows)
            
            features["unique_destination_count"] = len(unique_dsts)
            features["unique_destination_port_count"] = len(unique_dst_ports)
            
            # Destination concentration: max flows to single dst / total flows from src
            dst_counts = [sum(1 for f in same_src_flows if f.dst_ip == d) for d in unique_dsts]
            max_dst = max(dst_counts) if dst_counts else 1
            features["destination_concentration"] = round(max_dst / len(same_src_flows), 4)
            features["connection_frequency"] = round(len(same_src_flows) / max(1.0, duration), 2)
        else:
            features["unique_destination_count"] = 1
            features["unique_destination_port_count"] = 1
            features["destination_concentration"] = 1.0
            features["connection_frequency"] = round(1.0 / max(1.0, duration), 2)

        # 4. DNS Features
        if flow.dns_query:
            query = flow.dns_query
            digits = sum(c.isdigit() for c in query)
            features["query_length"] = len(query)
            features["domain_entropy"] = cls.calculate_shannon_entropy(query)
            features["digit_ratio"] = round(digits / max(1, len(query)), 4)
            
            labels = query.split('.')
            features["label_length"] = max(len(l) for l in labels) if labels else len(query)
            features["query_frequency"] = features["packets_per_second"]
        else:
            features["query_length"] = None
            features["domain_entropy"] = None
            features["digit_ratio"] = None
            features["label_length"] = None
            features["query_frequency"] = None

        return features
