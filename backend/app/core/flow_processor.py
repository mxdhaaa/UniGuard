"""
UniGuard Directional Flow Processor
Aggregates packet metadata and authorized network telemetry into unidirectional flows (A -> B).
Does NOT require reverse-direction (B -> A) traffic or TCP connection establishment.
"""

from typing import List, Dict, Tuple, Optional, Any
import hashlib
from datetime import datetime, timezone
from backend.app.schemas.traffic import DirectionalFlowRecord


class DirectionalFlowProcessor:
    """
    Constructs and aggregates one-way (unidirectional) flow records.
    Key invariant: A -> B flow state is maintained entirely independently of B -> A.
    """

    @staticmethod
    def generate_flow_id(
        source_ip: str,
        source_port: int,
        destination_ip: str,
        destination_port: int,
        protocol: str,
    ) -> str:
        """
        Generates a deterministic flow identifier based strictly on directional 5-tuple.
        """
        raw_key = f"{source_ip}:{source_port}->{destination_ip}:{destination_port}:{protocol.upper()}"
        digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:12]
        return f"FL-DIR-{digest.upper()}"

    @classmethod
    def create_flow(
        cls,
        source_ip: str,
        destination_ip: str,
        source_port: int = 0,
        destination_port: int = 0,
        protocol: str = "TCP",
        timestamp: Optional[str] = None,
        duration: Optional[float] = None,
        packet_count: Optional[int] = None,
        byte_count: Optional[int] = None,
        packet_sizes: Optional[List[int]] = None,
        packet_timestamps: Optional[List[float]] = None,
        dns_query: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> DirectionalFlowRecord:
        """
        Constructs a validated DirectionalFlowRecord handling missing, zero, or partial inputs safely.
        """
        sizes = [max(0, int(s)) for s in (packet_sizes or [])]
        timestamps = sorted([float(t) for t in (packet_timestamps or [])])

        # Inter-arrival times derivation
        inter_arrivals: List[float] = []
        if len(timestamps) > 1:
            for i in range(1, len(timestamps)):
                diff = timestamps[i] - timestamps[i - 1]
                inter_arrivals.append(max(0.0, diff))

        # Calculate duration
        computed_duration: float = 0.0
        if duration is not None:
            computed_duration = max(0.0, float(duration))
        elif len(timestamps) > 1:
            computed_duration = max(0.0, timestamps[-1] - timestamps[0])
        elif len(inter_arrivals) > 0:
            computed_duration = max(0.0, sum(inter_arrivals))

        # Calculate packet and byte counts
        computed_packets = packet_count if packet_count is not None else len(sizes)
        computed_packets = max(0, computed_packets)

        computed_bytes = byte_count if byte_count is not None else sum(sizes)
        computed_bytes = max(0, computed_bytes)

        # Formulate timestamp
        if not timestamp:
            if timestamps:
                ts_str = datetime.fromtimestamp(timestamps[0], tz=timezone.utc).isoformat()
            else:
                ts_str = datetime.now(timezone.utc).isoformat()
        else:
            ts_str = timestamp

        flow_id = cls.generate_flow_id(source_ip, source_port, destination_ip, destination_port, protocol)

        return DirectionalFlowRecord(
            flow_id=flow_id,
            timestamp=ts_str,
            source_ip=source_ip,
            source_port=max(0, min(65535, int(source_port))),
            destination_ip=destination_ip,
            destination_port=max(0, min(65535, int(destination_port))),
            protocol=protocol.upper(),
            duration=round(computed_duration, 6),
            packet_count=computed_packets,
            byte_count=computed_bytes,
            packet_sizes=sizes,
            packet_timestamps=timestamps,
            inter_arrival_times=inter_arrivals,
            dns_query=dns_query,
            metadata=metadata or {},
        )

    @classmethod
    def aggregate_packet_events(cls, packet_events: List[Dict[str, Any]]) -> List[DirectionalFlowRecord]:
        """
        Aggregates raw unidirectional packet events into grouped DirectionalFlowRecord objects.
        Groups strictly by directional key (source_ip, destination_ip, source_port, destination_port, protocol).
        """
        flows_map: Dict[Tuple[str, str, int, int, str], Dict[str, Any]] = {}

        for pkt in packet_events:
            src_ip = str(pkt.get("source_ip", "0.0.0.0"))
            dst_ip = str(pkt.get("destination_ip", "0.0.0.0"))
            src_port = int(pkt.get("source_port", 0))
            dst_port = int(pkt.get("destination_port", 0))
            proto = str(pkt.get("protocol", "IP")).upper()
            size = max(0, int(pkt.get("size", pkt.get("bytes", 0))))
            ts = float(pkt.get("timestamp", pkt.get("time", 0.0)))
            dns_q = pkt.get("dns_query")

            key = (src_ip, dst_ip, src_port, dst_port, proto)

            if key not in flows_map:
                flows_map[key] = {
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "source_port": src_port,
                    "destination_port": dst_port,
                    "protocol": proto,
                    "packet_sizes": [size],
                    "packet_timestamps": [ts],
                    "dns_query": dns_q,
                }
            else:
                entry = flows_map[key]
                entry["packet_sizes"].append(size)
                entry["packet_timestamps"].append(ts)
                if dns_q and not entry["dns_query"]:
                    entry["dns_query"] = dns_q

        records: List[DirectionalFlowRecord] = []
        for entry in flows_map.values():
            rec = cls.create_flow(
                source_ip=entry["source_ip"],
                destination_ip=entry["destination_ip"],
                source_port=entry["source_port"],
                destination_port=entry["destination_port"],
                protocol=entry["protocol"],
                packet_sizes=entry["packet_sizes"],
                packet_timestamps=entry["packet_timestamps"],
                dns_query=entry["dns_query"],
            )
            records.append(rec)

        return records
