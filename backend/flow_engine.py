"""
UniGuard One-Way Flow Engine
Parses raw PCAPs / packet lists into unidirectional flow records (A -> B).
Does NOT require reverse traffic or TCP SYN/ACK handshake completion.
"""

from typing import List, Dict, Tuple, Optional
import hashlib
from datetime import datetime, timezone
import scapy.all as scapy
from .schemas import FlowRecord


class FlowEngine:
    """
    Extracts unidirectional flows from PCAPs or raw Scapy packet lists.
    """

    @staticmethod
    def _generate_one_way_flow_id(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> str:
        raw_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{protocol}"
        return f"FL-{hashlib.md5(raw_key.encode()).hexdigest()[:10]}"

    @classmethod
    def process_packets(cls, packets: List[scapy.Packet]) -> List[FlowRecord]:
        """
        Processes a list of Scapy packets into one-way flows.
        """
        flows_map: Dict[Tuple[str, str, int, int, str], Dict] = {}

        for pkt in packets:
            if not pkt.haslayer(scapy.IP):
                continue

            ip_layer = pkt.getlayer(scapy.IP)
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            pkt_time = float(pkt.time)
            pkt_size = len(pkt)

            src_port = 0
            dst_port = 0
            protocol = "IP"
            dns_query = None

            if pkt.haslayer(scapy.TCP):
                tcp_layer = pkt.getlayer(scapy.TCP)
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                protocol = "TCP"
            elif pkt.haslayer(scapy.UDP):
                udp_layer = pkt.getlayer(scapy.UDP)
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                protocol = "UDP"

                if pkt.haslayer(scapy.DNS):
                    dns_layer = pkt.getlayer(scapy.DNS)
                    if dns_layer.qd and hasattr(dns_layer.qd, 'qname'):
                        try:
                            dns_query = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                            protocol = "DNS"
                        except Exception:
                            pass
            elif pkt.haslayer(scapy.ICMP):
                protocol = "ICMP"

            # Key is strictly ONE-WAY (src_ip -> dst_ip)
            flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)

            if flow_key not in flows_map:
                flows_map[flow_key] = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "first_seen": pkt_time,
                    "last_seen": pkt_time,
                    "packet_sizes": [pkt_size],
                    "timestamps": [pkt_time],
                    "dns_query": dns_query,
                }
            else:
                f = flows_map[flow_key]
                f["last_seen"] = pkt_time
                f["packet_sizes"].append(pkt_size)
                f["timestamps"].append(pkt_time)
                if dns_query and not f["dns_query"]:
                    f["dns_query"] = dns_query

        # Convert flow map to FlowRecord list
        flow_records: List[FlowRecord] = []
        for key, f in flows_map.items():
            timestamps = f["timestamps"]
            inter_arrivals: List[float] = []
            for i in range(1, len(timestamps)):
                diff = timestamps[i] - timestamps[i - 1]
                inter_arrivals.append(max(0.0, diff))

            duration = max(0.001, f["last_seen"] - f["first_seen"])
            flow_id = cls._generate_one_way_flow_id(f["src_ip"], f["dst_ip"], f["src_port"], f["dst_port"], f["protocol"])
            ts_str = datetime.fromtimestamp(f["first_seen"], tz=timezone.utc).isoformat()

            record = FlowRecord(
                flow_id=flow_id,
                timestamp=ts_str,
                src_ip=f["src_ip"],
                dst_ip=f["dst_ip"],
                src_port=f["src_port"],
                dst_port=f["dst_port"],
                protocol=f["protocol"],
                packet_count=len(f["packet_sizes"]),
                byte_count=sum(f["packet_sizes"]),
                duration=round(duration, 4),
                packet_sizes=f["packet_sizes"],
                inter_arrival_times=inter_arrivals,
                dns_query=f["dns_query"],
            )
            flow_records.append(record)

        return flow_records

    @classmethod
    def process_pcap_bytes(cls, pcap_data: bytes) -> List[FlowRecord]:
        """
        Reads raw binary PCAP bytes and extracts one-way flows.
        """
        from io import BytesIO
        packets = scapy.pcapio.RawPcapReader(BytesIO(pcap_data))
        # Alternative: use BytesIO with rdpcap
        try:
            tmp_packets = scapy.rdpcap(BytesIO(pcap_data))
            return cls.process_packets(tmp_packets)
        except Exception:
            # Fallback if rdpcap encounters minor header padding issues
            return []
