"""
Synthetic One-Way Test Data Generator
Produces deterministic one-way flow scenarios for testing detectors.
"""

from typing import List
from .schemas import FlowRecord


class SyntheticTrafficGenerator:
    """
    Generates deterministic synthetic flow records for reproducible detector unit tests.
    """

    @staticmethod
    def generate_benign_flow(src_ip: str = "10.24.1.15", dst_ip: str = "142.250.190.46", src_port: int = 51200, dst_port: int = 443) -> FlowRecord:
        """Normal web browsing flow with random inter-arrival times."""
        # Variable inter-arrivals (CV > 0.60)
        iats = [0.12, 1.45, 0.05, 4.20, 0.35, 12.10, 0.02, 2.80, 0.15, 8.40]
        sizes = [64, 1420, 120, 850, 64, 1420, 1420, 64, 512, 1420]
        duration = sum(iats)

        return FlowRecord(
            flow_id="FL-BENIGN-001",
            timestamp="2026-10-03T23:00:00Z",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol="HTTPS",
            packet_count=len(sizes),
            byte_count=sum(sizes),
            duration=round(duration, 4),
            packet_sizes=sizes,
            inter_arrival_times=iats,
            dns_query=None,
        )

    @staticmethod
    def generate_c2_beaconing_flow(src_ip: str = "10.24.8.21", dst_ip: str = "185.220.101.5", src_port: int = 49812, dst_port: int = 443) -> FlowRecord:
        """Highly periodic outbound C2 beaconing flow (CV < 0.05)."""
        # Exactly 5.0s pulse interval with minor microsecond jitter
        iats = [5.001, 4.998, 5.002, 5.000, 4.999, 5.001, 5.000, 4.998, 5.002, 5.000]
        sizes = [512, 512, 512, 512, 512, 512, 512, 512, 512, 512, 512]
        duration = sum(iats)

        return FlowRecord(
            flow_id="FL-C2-BEACON-001",
            timestamp="2026-10-03T23:00:00Z",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol="TCP",
            packet_count=len(sizes),
            byte_count=sum(sizes),
            duration=round(duration, 4),
            packet_sizes=sizes,
            inter_arrival_times=iats,
            dns_query=None,
        )

    @staticmethod
    def generate_ddos_flow(src_ip: str = "10.24.4.109", dst_ip: str = "91.218.114.22", src_port: int = 54102, dst_port: int = 443) -> FlowRecord:
        """Volumetric UDP flood packet stream."""
        packet_count = 1200
        sizes = [1420] * packet_count
        iats = [0.001] * (packet_count - 1)  # High rate (1000 pps)
        duration = sum(iats)

        return FlowRecord(
            flow_id="FL-DDOS-FLOOD-001",
            timestamp="2026-10-03T23:00:00Z",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol="UDP",
            packet_count=packet_count,
            byte_count=sum(sizes),
            duration=round(duration, 4),
            packet_sizes=sizes,
            inter_arrival_times=iats,
            dns_query=None,
        )

    @staticmethod
    def generate_dns_tunnelling_flow(src_ip: str = "10.24.12.84", dst_ip: str = "10.24.0.2", src_port: int = 53120, dst_port: int = 53) -> FlowRecord:
        """High entropy base64 encoded DNS query flow."""
        query = "v9k84a72x910ma94kz21q9481z91m02a941z8.exfil-tunnel.auth-domain.org"
        iats = [0.25, 0.28, 0.24, 0.26, 0.25]
        sizes = [210] * 6
        duration = sum(iats)

        return FlowRecord(
            flow_id="FL-DNS-TUNNEL-001",
            timestamp="2026-10-03T23:00:00Z",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol="DNS",
            packet_count=6,
            byte_count=sum(sizes),
            duration=round(duration, 4),
            packet_sizes=sizes,
            inter_arrival_times=iats,
            dns_query=query,
        )

    @staticmethod
    def generate_port_scan_flows(src_ip: str = "10.24.8.44") -> List[FlowRecord]:
        """Probing 15 distinct ports on a target subnet."""
        flows: List[FlowRecord] = []
        for p in range(1, 16):
            port = 1000 + p * 20
            f = FlowRecord(
                flow_id=f"FL-SCAN-00{p}",
                timestamp="2026-10-03T23:00:00Z",
                src_ip=src_ip,
                dst_ip="10.24.10.15",
                src_port=49000 + p,
                dst_port=port,
                protocol="TCP",
                packet_count=1,
                byte_count=64,
                duration=0.1,
                packet_sizes=[64],
                inter_arrival_times=[],
                dns_query=None,
            )
            flows.append(f)
        return flows
