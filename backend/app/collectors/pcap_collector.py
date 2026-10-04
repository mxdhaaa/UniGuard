"""
UniGuard PCAP Collector (Milestone 11)

Reads PCAP/PCAPNG files offline using Scapy. Aggregates packets into 
directional 5-tuple flows using the shared ActiveFlowState from M10.
Flow expiration is driven explicitly by packet capture timestamps.
"""

import logging
from typing import Dict, Callable, Optional, Tuple
import scapy.all as scapy

from backend.app.schemas.traffic import DirectionalFlowRecord
from backend.app.collectors.live_collector import ActiveFlowState

logger = logging.getLogger(__name__)

class PcapCollector:
    """
    Offline packet reader and flow aggregator.
    Executes synchronously within a background job thread.
    """
    def __init__(
        self,
        pcap_path: str,
        idle_timeout: float = 30.0,
        max_duration: float = 120.0,
        on_flow_expired: Optional[Callable[[DirectionalFlowRecord], None]] = None
    ):
        self.pcap_path = pcap_path
        self.idle_timeout = idle_timeout
        self.max_duration = max_duration
        self.on_flow_expired = on_flow_expired
        
        self.active_flows: Dict[str, ActiveFlowState] = {}
        
        # Track simulated time based on the PCAP packets
        self.current_pcap_time = 0.0
        
        # Metrics
        self.total_packets = 0
        self.flows_completed = 0
        self.errors = 0

    def process(self) -> Tuple[int, int, int]:
        """
        Reads the PCAP file, aggregates flows, and pushes them through callbacks.
        Returns: (total_packets, flows_completed, errors)
        """
        try:
            with scapy.PcapReader(self.pcap_path) as pcap_reader:
                for pkt in pcap_reader:
                    self._process_packet(pkt)
                    
            # End of file reached, force flush all remaining flows
            self._flush_all()
            
        except Exception as e:
            logger.error(f"Error reading PCAP file {self.pcap_path}: {e}")
            self.errors += 1
            # We still want to flush whatever we did successfully gather before failing
            self._flush_all()
            raise e
            
        return self.total_packets, self.flows_completed, self.errors

    def _process_packet(self, pkt):
        """Extract directional 5-tuple and advance simulated PCAP time."""
        try:
            if not pkt.haslayer(scapy.IP):
                return
                
            src_ip = pkt[scapy.IP].src
            dst_ip = pkt[scapy.IP].dst
            
            src_port = 0
            dst_port = 0
            protocol = "UNKNOWN"
            
            if pkt.haslayer(scapy.TCP):
                protocol = "TCP"
                src_port = pkt[scapy.TCP].sport
                dst_port = pkt[scapy.TCP].dport
            elif pkt.haslayer(scapy.UDP):
                protocol = "UDP"
                src_port = pkt[scapy.UDP].sport
                dst_port = pkt[scapy.UDP].dport
            elif pkt.haslayer(scapy.ICMP):
                protocol = "ICMP"
            else:
                return # Unsupported protocol
                
            flow_key = f"{protocol}:{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            pkt_time = float(pkt.time)
            pkt_size = len(pkt)
            
            # Out-of-order packets: safely max the current time
            self.current_pcap_time = max(self.current_pcap_time, pkt_time)
            self.total_packets += 1
            
            # Check expirations BEFORE adding the packet to the flow state.
            # This ensures that if this packet arrives after an idle timeout,
            # the old flow is flushed first, and this packet starts a new flow.
            self._check_expirations()
            
            if flow_key not in self.active_flows:
                self.active_flows[flow_key] = ActiveFlowState(
                    src_ip, src_port, dst_ip, dst_port, protocol, prefix="pcap-"
                )
            
            self.active_flows[flow_key].add_packet(pkt_size, pkt_time)
            
        except Exception as e:
            self.errors += 1
            # Do not crash the entire import on a malformed packet

    def _check_expirations(self):
        """Evaluate idle timeouts and max durations against current_pcap_time."""
        expired_keys = []
        for key, state in self.active_flows.items():
            idle_time = self.current_pcap_time - state.last_seen
            duration = self.current_pcap_time - state.first_seen
            
            if idle_time >= self.idle_timeout or duration >= self.max_duration:
                expired_keys.append(key)
                
        for key in expired_keys:
            self._expire_flow(key)

    def _flush_all(self):
        """Force expiration of all currently active flows (e.g. at EOF)."""
        flow_keys = list(self.active_flows.keys())
        for key in flow_keys:
            self._expire_flow(key)

    def _expire_flow(self, key: str):
        state = self.active_flows.pop(key, None)
        if not state:
            return
            
        record = state.to_record()
        self.flows_completed += 1
        
        if self.on_flow_expired:
            try:
                self.on_flow_expired(record)
            except Exception as e:
                self.errors += 1
                logger.error(f"Error processing PCAP flow {record.flow_id}: {e}")
