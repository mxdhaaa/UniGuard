"""
UniGuard Live Traffic Collector (Milestone 10)

Captures packets on a background thread using Scapy, aggregates them into
directional 5-tuple flows, and manages flow expiration (idle/max timeouts).
Does not store raw packet payloads.
"""

import threading
import time
import uuid
import logging
from typing import Dict, Callable, Optional, List
from datetime import datetime, timezone
import scapy.all as scapy

from backend.app.schemas.traffic import DirectionalFlowRecord

logger = logging.getLogger(__name__)

class ActiveFlowState:
    """Internal tracker for a single directional flow."""
    def __init__(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str, prefix: str = "live-"):
        self.flow_id = f"{prefix}{uuid.uuid4().hex[:12]}"
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        
        self.packet_count = 0
        self.byte_count = 0
        self.packet_sizes: List[int] = []
        self.packet_timestamps: List[float] = []
        
        self.first_seen = 0.0
        self.last_seen = 0.0
        self.initial_timestamp_str = ""

    def add_packet(self, pkt_size: int, pkt_time: float):
        if self.packet_count == 0:
            self.first_seen = pkt_time
            # Convert Scapy time (Unix epoch) to ISO 8601 UTC string
            dt = datetime.fromtimestamp(pkt_time, timezone.utc)
            self.initial_timestamp_str = dt.isoformat()
            
        self.packet_count += 1
        self.byte_count += pkt_size
        self.packet_sizes.append(pkt_size)
        
        # Scapy packet times are absolute, we want relative to first_seen
        relative_time = pkt_time - self.first_seen
        self.packet_timestamps.append(relative_time)
        self.last_seen = pkt_time

    def to_record(self) -> DirectionalFlowRecord:
        inter_arrival_times = []
        for i in range(1, len(self.packet_timestamps)):
            inter_arrival_times.append(self.packet_timestamps[i] - self.packet_timestamps[i-1])
            
        duration = self.last_seen - self.first_seen
        
        return DirectionalFlowRecord(
            flow_id=self.flow_id,
            timestamp=self.initial_timestamp_str,
            source_ip=self.src_ip,
            source_port=self.src_port,
            destination_ip=self.dst_ip,
            destination_port=self.dst_port,
            protocol=self.protocol,
            duration=float(duration),
            packet_count=self.packet_count,
            byte_count=self.byte_count,
            packet_sizes=self.packet_sizes,
            packet_timestamps=self.packet_timestamps,
            inter_arrival_times=inter_arrival_times
        )


class LiveTrafficCollector:
    """
    Background packet sniffer and flow aggregator.
    Executes entirely off the FastAPI main thread.
    """
    def __init__(
        self,
        interface: str,
        bpf_filter: str,
        idle_timeout: float = 30.0,
        max_duration: float = 120.0,
        on_flow_expired: Optional[Callable[[DirectionalFlowRecord], None]] = None,
        _time_func: Callable[[], float] = time.time  # Injectable for testing
    ):
        self.interface = interface if interface else None
        self.bpf_filter = bpf_filter
        self.idle_timeout = idle_timeout
        self.max_duration = max_duration
        self.on_flow_expired = on_flow_expired
        self._time = _time_func
        
        self.active_flows: Dict[str, ActiveFlowState] = {}
        self.is_running = False
        self._lock = threading.Lock()
        
        self.packets_captured = 0
        self.flows_completed = 0
        self.errors = 0
        
        self._sniff_thread: Optional[threading.Thread] = None
        self._maintenance_thread: Optional[threading.Thread] = None

    def start(self):
        if self.is_running:
            return
            
        self.is_running = True
        
        # We start the sniffer thread
        self._sniff_thread = threading.Thread(target=self._run_sniffer, daemon=True)
        self._sniff_thread.start()
        
        # We start the maintenance thread to reap expired flows
        self._maintenance_thread = threading.Thread(target=self._maintenance_loop, daemon=True)
        self._maintenance_thread.start()

    def stop(self):
        self.is_running = False
        if self._sniff_thread:
            self._sniff_thread.join(timeout=2.0)
        if self._maintenance_thread:
            self._maintenance_thread.join(timeout=2.0)

    def flush(self):
        """Immediately expire and process all currently active flows."""
        with self._lock:
            flow_keys = list(self.active_flows.keys())
            for key in flow_keys:
                self._expire_flow(key)

    def _should_stop_sniffer(self, pkt) -> bool:
        return not self.is_running

    def _run_sniffer(self):
        try:
            # store=False ensures we don't leak memory by keeping raw packets
            scapy.sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._process_packet,
                store=False,
                stop_filter=self._should_stop_sniffer
            )
        except Exception as e:
            self.errors += 1
            logger.error(f"Scapy sniffing error: {e}")
            self.is_running = False

    def _process_packet(self, pkt):
        """Extract directional 5-tuple and update flow state safely."""
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
                
            # Directional key
            flow_key = f"{protocol}:{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            pkt_time = float(pkt.time)
            pkt_size = len(pkt)
            
            with self._lock:
                self.packets_captured += 1
                if flow_key not in self.active_flows:
                    self.active_flows[flow_key] = ActiveFlowState(src_ip, src_port, dst_ip, dst_port, protocol)
                
                self.active_flows[flow_key].add_packet(pkt_size, pkt_time)
                
        except Exception as e:
            self.errors += 1
            # Do not crash the sniffer on a malformed packet
            pass

    def _maintenance_loop(self):
        while self.is_running:
            time.sleep(1.0) # Check expirations roughly every second
            self._check_expirations()

    def _check_expirations(self):
        current_time = self._time()
        expired_keys = []
        
        with self._lock:
            for key, state in self.active_flows.items():
                idle_time = current_time - state.last_seen
                duration = current_time - state.first_seen
                
                if idle_time >= self.idle_timeout or duration >= self.max_duration:
                    expired_keys.append(key)
                    
            for key in expired_keys:
                self._expire_flow(key)

    def _expire_flow(self, key: str):
        """Called WITH _lock held."""
        state = self.active_flows.pop(key, None)
        if not state:
            return
            
        record = state.to_record()
        self.flows_completed += 1
        
        if self.on_flow_expired:
            try:
                # Dispatch safely so a failure in the pipeline doesn't break the collector
                self.on_flow_expired(record)
            except Exception as e:
                self.errors += 1
                logger.error(f"Error processing expired flow {record.flow_id}: {e}")
