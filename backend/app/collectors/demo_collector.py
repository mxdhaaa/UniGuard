"""
UniGuard Safe Synthetic Demo Traffic Collector
Generates realistic unidirectional flow metadata across 6 simulated behavioral profiles.
Defensive cybersecurity demonstration only: uses private/documentation IP addresses and in-memory flow metadata.
"""

from typing import List, Dict, Optional, Any
import random
from datetime import datetime, timezone
from backend.app.schemas.traffic import DirectionalFlowRecord
from backend.app.core.flow_processor import DirectionalFlowProcessor

VALID_PROFILES = [
    "NORMAL",
    "SCANNING_LIKE",
    "DOS_LIKE",
    "BOTNET_LIKE",
    "EXFILTRATION_LIKE",
    "OTHER_SUSPICIOUS",
]

DEFAULT_PROFILE_MIX: Dict[str, float] = {
    "NORMAL": 0.50,
    "SCANNING_LIKE": 0.15,
    "DOS_LIKE": 0.15,
    "BOTNET_LIKE": 0.10,
    "EXFILTRATION_LIKE": 0.05,
    "OTHER_SUSPICIOUS": 0.05,
}

# Documentation & Private Subnets (RFC 1918 & RFC 5737 - no real external network targets)
INTERNAL_SOURCES = [
    "10.24.1.15",
    "10.24.1.22",
    "10.24.4.109",
    "10.24.8.21",
    "10.24.12.84",
    "192.168.10.45",
]

DOC_TARGETS = [
    "198.51.100.10",
    "198.51.100.25",
    "203.0.113.5",
    "203.0.113.88",
    "192.0.2.14",
    "192.0.2.77",
]

SCAN_TARGET_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 1521, 3306, 3389, 5432, 8080, 8443]


class DemoTrafficCollector:
    """
    Controllable PRNG synthetic flow generator producing unidirectional flow metadata.
    """

    def __init__(self, seed: Optional[int] = 42) -> None:
        self.seed = seed
        self._rng = random.Random(seed)
        self._flow_counter = 0

    def set_seed(self, seed: Optional[int]) -> None:
        """Sets the PRNG seed for deterministic output reproduction."""
        self.seed = seed
        self._rng = random.Random(seed)
        self._flow_counter = 0

    def _generate_flow_timestamp(self) -> str:
        """Generates an ISO UTC timestamp."""
        return datetime.now(timezone.utc).isoformat()

    def generate_normal_flow(self, source_ip: Optional[str] = None) -> DirectionalFlowRecord:
        """
        NORMAL: Moderate packet rates, standard packet sizes, moderate duration, typical protocols.
        """
        src = source_ip or self._rng.choice(INTERNAL_SOURCES)
        dst = self._rng.choice(DOC_TARGETS)
        sport = self._rng.randint(49152, 65535)
        dport = self._rng.choice([80, 443, 53, 8080])
        proto = "TCP" if dport != 53 else "UDP"

        packet_count = self._rng.randint(8, 30)
        # Mix of standard ACK/header packets (64) and payload MTU segments (256-1420)
        sizes = [self._rng.choice([64, 128, 256, 512, 1024, 1420]) for _ in range(packet_count)]

        # Realistic human-browsing / API inter-arrival times with moderate variance
        iats = [round(self._rng.uniform(0.05, 0.45), 4) for _ in range(packet_count - 1)]
        duration = round(sum(iats), 4) if iats else 0.1

        t0 = datetime.now(timezone.utc).timestamp() + self._flow_counter
        timestamps = [t0]
        curr = t0
        for gap in iats:
            curr += gap
            timestamps.append(curr)

        self._flow_counter += 1
        return DirectionalFlowProcessor.create_flow(
            source_ip=src,
            destination_ip=dst,
            source_port=sport,
            destination_port=dport,
            protocol=proto,
            duration=duration,
            packet_sizes=sizes,
            packet_timestamps=timestamps,
            metadata={"simulated_profile": "NORMAL"},
        )

    def generate_scanning_like_flow(self, source_ip: Optional[str] = None) -> DirectionalFlowRecord:
        """
        SCANNING_LIKE: Probing diverse ports/destinations, 1-2 packets per flow, very short duration.
        """
        src = source_ip or "10.24.8.44"  # Dedicated scan source for context diversity
        dst = self._rng.choice(DOC_TARGETS)
        sport = self._rng.randint(50000, 65000)
        dport = self._rng.choice(SCAN_TARGET_PORTS)
        proto = "TCP"

        packet_count = self._rng.choice([1, 2])
        sizes = [60] * packet_count  # Standard TCP SYN probe size
        iats = [0.01] if packet_count > 1 else []
        duration = 0.01 if packet_count > 1 else 0.001

        t0 = datetime.now(timezone.utc).timestamp() + self._flow_counter * 0.02
        timestamps = [t0] if packet_count == 1 else [t0, t0 + 0.01]

        self._flow_counter += 1
        return DirectionalFlowProcessor.create_flow(
            source_ip=src,
            destination_ip=dst,
            source_port=sport,
            destination_port=dport,
            protocol=proto,
            duration=duration,
            packet_sizes=sizes,
            packet_timestamps=timestamps,
            metadata={"simulated_profile": "SCANNING_LIKE"},
        )

    def generate_dos_like_flow(self, source_ip: Optional[str] = None) -> DirectionalFlowRecord:
        """
        DOS_LIKE: Volumetric packet stream, high packet rate (pps), rapid inter-arrival, bursty.
        """
        src = source_ip or "10.24.4.109"
        dst = "198.51.100.25"
        sport = self._rng.randint(49152, 65535)
        dport = self._rng.choice([80, 443, 53])
        proto = "UDP"

        packet_count = self._rng.randint(300, 800)
        sizes = [self._rng.choice([512, 1024, 1420])] * packet_count
        # Microsecond inter-arrival rate (~1000 - 5000 pps)
        base_iat = round(self._rng.uniform(0.0002, 0.0008), 6)
        iats = [base_iat] * (packet_count - 1)
        duration = round(sum(iats), 6)

        t0 = datetime.now(timezone.utc).timestamp() + self._flow_counter
        timestamps = [t0 + i * base_iat for i in range(packet_count)]

        self._flow_counter += 1
        return DirectionalFlowProcessor.create_flow(
            source_ip=src,
            destination_ip=dst,
            source_port=sport,
            destination_port=dport,
            protocol=proto,
            duration=duration,
            packet_sizes=sizes,
            packet_timestamps=timestamps,
            metadata={"simulated_profile": "DOS_LIKE"},
        )

    def generate_botnet_like_flow(self, source_ip: Optional[str] = None) -> DirectionalFlowRecord:
        """
        BOTNET_LIKE: Regular periodic outbound pulses (low jitter CV < 0.05), identical payload sizes.
        """
        src = source_ip or "10.24.8.21"
        dst = "203.0.113.88"  # Fixed remote controller
        sport = 49812
        dport = 443
        proto = "TCP"

        packet_count = self._rng.randint(8, 16)
        payload_size = 512
        sizes = [payload_size] * packet_count

        # Strictly periodic pulse (e.g. ~2.0s pulse with ±0.002s minor micro-jitter)
        base_period = 2.0
        iats = [round(base_period + self._rng.uniform(-0.003, 0.003), 4) for _ in range(packet_count - 1)]
        duration = round(sum(iats), 4)

        t0 = datetime.now(timezone.utc).timestamp() + self._flow_counter
        timestamps = [t0]
        curr = t0
        for gap in iats:
            curr += gap
            timestamps.append(curr)

        self._flow_counter += 1
        return DirectionalFlowProcessor.create_flow(
            source_ip=src,
            destination_ip=dst,
            source_port=sport,
            destination_port=dport,
            protocol=proto,
            duration=duration,
            packet_sizes=sizes,
            packet_timestamps=timestamps,
            metadata={"simulated_profile": "BOTNET_LIKE"},
        )

    def generate_exfiltration_like_flow(self, source_ip: Optional[str] = None) -> DirectionalFlowRecord:
        """
        EXFILTRATION_LIKE: Heavy outbound byte volume, large average packet size (>1200 B), sustained flow.
        """
        src = source_ip or "10.24.12.84"
        dst = "192.0.2.77"
        sport = self._rng.randint(49152, 65535)
        dport = 443
        proto = "TCP"

        packet_count = self._rng.randint(80, 200)
        # Predominantly maximum transmission unit (MTU 1420 bytes) data frames
        sizes = [self._rng.choice([1420, 1420, 1420, 1400, 1380]) for _ in range(packet_count)]
        iats = [round(self._rng.uniform(0.01, 0.05), 4) for _ in range(packet_count - 1)]
        duration = round(sum(iats), 4)

        t0 = datetime.now(timezone.utc).timestamp() + self._flow_counter
        timestamps = [t0]
        curr = t0
        for gap in iats:
            curr += gap
            timestamps.append(curr)

        self._flow_counter += 1
        return DirectionalFlowProcessor.create_flow(
            source_ip=src,
            destination_ip=dst,
            source_port=sport,
            destination_port=dport,
            protocol=proto,
            duration=duration,
            packet_sizes=sizes,
            packet_timestamps=timestamps,
            metadata={"simulated_profile": "EXFILTRATION_LIKE"},
        )

    def generate_other_suspicious_flow(self, source_ip: Optional[str] = None) -> DirectionalFlowRecord:
        """
        OTHER_SUSPICIOUS: Unusual combination of high-entropy payload sizes and erratic burst arrivals.
        """
        src = source_ip or self._rng.choice(INTERNAL_SOURCES)
        dst = self._rng.choice(DOC_TARGETS)
        sport = self._rng.randint(49152, 65535)
        dport = 5353
        proto = "UDP"

        packet_count = self._rng.randint(10, 25)
        # Diverse, highly irregular packet sizes
        sizes = [self._rng.randint(40, 1450) for _ in range(packet_count)]
        # Erratic inter-arrivals
        iats = [round(self._rng.expovariate(2.0), 4) for _ in range(packet_count - 1)]
        duration = round(sum(iats), 4)

        t0 = datetime.now(timezone.utc).timestamp() + self._flow_counter
        timestamps = [t0]
        curr = t0
        for gap in iats:
            curr += gap
            timestamps.append(curr)

        self._flow_counter += 1
        return DirectionalFlowProcessor.create_flow(
            source_ip=src,
            destination_ip=dst,
            source_port=sport,
            destination_port=dport,
            protocol=proto,
            duration=duration,
            packet_sizes=sizes,
            packet_timestamps=timestamps,
            metadata={"simulated_profile": "OTHER_SUSPICIOUS"},
        )

    def generate_flow_by_profile(self, profile: str, source_ip: Optional[str] = None) -> DirectionalFlowRecord:
        """Generates a directional flow record matching the given profile string."""
        profile_key = profile.upper().strip()
        if profile_key == "NORMAL":
            return self.generate_normal_flow(source_ip=source_ip)
        elif profile_key == "SCANNING_LIKE":
            return self.generate_scanning_like_flow(source_ip=source_ip)
        elif profile_key == "DOS_LIKE":
            return self.generate_dos_like_flow(source_ip=source_ip)
        elif profile_key == "BOTNET_LIKE":
            return self.generate_botnet_like_flow(source_ip=source_ip)
        elif profile_key == "EXFILTRATION_LIKE":
            return self.generate_exfiltration_like_flow(source_ip=source_ip)
        elif profile_key == "OTHER_SUSPICIOUS":
            return self.generate_other_suspicious_flow(source_ip=source_ip)
        else:
            raise ValueError(f"Unknown behavioral profile '{profile}'. Must be one of {VALID_PROFILES}")

    def generate_batch(
        self,
        count: int = 20,
        profile_mix: Optional[Dict[str, float]] = None,
    ) -> List[DirectionalFlowRecord]:
        """
        Generates a batch of synthetic DirectionalFlowRecord objects using the specified profile mix.
        """
        if count <= 0:
            raise ValueError(f"Count must be a positive integer, got {count}")

        mix = profile_mix or DEFAULT_PROFILE_MIX
        # Validate profile mix keys
        for key in mix.keys():
            if key not in VALID_PROFILES:
                raise ValueError(f"Invalid profile key '{key}' in profile_mix. Allowed: {VALID_PROFILES}")

        # Validate weights sum to ~1.0
        total_weight = sum(mix.values())
        if total_weight <= 0.0 or abs(total_weight - 1.0) > 0.05:
            raise ValueError(f"Profile mix weights must sum to approximately 1.0, got {total_weight}")

        profiles = list(mix.keys())
        weights = [mix[p] for p in profiles]

        chosen_profiles = self._rng.choices(profiles, weights=weights, k=count)
        return [self.generate_flow_by_profile(p) for p in chosen_profiles]



