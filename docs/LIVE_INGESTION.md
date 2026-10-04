# UniGuard Live Flow Ingestion (Milestone 10)

## Overview
Milestone 10 introduces live network packet capture to UniGuard. The ingestion layer securely intercepts traffic on a local interface, aggregates packets into directional 5-tuple flows, and seamlessly feeds expired flows into the deterministic Machine Learning and Risk pipeline (Milestones 3–9).

## Architecture
The Live Ingestion layer is composed of three main parts:
1. **LiveTrafficCollector:** A background thread running Scapy's `sniff()` loop. It maintains a thread-safe state dictionary of active flows.
2. **IngestionService:** Orchestrates the lifecycle of the collector and provides the callback to execute the M3–M9 analysis pipeline when a flow expires.
3. **API Layer:** Exposes the `GET /api/ingestion/status`, `POST /api/ingestion/start`, and `POST /api/ingestion/stop` endpoints.

## Flow Identity
UniGuard strictly uses a **Directional 5-Tuple**:
`(Protocol, Source IP, Source Port, Destination IP, Destination Port)`

Forward and reverse traffic are treated as two independent directional flows. This design ensures that malicious asymmetric behaviors (e.g., unidirectional scanning or stealth exfiltration) are analyzed precisely.

## Expiration Rules
To prevent memory leaks and ensure timely analysis, flows are forcefully expired and pushed into the pipeline under two conditions:
1. **Idle Timeout:** No new packets received for `FLOW_IDLE_TIMEOUT` seconds (default: 30s).
2. **Max Duration:** The flow has existed for `FLOW_MAX_DURATION` seconds (default: 120s), regardless of activity.

## Configuration
Capture behavior is configurable via environment variables in `backend/app/config.py`:
- `CAPTURE_INTERFACE`: The specific network interface (e.g., `eth0` or `Wi-Fi`). If left empty, Scapy listens on all interfaces (where OS permissions allow).
- `CAPTURE_FILTER`: A standard BPF filter string. Default: `ip and (tcp or udp or icmp)`.
- `FLOW_IDLE_TIMEOUT`: Seconds before an idle flow is expired (default `30.0`).
- `FLOW_MAX_DURATION`: Maximum seconds a flow can remain active (default `120.0`).

> **Security Default:** Live capture is strictly **OFF** by default upon FastAPI startup to prevent unintended observation.

## Privacy & Security
- **No Payload Storage:** The collector completely ignores Layers 7+ (application payloads). Only Layer 3/4 headers are evaluated to determine IP/Ports, protocol, packet sizes, and arrival times.
- **No PCAP Exports:** Raw packets are never persisted to disk or the database.
- **Platform Permissions:** Depending on the OS (e.g., Linux or macOS), running a raw socket sniffer requires elevated privileges (`sudo` or `CAP_NET_RAW`). Windows generally requires Npcap/WinPcap. *Errors stemming from insufficient permissions will prevent the collector from starting but will not crash the FastAPI application.*

## Pipeline Integration
When a flow expires, the background thread executes the following sequence synchronously, generating a fresh, isolated database session:
`ActiveFlowState` → `DirectionalFlowRecord` → `FeatureEngine` → `ML Inference` → `RiskEngine` → `EvidenceEngine` → `PersistenceService`

A pipeline crash for a single flow is safely caught and logged, guaranteeing that the packet sniffer loop continues uninterrupted.
