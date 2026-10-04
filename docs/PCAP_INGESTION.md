# UniGuard PCAP File Ingestion (Milestone 11)

## Overview
Milestone 11 enables offline analysis of network traffic through `.pcap` and `.pcapng` file ingestion. Rather than observing live traffic, users can upload capture files for asynchronous background processing through the deterministic UniGuard analysis pipeline.

## API Usage
### 1. Upload PCAP
`POST /api/pcap/upload`
Accepts `multipart/form-data` with a `file` field. 
- Only `.pcap` and `.pcapng` extensions are supported.
- File size is restricted by `PCAP_MAX_FILE_SIZE_MB` (default 50 MB) to prevent resource exhaustion.
- Returns a `job_id` indicating the background processing has started.

### 2. Check Job Status
`GET /api/pcap/status/{job_id}`
Returns the current progress of the ingestion:
- `status`: `PROCESSING`, `COMPLETED`, or `FAILED`.
- `total_packets`: Packets read from the file so far.
- `flows_completed`: Flows successfully aggregated, expired, and analyzed.
- `errors`: Number of malformed packets or pipeline errors encountered.

## Flow Identity & Shared Aggregation
PCAP ingestion strictly shares the `ActiveFlowState` mechanism introduced in Milestone 10 (Live Ingestion). 
Flows are aggregated by Directional 5-Tuple:
`(Protocol, Source IP, Source Port, Destination IP, Destination Port)`
Forward and reverse traffic remain independent flows.

## Timestamp Expiration Semantics
Unlike live ingestion which evaluates expiration against wall-clock time, PCAP ingestion evaluates expiration strictly against **packet capture timestamps (`pkt.time`)**. 
As the collector iterates over packets, it advances its internal "simulated time" to match the timestamp of the newest packet observed. If an existing flow's `last_seen` timestamp falls further behind the simulated time than the configured `FLOW_IDLE_TIMEOUT` (default: 30s) or exceeds `FLOW_MAX_DURATION` (default: 120s), it is expired and analyzed immediately.

At the end of the file (EOF), a forced flush occurs to ensure every remaining active flow is processed.

## Analysis Pipeline Integration
Completed flows are passed to the identical pipeline used by M10:
`FeatureEngine` → `ML Inference` → `RiskEngine` → `EvidenceEngine` → `PersistenceService`

A fresh, isolated SQLite/PostgreSQL database session is created for each flow to ensure thread safety and transaction boundaries.

## Privacy & Security
- **No Payload Extraction:** PCAP payloads (Layers 7+) are completely ignored. Only Layer 3/4 metadata (IPs, ports, protocols, sizes, timestamps) are evaluated.
- **Auto-Cleanup:** The uploaded PCAP file is assigned an internal safe UUID-based filename and stored in a temporary upload directory (`PCAP_UPLOAD_DIR`). The file is strictly deleted upon completion or failure of the background processing job. It is never stored in the database.
- **No PCAP Export:** The API intentionally does not provide endpoints to download or retrieve uploaded PCAP contents.
