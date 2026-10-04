# UniGuard Safe Demo Traffic Pipeline Specification

> [!IMPORTANT]
> **Defensive Security Notice**:
> "Demo traffic is synthetic and is not evidence of real-world malicious activity."
> All generated telemetry uses private (RFC 1918) and documentation (RFC 5737) IP spaces. It does not perform active network scanning, packet injection, exploitation, or real network transmission.

---

## 1. Purpose of Demo Mode

The UniGuard Demo Mode provides an in-memory, reproducible simulation harness for evaluating unidirectional flow processing and feature extraction pipelines without requiring an active physical network sensor, TAP device, or physical data diode.

It generates statistical network flow metadata modeling six simulated behavioral profiles.

---

## 2. Simulated Behavioral Profiles

| Profile Label | Traffic Pattern Characteristics | Flow Duration | Packet Count | Packet Sizes | Typical Ports & Protocols |
|---|---|---|---|---|---|
| `NORMAL` | Moderate rates, human/API inter-arrival gaps, standard web traffic | 1.0 – 15.0 s | 8 – 30 pkts | Mixed: 64, 128, 256, 512, 1024, 1420 B | TCP/UDP 80, 443, 53, 8080 |
| `SCANNING_LIKE` | Rapid fan-out across multiple ports/destinations, low bytes/flow | 0.001 – 0.05 s | 1 – 2 pkts | Small SYN probes: 60 B | TCP across common service ports |
| `DOS_LIKE` | Volumetric packet stream, high packet rate (pps), microsecond intervals | Variable | 300 – 800 pkts | Identical high-rate frames (512–1420 B) | UDP / TCP flood |
| `BOTNET_LIKE` | Periodic outbound pulses with low jitter ($CV < 0.05$), fixed target | 20.0 – 60.0 s | 8 – 16 pkts | Identical 512 B pulses | TCP 443 |
| `EXFILTRATION_LIKE` | Heavy outbound byte volume, sustained flow, large average packet size | 5.0 – 30.0 s | 80 – 200 pkts | MTU dominated (1380–1420 B) | TCP / HTTPS 443 |
| `OTHER_SUSPICIOUS` | Irregular packet size distribution, erratic burst inter-arrivals | Variable | 10 – 25 pkts | Irregular sizes (40–1450 B) | UDP 5353 / Custom |

---

## 3. PRNG Determinism & Random Seed

The generator incorporates a configurable pseudorandom number generator (PRNG) seed:
* **Reproducibility**: Calling with the same seed (e.g. `seed=42`) generates an identical, reproducible flow sequence.
* **Testing**: Eliminates flakiness in automated unit and regression testing.
* **Exploration**: Supplying a different seed generates distinct statistical variations within the profile parameters.

---

## 4. Processing Pipeline

The demo engine feeds the same canonical pipeline consumed by future live telemetry:

```
+-------------------------------------------------------+
|                DemoTrafficCollector                   |
| (Generates DirectionalFlowRecord with RFC IP space)   |
+---------------------------+---------------------------+
                            |
                            v
+-------------------------------------------------------+
|               DirectionalFlowProcessor                |
| (Validates directional 5-tuple, timestamps, counts)   |
+---------------------------+---------------------------+
                            |
                            v
+-------------------------------------------------------+
|                     FeatureEngine                     |
|  (Extracts 16 features using batch context window)    |
+---------------------------+---------------------------+
                            |
                            v
+-------------------------------------------------------+
|                   FeaturePreprocessor                 |
|    (Validates finite numerics, applies max bounds)    |
+---------------------------+---------------------------+
                            |
                            v
+-------------------------------------------------------+
|                    DemoResultItem                     |
| (Flow Record + FeatureVector + Preprocessed + Label)  |
+-------------------------------------------------------+
```

---

## 5. REST API Endpoints

### 5.1 Controller State Endpoints
* `GET /api/demo/status` — Retrieves engine state (`STOPPED`, `RUNNING`, `PAUSED`), generated flow count, active seed, and disclaimer.
* `POST /api/demo/start` — Transitions engine to `RUNNING`. Accepts optional `{ "seed": 42, "profile_mix": { ... } }`.
* `POST /api/demo/pause` — Transitions engine to `PAUSED`.
* `POST /api/demo/stop` — Transitions engine to `STOPPED`.
* `POST /api/demo/clear` — Resets session counter to `0` and resets PRNG sequence.

### 5.2 Batch Generation Endpoint
* `POST /api/demo/batch`
  * **Request Body**:
    ```json
    {
      "count": 5,
      "seed": 42,
      "profile_mix": {
        "NORMAL": 0.50,
        "SCANNING_LIKE": 0.15,
        "DOS_LIKE": 0.15,
        "BOTNET_LIKE": 0.10,
        "EXFILTRATION_LIKE": 0.05,
        "OTHER_SUSPICIOUS": 0.05
      }
    }
    ```
  * **Response (`200 OK`)**: Array of `DemoResultItem` objects containing full flow telemetry, 16 extracted features, preprocessed vector values, and simulated profile label.

---

## 6. Limitations

* Synthetic flows do not contain Layer-7 application payloads (e.g. HTTP headers or raw TLS handshakes).
* Profile labels represent simulated behavioral classes for demonstration and training, not ground-truth forensic evidence of actual compromises.
