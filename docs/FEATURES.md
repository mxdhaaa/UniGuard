# UniGuard Directional Feature Contract

This specification documents the deterministic 16-feature vector extracted from unidirectional IP traffic telemetry.

---

## 1. Overview & Directionality Principles

In unidirectional traffic monitoring (e.g. physical data diodes, TAP/SPAN reflection, or unidirectional telemetry feeds), no reverse packets ($B \to A$) can be observed or expected.

All features defined below are calculated exclusively from one-way packet observations ($A \to B$) without assuming:
* TCP handshake completion (`SYN-ACK` / `ACK`)
* Layer-4 connection termination (`FIN` / `RST`)
* Request-response symmetry

---

## 2. Global Constants & Edge-Case Protection

* **$\epsilon$ (Epsilon)**: `1e-6` seconds ($1\,\mu\text{s}$). Used in rate denominators ($\max(\text{duration}, \epsilon)$) to prevent division by zero for flows whose duration is 0 or unmeasured.
* **Shannon Entropy Base**: $\log_2$, yielding entropy in bits.
* **Safe Default**: `0.0` for all rates, averages, standard deviations, and entropies when packet count is zero or data is missing.

---

## 3. Feature Specifications

| # | Feature Name | Type | Unit | Scope | Definition / Formula | Input Fields | Edge-Case Behavior |
|---|---|---|---|---|---|---|---|
| 1 | `flow_duration` | float | seconds | Flow | $t_{\text{last}} - t_{\text{first}}$ | `packet_timestamps` or `duration` | If single packet or simultaneous packets, returns `0.0`. |
| 2 | `packet_count` | int | count | Flow | Total number of directional packets ($N$). | `packet_sizes` or `packet_count` | Non-negative integer. Defaults to `0` if empty. |
| 3 | `byte_count` | int | bytes | Flow | Total volume of packet payloads ($B = \sum s_i$). | `packet_sizes` or `byte_count` | Non-negative integer. Defaults to `0` if empty. |
| 4 | `packets_per_second` | float | packets/s | Flow | $N / \max(\text{duration}, \epsilon)$ | `packet_count`, `duration` | If $N = 0$, returns `0.0`. If duration is $0.0$, uses $\epsilon$ divisor. |
| 5 | `bytes_per_second` | float | bytes/s | Flow | $B / \max(\text{duration}, \epsilon)$ | `byte_count`, `duration` | If $B = 0$, returns `0.0`. If duration is $0.0$, uses $\epsilon$ divisor. |
| 6 | `average_packet_size` | float | bytes | Flow | $\frac{1}{N} \sum_{i=1}^N s_i$ | `packet_sizes`, `packet_count`, `byte_count` | If $N = 0$, returns `0.0`. |
| 7 | `packet_size_std` | float | bytes | Flow | $\sqrt{\frac{1}{N} \sum_{i=1}^N (s_i - \bar{s})^2}$ | `packet_sizes` | If $N \le 1$, returns `0.0`. |
| 8 | `unique_destination_count` | int | count | Window | Number of distinct destination IPs observed from `source_ip`. | `destination_ip`, `context_flows` | If no context flows provided, defaults to `1` (or `0` if IP missing). |
| 9 | `unique_destination_port_count` | int | count | Window | Number of distinct destination ports observed from `source_ip`. | `destination_port`, `context_flows` | If no context flows provided, defaults to `1`. |
| 10 | `destination_port_entropy` | float | bits | Window | $H(\text{dst\_ports}) = -\sum p_i \log_2(p_i)$ | `destination_port`, `context_flows` | Returns `0.0` if single port or no context flows. Maximum 16 bits. |
| 11 | `packet_size_entropy` | float | bits | Flow | $H(\text{sizes}) = -\sum p(s) \log_2(p(s))$ | `packet_sizes` | Returns `0.0` if all packet sizes are identical or $N \le 1$. |
| 12 | `burst_score` | float | ratio | Flow | $\frac{CV}{CV + 1.0}$ where $CV = \frac{\sigma_{\Delta t}}{\mu_{\Delta t}}$ | `inter_arrival_times`, `packet_timestamps` | Returns `0.0` for perfectly periodic traffic ($\sigma = 0$) or $N < 2$. Returns `1.0` if $\mu_{\Delta t} = 0$ ($N \ge 2$ simultaneous). Strictly bounded in $[0.0, 1.0]$. |
| 13 | `source_activity_rate` | float | flows/s | Window | $\frac{\text{flows}_{\text{src}}}{\max(\text{span}, 1.0)}$ | `source_ip`, `context_flows` | Defaults to $1.0 / \max(\text{duration}, 1.0)$ if standalone flow. |
| 14 | `destination_diversity` | float | ratio | Window | $\frac{\text{unique\_destinations}}{\text{total\_source\_flows}}$ | `destination_ip`, `context_flows` | Standalone flow defaults to `1.0`. Strictly bounded in $[0.0, 1.0]$. |
| 15 | `port_diversity` | float | ratio | Window | $\frac{\text{unique\_destination\_ports}}{\text{total\_source\_flows}}$ | `destination_port`, `context_flows` | Standalone flow defaults to `1.0`. Strictly bounded in $[0.0, 1.0]$. |
| 16 | `protocol_indicator` | float | categorical | Flow | TCP=1.0, UDP=2.0, ICMP=3.0, DNS=4.0, HTTP=5.0, HTTPS=6.0, OTHER=0.0 | `protocol` | Case-insensitive mapping. Unknown protocols map to `0.0`. |

---

## 4. Canonical Feature Ordering

Downstream supervised classifiers (Random Forest) and unsupervised anomaly detectors (Isolation Forest) consume features in this exact numerical array index order:

```python
FEATURE_NAMES = [
    "flow_duration",                 # Index 0
    "packet_count",                  # Index 1
    "byte_count",                    # Index 2
    "packets_per_second",            # Index 3
    "bytes_per_second",              # Index 4
    "average_packet_size",           # Index 5
    "packet_size_std",               # Index 6
    "unique_destination_count",       # Index 7
    "unique_destination_port_count",  # Index 8
    "destination_port_entropy",      # Index 9
    "packet_size_entropy",           # Index 10
    "burst_score",                   # Index 11
    "source_activity_rate",          # Index 12
    "destination_diversity",         # Index 13
    "port_diversity",                # Index 14
    "protocol_indicator",            # Index 15
]
```

---

## 5. Preprocessing & Extreme Value Bounds

The `FeaturePreprocessor` (`backend/app/core/preprocessing.py`) applies defensive bounds to prevent numeric overflow:

* `flow_duration`: clamped to $\le 86,400.0$ s (24 hours).
* `packet_count`: clamped to $\le 100,000,000$.
* `byte_count`: clamped to $\le 100,000,000,000$ B (100 GB).
* `packets_per_second`: clamped to $\le 10,000,000.0$ pps.
* `bytes_per_second`: clamped to $\le 10,000,000,000.0$ Bps.
* `destination_port_entropy`: clamped to $\le 16.0$ bits.
* `burst_score`, `destination_diversity`, `port_diversity`: strictly clamped to $[0.0, 1.0]$.
* `NaN` or `Inf` inputs are replaced with safe fallback values (`0.0`) and flagged with `is_valid=False`.
