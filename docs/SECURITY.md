# UniGuard Security Policy & Hardening Specification

## 1. High-Level Threat Model

UniGuard is designed as an internal Security Operations Center (SOC) network intelligence and threat monitoring platform. It inspects unidirectional IP packet flows passively, extracts 16 statistical flow features, performs machine learning threat classification, computes explainable risk scores, and surfaces alerts in real time.

### Trust Boundary & Environment Classification
- **Operational Scope**: UniGuard is engineered for deployment within a **trusted management network or dedicated SOC environment**.
- **External Exposure**: The direct backend API is not intended to be exposed directly to the public internet without an authenticating reverse proxy or API gateway.
- **Data Inflow**: Inbound traffic consists of passive raw packet captures, offline PCAP files, and operational analyst dashboard queries.

---

## 2. Authentication & Authorization Status

> **Important Disclosure**: Milestone 15 intentionally does not implement a bespoke user authentication (AuthN) or role-based access control (RBAC) system.

- **Current State**: All REST endpoints and the WebSocket stream are unauthenticated.
- **Operational Requirement**: In production deployments, access control MUST be enforced at the network or reverse-proxy perimeter (e.g., VPN, mTLS, Cloudflare Access, AWS Cognito, or an authenticating Nginx ingress controller).
- **Future Roadmap**: Centralized SAML 2.0 / OIDC (SSO) integration is slated for enterprise-tier releases.

---

## 3. Secrets & Configuration Handling

- **Zero Hard-Coded Credentials**: No passwords, database credentials, API keys, or private certificates exist in the codebase.
- **Environment Isolation**: All deployment-specific parameters are supplied via environment variables (`DATABASE_URL`, `CORS_ORIGINS`, `API_HOST`, etc.).
- **Git Hygiene**: `.env` and local database files (`*.db`, `*.sqlite`) are strictly gitignored. `.env.example` contains only sanitized placeholder templates.
- **Database Connection Security**: Connection strings containing credentials are masked and never exposed in API outputs or application logs.

---

## 4. CORS Hardening

- **Configurable Whitelist**: Browser origins allowed to make cross-origin requests are controlled via `CORS_ORIGINS`.
- **Wildcard Rejection**: In `ENVIRONMENT=production`, any wildcard (`*`) origin is automatically stripped from the allowed origins list to prevent cross-origin data theft with credentials.
- **Localhost Development**: Default development settings allow `http://localhost:5173`, `http://localhost:3000`, `http://127.0.0.1:5173`, and `http://127.0.0.1:3000`.

---

## 5. HTTP Security Headers

FastAPI HTTP middleware injects the following security headers into every API response:

| Header | Value | Purpose |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type sniffing by browsers. |
| `X-Frame-Options` | `DENY` | Protects the application against clickjacking by preventing iframe embedding. |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Protects referrer metadata from leaking across external origins. |
| `Permissions-Policy` | `geolocation=(), camera=(), microphone=(), payment=()` | Disables sensitive browser hardware APIs. |

---

## 6. Upload & Path Traversal Hardening

The PCAP file ingestion pipeline (`POST /api/pcap/upload`) implements strict defensive measures:

1. **Filename Sanitization**:
   - Original filenames are stripped of null bytes (`\x00`), Windows backslashes (`\`), and path traversal segments (`../`, `..\\`) using `os.path.basename`.
   - Filenames evaluating to `.` or `..` are immediately rejected with `HTTP 400`.
2. **Extension Whitelisting**:
   - Only `.pcap` and `.pcapng` extensions are permitted. All executable or script extensions are rejected with `HTTP 400`.
3. **Storage Isolation**:
   - Files are stored using an internal random UUID (`upload_<uuid4>.pcap`) inside the dedicated `pcap_upload_dir`.
   - Absolute path validation ensures the target path is strictly within the upload directory boundary.
   - Upload directories are never mounted or served as static web directories.
4. **File Size Enforcement**:
   - Uploads are streamed with a strict byte counter enforcing `PCAP_MAX_FILE_SIZE_MB` (default: 50 MB).
   - If exceeded, an `HTTP 413` is returned and partial files are instantly deleted from disk.
5. **Deterministic Cleanup**:
   - Temporary PCAP files are deleted in a `finally` block immediately after flow feature extraction completes, ensuring temporary files do not accumulate.

---

## 7. Error Handling & Information Leakage Prevention

- **Production Mode (`ENVIRONMENT=production`)**:
  - Global exception handling catches all unhandled server errors and returns a generic `{"detail": "Internal server error occurred."}` (`HTTP 500`).
  - Python stack traces, local filesystem paths, internal module names, and database connection strings are never returned to clients.
- **Server-Side Observability**:
  - Full exception tracebacks are recorded only in server-side logs for operator debugging.

---

## 8. Logging Hygiene

- **Sensitive Data Redaction**:
  - Loggers are configured never to print database passwords, session tokens, or API credentials.
  - Raw packet payloads and packet payload bytes are strictly prohibited from log output.
- **Log Level Control**:
  - Configurable via `LOG_LEVEL` (`INFO` recommended for production; `DEBUG` for staging).

---

## 9. Packet Payload & Privacy Invariants

- **Zero Payload Inspection**: UniGuard models operate purely on statistical flow headers (packet count, byte volume, duration, TCP flags, port entropy, inter-packet arrival times).
- **No Payload Storage**: Unencrypted user application payloads (HTTP bodies, email contents, file transfers) are never parsed, analyzed, or stored in the database.
- **Compliance Alignment**: Supports GDPR and privacy-first network monitoring by inspecting traffic metadata without inspecting private user communications.

---

## 10. WebSocket Security

- **Endpoint**: `/api/ws/alerts` broadcasts real-time security alerts to connected SOC analysts.
- **Fail-Safe Broadcasting**: Disconnected or dead client sockets are cleaned up without disrupting active broadcasts.
- **Resource Limits**: Inactive or broken connections are culled immediately upon transmission failure.
- **Shutdown Cleanliness**: Server shutdown sends WebSocket close frame 1001 (Going Away) to release client sockets cleanly.

---

## 11. Known Limitations & Recommendations

1. **Authentication**: Must be provided by reverse proxy or gateway in untrusted network environments.
2. **Network Sniffing Capabilities**: Running live Scapy capture requires `CAP_NET_RAW` / `CAP_NET_ADMIN` on Linux. Run the container with minimal required capabilities rather than full privileged root access.
3. **DoS Resistance**: Rate-limiting should be applied at the outer Nginx or Cloudflare layer for public interfaces.
