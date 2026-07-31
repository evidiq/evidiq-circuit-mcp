# EVIDIQ Circuit — Verifiable API Proxy & Guard

> Verifiable API proxy, TLS attestation, & circuit breaker guard for autonomous AI agents.

Endpoint: `https://mcp.evidiq.dev/circuit/mcp`
Host Port: `3014`
Chain: `eip155:196` (X Layer Mainnet)
Asset: `USDT0` (`0x779ded0c9e1022225f8e0630b35a9b54be713736`)

---

## Capabilities

Circuit provides 10 tools (5 paid x402-gated, 5 free preflight & discovery):

### Paid Tools (x402 Gated)
1. `audit_endpoint_compliance` (0.005 USDT0 / 5000 atomic): Audit outbound API endpoint: TLS certificate validity, latency SLA, CORS configuration, and security headers.
2. `inspect_payload_schema` (0.01 USDT0 / 10000 atomic): Validate API response JSON payload against expected JSON Schema to detect data poisoning or structural drift.
3. `enforce_circuit_breaker` (0.015 USDT0 / 15000 atomic): Evaluate endpoint error rates, latency spikes, and velocity thresholds to return a `CLOSED` (healthy) or `OPEN` (tripped) state and `BLOCK`/`ALLOW` verdict.
4. `verify_webhook_signature` (0.02 USDT0 / 20000 atomic): Cryptographically verify HMAC-SHA256 or EIP-191 signatures on incoming/outgoing agent webhooks.
5. `attest_exchange_receipt` (0.03 USDT0 / 30000 atomic): Generate an EIP-191 signed cryptographic attestation receipt of an API HTTP exchange with 0G Merkle root anchoring.

### Free Tools
1. `circuit_capabilities`: Return engine limits, supported auth schemes, circuit breaker defaults, and tool pricing catalog.
2. `validate_request_params`: Validate target URL format, headers, and schema structures without executing or paying.
3. `estimate_cost`: Return exact atomic and human-readable price for any paid tool.
4. `verify_circuit_report`: Cryptographically verify a signed exchange receipt or circuit report offline.
5. `get_artifact`: Retrieve a stored exchange receipt or 0G Merkle proof by content-addressed ID.

---

## Contract Standards
- **Evaluation Verdicts**: `ALLOW`, `WARN`, `BLOCK`
- **Circuit States**: `CLOSED` (Healthy), `HALF_OPEN` (Trial), `OPEN` (Tripped)
- **Severity Levels**: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`
- **Integrity**: RFC 8785 Canonical JSON Hashing (JCS) + SHA-256 + EIP-191 deterministic ECDSA signing.
