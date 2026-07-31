# EVIDIQ Circuit MCP — Verifiable API Proxy & Circuit Breaker Guard Service

Verifiable API proxy, TLS attestation, & circuit breaker guard for autonomous AI agents. Enforces endpoint compliance, JSON payload schema validation, error rate thresholds, HMAC/EIP-191 webhook signatures, and EIP-191 signed exchange receipts with 0G storage anchoring.

---

## Service Overview

- **Service Name**: `EVIDIQ-Circuit`
- **Network**: `eip155:196` (X Layer Mainnet)
- **Payment Asset**: `USD₮0` (`0x779ded0c9e1022225f8e0630b35a9b54be713736`)
- **Protocol**: x402 v2 payment gate on HTTP POST `/mcp`
- **Public Endpoint**: `https://mcp.evidiq.dev/circuit`

---

## 10 Tools Specification

### Paid Audit Tools (x402 Gated)

1. **`audit_endpoint_compliance`** — `0.005 USD₮0` (5,000 atomic)
   - Audits outbound API endpoint for TLS certificate validity, latency SLA, CORS headers, and security compliance.
2. **`inspect_payload_schema`** — `0.01 USD₮0` (10,000 atomic)
   - Inspects API JSON payload structure against JSON Schema to prevent data poisoning and schema drift.
3. **`enforce_circuit_breaker`** — `0.015 USD₮0` (15,000 atomic)
   - Evaluates endpoint error rates, latency spikes, and velocity thresholds to return CLOSED (healthy) or OPEN (tripped) states.
4. **`verify_webhook_signature`** — `0.02 USD₮0` (20,000 atomic)
   - Cryptographically verifies HMAC-SHA256 or EIP-191 signatures on incoming/outgoing agent webhooks.
5. **`attest_exchange_receipt`** — `0.03 USD₮0` (30,000 atomic)
   - Binds API HTTP exchange metadata into an EIP-191 signed attestation and anchors on 0G storage.

### Free Discovery & Preflight Tools

6. **`circuit_capabilities`** — `FREE`
   - Returns full engine capabilities, supported auth schemes, circuit breaker defaults, and pricing catalog.
7. **`validate_request_params`** — `FREE`
   - Preflight parse-check: validates target URL format, headers, and payload schema structure without charging.
8. **`estimate_cost`** — `FREE`
   - Price quotation lookup tool for atomic and human-readable tool pricing.
9. **`verify_circuit_report`** — `FREE`
   - Offline verification tool for SHA-256 canonical hash digests and EIP-191 signatures.
10. **`get_artifact`** — `FREE`
    - Retrieves stored exchange receipts, circuit reports, or 0G Merkle proofs by content-addressed ID.

---

## x402 Payment Instructions for AI Agents

When invoking any paid tool, if payment is required, the server returns an HTTP `402 Payment Required` response containing a base64-encoded x402 challenge header:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": 402,
    "message": "Payment Required for tool 'audit_endpoint_compliance'. Costs 0.005 USD₮0.",
    "data": {
      "challenge": "<base64_challenge_string>"
    }
  }
}
```

Include the signed payment authorization in subsequent HTTP headers:
`Authorization: Payment <base64_payment_header>` or `X-Payment: <base64_payment_header>`.
