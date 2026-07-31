import { describe, it, expect } from "vitest";
import { auditEndpointCompliance } from "../lib/circuit/auditor.js";
import { inspectPayloadSchema } from "../lib/circuit/schema.js";
import { evaluateCircuitBreaker } from "../lib/circuit/breaker.js";
import { verifyWebhookSignature } from "../lib/circuit/webhook.js";
import { createCircuitReport, verifyCircuitReport } from "../lib/circuit/report.js";
import crypto from "crypto";

describe("EVIDIQ Circuit MCP Engine Tests", () => {
  it("audits endpoint compliance for TLS and security headers", () => {
    const res = auditEndpointCompliance({
      targetUrl: "https://api.example.com/v1/data",
      headers: {
        "strict-transport-security": "max-age=31536000",
        "access-control-allow-origin": "https://agent.example.com",
      },
    });

    expect(res.steps.length).toBe(5);
    expect(res.steps[0].checkId).toBe("tls.expired");
    expect(res.steps[3].checkId).toBe("headers.missing_hsts");
    expect(res.steps[3].passed).toBe(true);
    expect(res.steps[4].checkId).toBe("headers.cors_wildcard");
    expect(res.steps[4].passed).toBe(true);
  });

  it("detects missing HSTS and CORS wildcard", () => {
    const res = auditEndpointCompliance({
      targetUrl: "https://api.example.com/v1/data",
      headers: {
        "access-control-allow-origin": "*",
      },
    });

    expect(res.steps[3].passed).toBe(false); // missing HSTS
    expect(res.steps[4].passed).toBe(false); // CORS wildcard
  });

  it("evaluates JSON schema validation and field type drift", () => {
    const steps = inspectPayloadSchema({
      payload: { amount: "100", status: "ok" },
      expectedSchema: { required: ["amount", "user"] },
      baselineTypes: { amount: "number" },
    }, 5);

    expect(steps.length).toBe(2);
    expect(steps[0].checkId).toBe("schema.validation_failed");
    expect(steps[0].passed).toBe(false); // missing user
    expect(steps[1].checkId).toBe("schema.field_type_drift");
    expect(steps[1].passed).toBe(false); // amount is string instead of number
  });

  it("evaluates circuit breaker error rate and latency", () => {
    const breakerRes = evaluateCircuitBreaker({
      targetHost: "api.example.com",
      totalCalls: 100,
      errorCalls: 20, // 20% > 15% threshold
      latencyP95Ms: 3000, // > 2500ms SLA
    });

    expect(breakerRes.breakerState).toBe("OPEN");
    expect(breakerRes.steps[0].passed).toBe(false);
    expect(breakerRes.steps[1].passed).toBe(false);
  });

  it("verifies webhook HMAC-SHA256 signatures", () => {
    const secret = "my_secret_key";
    const payload = JSON.stringify({ event: "agent.transfer", amount: 50 });
    const hmac = crypto.createHmac("sha256", secret).update(payload).digest("hex");

    const steps = verifyWebhookSignature({
      payload,
      signature: `sha256=${hmac}`,
      secret,
      timestampHeader: new Date().toISOString(),
    });

    expect(steps[0].checkId).toBe("webhook.invalid_signature");
    expect(steps[0].passed).toBe(true);
    expect(steps[1].checkId).toBe("webhook.timestamp_expired");
    expect(steps[1].passed).toBe(true);
  });

  it("generates and verifies CircuitReport against all 4 mathematical invariants", async () => {
    const auditRes = auditEndpointCompliance({
      targetUrl: "https://api.example.com/v1/data",
    });

    const report = await createCircuitReport({
      targetUrl: "https://api.example.com/v1/data",
      trace: auditRes.steps,
      evaluationStartTimeMs: Date.now() - 50,
    });

    expect(report.metadata.executionId).toMatch(/^circuit_exec_\d+_[a-f0-9]{8}$/);
    expect(report.metadata.checksEvaluated).toBe(report.trace.length);
    expect(report.receipt.reportDigest).toMatch(/^0x[a-f0-9]{64}$/);
    expect(report.receipt.signature).toMatch(/^0x[a-f0-9]{130}$/);

    // Verify offline against all 4 invariants
    const verifyRes = await verifyCircuitReport(report);
    expect(verifyRes.valid).toBe(true);
    expect(verifyRes.errors).toHaveLength(0);
  });
});
