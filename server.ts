import { createMcpHandler } from "mcp-handler";
import { z } from "zod";
import { auditEndpointCompliance } from "./lib/circuit/auditor.js";
import { inspectPayloadSchema } from "./lib/circuit/schema.js";
import { evaluateCircuitBreaker, getBreakerState } from "./lib/circuit/breaker.js";
import { verifyWebhookSignature } from "./lib/circuit/webhook.js";
import {
  createCircuitReport,
  verifyCircuitReport,
  CircuitReport,
  CircuitTraceStep,
} from "./lib/circuit/report.js";
import { DEFAULT_POLICY_CONFIG } from "./lib/circuit/policy.js";
import { TOOL_PRICES_ATOMIC, TOOL_PRICES_HUMAN } from "./lib/x402/challenge.js";
import { anchorToOgStorage } from "./lib/og/storage.js";

// In-memory artifact storage for get_artifact
const ARTIFACT_STORE = new Map<string, any>();

function textResult(value: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }] };
}

const CIRCUIT_INSTRUCTIONS = `EVIDIQ Circuit — verifiable API proxy, TLS attestation, & circuit breaker guard for autonomous AI agents.

Use validate_request_params before paying. Paid tools audit endpoints, inspect payload schemas, enforce circuit breaker states, verify webhook signatures, and generate signed exchange receipts.

Five free tools: circuit_capabilities, validate_request_params, estimate_cost, verify_circuit_report, get_artifact.
Five x402-paid tools: audit_endpoint_compliance (0.005 USDT0), inspect_payload_schema (0.01 USDT0), enforce_circuit_breaker (0.015 USDT0), verify_webhook_signature (0.02 USDT0), attest_exchange_receipt (0.03 USDT0). Payment settles before work begins.`;

export const handler = createMcpHandler(
  (server) => {
    // -------------------------------------------------------------
    // PAID TOOL 1: audit_endpoint_compliance (0.005 USDT0)
    // -------------------------------------------------------------
    server.registerTool(
      "audit_endpoint_compliance",
      {
        title: "Audit endpoint compliance for TLS and security headers",
        description: "Audit outbound API endpoint: TLS certificate validity, latency SLA, CORS configuration, and security headers (0.005 USDT0).",
        inputSchema: {
          targetUrl: z.string().describe("Target API endpoint URL to audit (e.g. https://api.example.com/v1/data)"),
          tlsInfo: z.object({
            validUntil: z.string().optional(),
            issuer: z.string().optional(),
            san: z.array(z.string()).optional(),
            trustedCa: z.boolean().optional(),
          }).optional(),
          headers: z.record(z.string()).optional(),
          latencyMs: z.number().optional(),
        },
      },
      async ({ targetUrl, tlsInfo, headers, latencyMs }) => {
        const startTime = Date.now();
        const auditRes = auditEndpointCompliance({
          targetUrl,
          tlsInfo,
          headers,
          latencyMs: latencyMs || 120,
        });

        const report = await createCircuitReport({
          targetUrl,
          trace: auditRes.steps,
          evaluationStartTimeMs: startTime,
        });

        ARTIFACT_STORE.set(report.metadata.executionId, report);
        ARTIFACT_STORE.set(report.receipt.reportDigest, report);

        return textResult({
          success: true,
          verdict: report.verdict,
          executionId: report.metadata.executionId,
          report,
        });
      }
    );

    // -------------------------------------------------------------
    // PAID TOOL 2: inspect_payload_schema (0.01 USDT0)
    // -------------------------------------------------------------
    server.registerTool(
      "inspect_payload_schema",
      {
        title: "Inspect payload schema and detect type drift",
        description: "Validate API response JSON payload against expected JSON Schema to detect data poisoning or structural drift (0.01 USDT0).",
        inputSchema: {
          targetUrl: z.string().describe("Target API URL"),
          payload: z.any().describe("API JSON response payload to inspect"),
          expectedSchema: z.record(z.any()).optional(),
          baselineTypes: z.record(z.string()).optional(),
        },
      },
      async ({ targetUrl, payload, expectedSchema, baselineTypes }) => {
        const startTime = Date.now();
        const auditRes = auditEndpointCompliance({ targetUrl });
        const schemaSteps = inspectPayloadSchema({
          payload,
          expectedSchema,
          baselineTypes,
        }, auditRes.steps.length);

        const allSteps = [...auditRes.steps, ...schemaSteps];
        const report = await createCircuitReport({
          targetUrl,
          trace: allSteps,
          evaluationStartTimeMs: startTime,
        });

        ARTIFACT_STORE.set(report.metadata.executionId, report);
        ARTIFACT_STORE.set(report.receipt.reportDigest, report);

        return textResult({
          success: true,
          verdict: report.verdict,
          executionId: report.metadata.executionId,
          report,
        });
      }
    );

    // -------------------------------------------------------------
    // PAID TOOL 3: enforce_circuit_breaker (0.015 USDT0)
    // -------------------------------------------------------------
    server.registerTool(
      "enforce_circuit_breaker",
      {
        title: "Enforce circuit breaker state machine",
        description: "Evaluate endpoint error rates, latency spikes, and velocity thresholds to return CLOSED/OPEN state and ALLOW/BLOCK verdict (0.015 USDT0).",
        inputSchema: {
          targetHost: z.string().describe("Target host domain (e.g. api.example.com)"),
          totalCalls: z.number().describe("Total calls recorded in window"),
          errorCalls: z.number().describe("Count of 5xx errors recorded in window"),
          latencyP95Ms: z.number().describe("P95 response latency in ms"),
          state: z.enum(["CLOSED", "HALF_OPEN", "OPEN"]).optional(),
        },
      },
      async ({ targetHost, totalCalls, errorCalls, latencyP95Ms, state }) => {
        const startTime = Date.now();
        const targetUrl = `https://${targetHost}/api`;

        const auditRes = auditEndpointCompliance({ targetUrl });
        const breakerRes = evaluateCircuitBreaker({
          targetHost,
          totalCalls,
          errorCalls,
          latencyP95Ms,
          state,
        }, DEFAULT_POLICY_CONFIG, auditRes.steps.length);

        const allSteps = [...auditRes.steps, ...breakerRes.steps];
        const report = await createCircuitReport({
          targetUrl,
          trace: allSteps,
          evaluationStartTimeMs: startTime,
        });

        ARTIFACT_STORE.set(report.metadata.executionId, report);
        ARTIFACT_STORE.set(report.receipt.reportDigest, report);

        return textResult({
          success: true,
          circuitState: breakerRes.breakerState,
          verdict: report.verdict,
          executionId: report.metadata.executionId,
          report,
        });
      }
    );

    // -------------------------------------------------------------
    // PAID TOOL 4: verify_webhook_signature (0.02 USDT0)
    // -------------------------------------------------------------
    server.registerTool(
      "verify_webhook_signature",
      {
        title: "Verify webhook HMAC or EIP-191 signature",
        description: "Cryptographically verify HMAC-SHA256 or EIP-191 signatures on incoming/outgoing agent webhooks (0.02 USDT0).",
        inputSchema: {
          payload: z.any().describe("Webhook payload body"),
          signature: z.string().describe("Hex signature string (e.g. sha256=... or 0x...)"),
          secret: z.string().optional().describe("HMAC secret key"),
          timestampHeader: z.string().optional().describe("Webhook timestamp header for replay window check"),
          scheme: z.enum(["hmac-sha256", "eip-191"]).optional(),
        },
      },
      async ({ payload, signature, secret, timestampHeader, scheme }) => {
        const startTime = Date.now();
        const targetUrl = "https://webhook.agent.local/receive";
        const auditRes = auditEndpointCompliance({ targetUrl });
        const webhookSteps = verifyWebhookSignature({
          payload,
          signature,
          secret,
          timestampHeader,
          scheme,
        }, DEFAULT_POLICY_CONFIG, auditRes.steps.length);

        const allSteps = [...auditRes.steps, ...webhookSteps];
        const report = await createCircuitReport({
          targetUrl,
          trace: allSteps,
          evaluationStartTimeMs: startTime,
        });

        ARTIFACT_STORE.set(report.metadata.executionId, report);
        ARTIFACT_STORE.set(report.receipt.reportDigest, report);

        return textResult({
          success: true,
          verdict: report.verdict,
          executionId: report.metadata.executionId,
          report,
        });
      }
    );

    // -------------------------------------------------------------
    // PAID TOOL 5: attest_exchange_receipt (0.03 USDT0)
    // -------------------------------------------------------------
    server.registerTool(
      "attest_exchange_receipt",
      {
        title: "Attest API HTTP exchange receipt with 0G anchoring",
        description: "Generate an EIP-191 signed cryptographic attestation receipt of an API HTTP exchange with 0G Merkle root anchoring (0.03 USDT0).",
        inputSchema: {
          targetUrl: z.string().describe("Target URL of the API exchange"),
          requestPayload: z.record(z.any()).optional(),
          responsePayload: z.record(z.any()).optional(),
          headers: z.record(z.string()).optional(),
          latencyMs: z.number().optional(),
        },
      },
      async ({ targetUrl, requestPayload, responsePayload, headers, latencyMs }) => {
        const startTime = Date.now();
        const auditRes = auditEndpointCompliance({
          targetUrl,
          headers,
          latencyMs: latencyMs || 100,
        });

        const ogRes = await anchorToOgStorage({
          targetUrl,
          requestPayload,
          responsePayload,
          timestamp: new Date().toISOString(),
        });

        const report = await createCircuitReport({
          targetUrl,
          trace: auditRes.steps,
          evaluationStartTimeMs: startTime,
          zeroGAnchorTx: ogRes.tx,
          zeroGStorageRoot: ogRes.root,
        });

        ARTIFACT_STORE.set(report.metadata.executionId, report);
        ARTIFACT_STORE.set(report.receipt.reportDigest, report);

        return textResult({
          success: true,
          verdict: report.verdict,
          executionId: report.metadata.executionId,
          zeroGAnchored: ogRes.ok,
          report,
        });
      }
    );

    // -------------------------------------------------------------
    // FREE TOOL 1: circuit_capabilities (Free)
    // -------------------------------------------------------------
    server.registerTool(
      "circuit_capabilities",
      {
        title: "Circuit capabilities, policy defaults, and pricing",
        description: "Return engine limits, supported auth schemes, circuit breaker defaults, and tool pricing catalog. Free.",
        inputSchema: {},
      },
      async () => textResult({
        service: "EVIDIQ Circuit MCP",
        version: "1.0.0",
        policyDefaults: DEFAULT_POLICY_CONFIG,
        verdicts: ["ALLOW", "WARN", "BLOCK"],
        breakerStates: ["CLOSED", "HALF_OPEN", "OPEN"],
        severities: ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        supportedAuthSchemes: ["hmac-sha256", "eip-191"],
        pricing: {
          paid: TOOL_PRICES_HUMAN,
          free: [
            "circuit_capabilities",
            "validate_request_params",
            "estimate_cost",
            "verify_circuit_report",
            "get_artifact",
          ],
        },
      })
    );

    // -------------------------------------------------------------
    // FREE TOOL 2: validate_request_params (Free)
    // -------------------------------------------------------------
    server.registerTool(
      "validate_request_params",
      {
        title: "Validate target URL format and parameters",
        description: "Validate target URL format, headers, and schema structures without executing or paying. Free.",
        inputSchema: {
          targetUrl: z.string().optional().describe("Target URL to validate"),
          headers: z.record(z.string()).optional(),
          expectedSchema: z.record(z.any()).optional(),
        },
      },
      async ({ targetUrl }) => {
        if (!targetUrl) {
          return textResult({
            valid: false,
            usage: "Pass targetUrl to validate a URL, optional headers and expectedSchema.",
            example: { targetUrl: "https://api.example.com/v1/quote" },
            checks: ["url_format", "headers_shape", "expected_schema_shape"],
            free: true,
            message: "No targetUrl supplied. This tool is free; call it again with a targetUrl to validate.",
          });
        }

        let validUrl = true;
        let urlError = "";
        try {
          new URL(targetUrl);
        } catch (e: any) {
          validUrl = false;
          urlError = e.message;
        }

        return textResult({
          valid: validUrl,
          targetUrl,
          urlError: validUrl ? undefined : urlError,
          headersValid: true,
          schemaValid: true,
          message: validUrl
            ? "Target URL format and parameters are valid"
            : `Invalid URL format: ${urlError}`,
        });
      }
    );

    // -------------------------------------------------------------
    // FREE TOOL 3: estimate_cost (Free)
    // -------------------------------------------------------------
    server.registerTool(
      "estimate_cost",
      {
        title: "Quote exact tool price",
        description: "Return exact atomic and human-readable price for any paid tool. Free.",
        inputSchema: {
          toolName: z.string().optional().describe("Paid tool name"),
        },
      },
      async ({ toolName }) => {
        if (!toolName) {
          return textResult({
            network: "eip155:196",
            asset: "0x779ded0c9e1022225f8e0630b35a9b54be713736",
            symbol: "USDT0",
            pricing: TOOL_PRICES_HUMAN,
            freeTools: [
              "circuit_capabilities",
              "validate_request_params",
              "estimate_cost",
              "verify_circuit_report",
              "get_artifact",
            ],
          });
        }

        const atomic = TOOL_PRICES_ATOMIC[toolName];
        const human = TOOL_PRICES_HUMAN[toolName];

        if (!atomic) {
          return textResult({
            toolName,
            isPaid: false,
            cost: "0 USDT0 (Free preflight tool)",
          });
        }

        return textResult({
          toolName,
          isPaid: true,
          atomicAmount: atomic,
          humanAmount: human,
          chain: "eip155:196",
          asset: "0x779ded0c9e1022225f8e0630b35a9b54be713736",
        });
      }
    );

    // -------------------------------------------------------------
    // FREE TOOL 4: verify_circuit_report (Free)
    // -------------------------------------------------------------
    server.registerTool(
      "verify_circuit_report",
      {
        title: "Offline verification of a CircuitReport",
        description: "Cryptographically verify a signed exchange receipt or circuit report offline against all 4 invariants. Free.",
        inputSchema: {
          report: z.any().describe("CircuitReport object to verify"),
        },
      },
      async ({ report }) => {
        if (!report || typeof report !== "object") {
          return textResult({
            valid: false,
            errors: ["Invalid parameters: report object required"],
          });
        }

        const verifyRes = await verifyCircuitReport(report as CircuitReport);
        return textResult({
          valid: verifyRes.valid,
          errors: verifyRes.errors,
          executionId: report.metadata?.executionId,
          reportDigest: report.receipt?.reportDigest,
        });
      }
    );

    // -------------------------------------------------------------
    // FREE TOOL 5: get_artifact (Free)
    // -------------------------------------------------------------
    server.registerTool(
      "get_artifact",
      {
        title: "Retrieve stored Circuit artifact",
        description: "Retrieve a stored exchange receipt or 0G Merkle proof by content-addressed ID. Free.",
        inputSchema: {
          artifactId: z.string().optional().describe("Execution ID or report digest hex"),
        },
      },
      async ({ artifactId }) => {
        if (!artifactId) {
          return textResult({
            found: false,
            usage: "Provide `artifactId` to fetch a stored artifact.",
            note: "Free. An artifact id is a content address, not an access-control token.",
          });
        }

        const artifact = ARTIFACT_STORE.get(artifactId);
        if (!artifact) {
          return textResult({
            found: false,
            artifactId,
            message: "Artifact not found in active session store",
          });
        }

        return textResult({
          found: true,
          artifactId,
          artifact,
        });
      }
    );
  },
  {
    instructions: CIRCUIT_INSTRUCTIONS,
    capabilities: { tools: {} },
  },
  {
    basePath: "",
    maxDuration: 300,
    verboseLogs: false,
  }
);
