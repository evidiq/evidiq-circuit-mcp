import { X402Challenge, X402AcceptRequirement } from "./types.js";
import { getX402Config } from "./config.js";

export const TOOL_PRICES_ATOMIC: Record<string, string> = {
  audit_endpoint_compliance: "5000",   // 0.005 USDT0
  inspect_payload_schema: "10000",      // 0.01 USDT0
  enforce_circuit_breaker: "15000",     // 0.015 USDT0
  verify_webhook_signature: "20000",    // 0.02 USDT0
  attest_exchange_receipt: "30000",     // 0.03 USDT0
};

export const TOOL_PRICES_HUMAN: Record<string, string> = {
  audit_endpoint_compliance: "0.005 USDT0",
  inspect_payload_schema: "0.01 USDT0",
  enforce_circuit_breaker: "0.015 USDT0",
  verify_webhook_signature: "0.02 USDT0",
  attest_exchange_receipt: "0.03 USDT0",
};

export function createChallenge(toolName: string): X402Challenge {
  const cfg = getX402Config();
  const atomicAmount = TOOL_PRICES_ATOMIC[toolName] || "5000";
  const humanAmount = TOOL_PRICES_HUMAN[toolName] || "0.005 USDT0";

  const acceptReq: X402AcceptRequirement = {
    scheme: "exact",
    network: cfg.chain,
    asset: cfg.asset,
    amount: atomicAmount,
    payTo: cfg.payTo,
    maxTimeoutSeconds: 300,
    extra: {
      name: cfg.domainName,
      version: cfg.domainVersion,
    },
  };

  return {
    x402Version: 2,
    resource: {
      url: `${cfg.publicBaseUrl}/mcp`,
      description: "EVIDIQ Circuit — verifiable API proxy, TLS attestation, & circuit breaker guard for autonomous AI agents.",
      mimeType: "application/json",
    },
    accepts: [acceptReq],
    error: `Payment Required for tool '${toolName}'. Costs ${humanAmount}.`,
  };
}

export function encodeChallengeToBase64(challenge: X402Challenge): string {
  const { error, ...headerChallenge } = challenge;
  return Buffer.from(JSON.stringify(headerChallenge)).toString("base64");
}

export function getX402DiscoveryCatalog() {
  const cfg = getX402Config();
  return {
    x402Version: 2,
    resource: {
      url: `${cfg.publicBaseUrl}/mcp`,
      description: "EVIDIQ Circuit — verifiable API proxy, TLS attestation, & circuit breaker guard for autonomous AI agents. Free tools (circuit_capabilities, validate_request_params, estimate_cost, verify_circuit_report, get_artifact) remain free.",
      mimeType: "application/json",
    },
    accepts: [
      {
        scheme: "exact",
        network: cfg.chain,
        asset: cfg.asset,
        amount: "5000",
        payTo: cfg.payTo,
        maxTimeoutSeconds: 300,
        extra: {
          name: cfg.domainName,
          version: cfg.domainVersion,
        },
      },
    ],
    pricing: [
      { tool: "audit_endpoint_compliance", amount: "5000", usd: 0.005 },
      { tool: "inspect_payload_schema", amount: "10000", usd: 0.01 },
      { tool: "enforce_circuit_breaker", amount: "15000", usd: 0.015 },
      { tool: "verify_webhook_signature", amount: "20000", usd: 0.02 },
      { tool: "attest_exchange_receipt", amount: "30000", usd: 0.03 },
      { tool: "circuit_capabilities", amount: "0", usd: 0, free: true },
      { tool: "validate_request_params", amount: "0", usd: 0, free: true },
      { tool: "estimate_cost", amount: "0", usd: 0, free: true },
      { tool: "verify_circuit_report", amount: "0", usd: 0, free: true },
      { tool: "get_artifact", amount: "0", usd: 0, free: true },
    ],
    guidance: "Before paying, call the free validate_request_params tool first; circuit_capabilities and estimate_cost are also free.",
  };
}
