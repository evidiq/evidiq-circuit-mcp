import { x402Client } from "@okxweb3/x402-core/client";
import { registerExactEvmScheme } from "@okxweb3/x402-evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";

const TEST_PRIVATE_KEY = process.env.X402_SETTLE_KEY;
if (!TEST_PRIVATE_KEY) {
  console.error("Missing required X402_SETTLE_KEY environment variable.");
  process.exit(1);
}
const TARGET_URL = process.env.TARGET_URL || "https://mcp.evidiq.dev/circuit/mcp";
const TOOL_NAME = process.env.TOOL_NAME || "audit_endpoint_compliance";

function getToolArgs(name) {
  switch (name) {
    case "audit_endpoint_compliance":
      return { targetUrl: "https://api.example.com/v1/status" };
    case "inspect_payload_schema":
      return { targetUrl: "https://api.example.com/v1/status", payload: { status: "ok" } };
    case "enforce_circuit_breaker":
      return { targetHost: "api.example.com", totalCalls: 100, errorCalls: 2, latencyP95Ms: 200 };
    case "verify_webhook_signature":
      return { payload: { event: "ping" }, signature: "0x1234567890abcdef" };
    case "attest_exchange_receipt":
      return { targetUrl: "https://api.example.com/v1/status", requestPayload: { id: 1 }, responsePayload: { ok: true } };
    default:
      return { targetUrl: "https://api.example.com/v1/status" };
  }
}

async function main() {
  console.log(`[1] Requesting 402 challenge from ${TARGET_URL} for tool ${TOOL_NAME}...`);
  const initialRes = await fetch(TARGET_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json, text/event-stream",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: TOOL_NAME,
        arguments: getToolArgs(TOOL_NAME),
      },
    }),
  });

  if (initialRes.status !== 402) {
    console.error(`Expected 402 status, got ${initialRes.status}`);
    process.exit(1);
  }

  const paymentHeader = initialRes.headers.get("payment-required") || initialRes.headers.get("x-payment-required");
  if (!paymentHeader) {
    console.error("Missing payment-required header in 402 response");
    process.exit(1);
  }

  console.log(`[2] Received 402 Challenge header (length: ${paymentHeader.length})`);
  const challengeObj = JSON.parse(Buffer.from(paymentHeader, "base64").toString("utf-8"));
  console.log("Parsed challenge object:", JSON.stringify(challengeObj, null, 2));

  const account = privateKeyToAccount(TEST_PRIVATE_KEY);
  console.log(`Payer address: ${account.address}`);

  const client = new x402Client();
  registerExactEvmScheme(client, { signer: account });

  console.log(`[3] Creating payment payload with official OKX x402Client...`);
  const paymentPayloadObj = await client.createPaymentPayload(challengeObj);
  const paymentHeaderBase64 = Buffer.from(JSON.stringify(paymentPayloadObj)).toString("base64");
  console.log(`Payment payload generated (length: ${paymentHeaderBase64.length})`);

  console.log(`[4] Sending paid request with payment-signature header...`);
  const paidRes = await fetch(TARGET_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json, text/event-stream",
      "payment-signature": paymentHeaderBase64,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: TOOL_NAME,
        arguments: getToolArgs(TOOL_NAME),
      },
    }),
  });

  console.log(`Response status: ${paidRes.status}`);
  const resText = await paidRes.text();
  console.log(`Response body: ${resText}`);

  const paymentRespHeader = paidRes.headers.get("payment-response");
  if (paymentRespHeader) {
    console.log(`PAYMENT-RESPONSE header: ${paymentRespHeader}`);
  }
}

main().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
