import { createChallenge, encodeChallengeToBase64 } from "./challenge.js";
import { extractPaymentHeader } from "./verify.js";
import { verifyAndSettlePayment } from "./okx.js";

export const PAID_TOOLS = new Set([
  "audit_endpoint_compliance",
  "inspect_payload_schema",
  "enforce_circuit_breaker",
  "verify_webhook_signature",
  "attest_exchange_receipt",
]);

export function isPaidTool(toolName: string): boolean {
  return PAID_TOOLS.has(toolName);
}

export function build402Response(toolName: string) {
  const challenge = createChallenge(toolName);
  const base64Challenge = encodeChallengeToBase64(challenge);

  return new Response(JSON.stringify(challenge), {
    status: 402,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "payment-required": base64Challenge,
      "x-payment-required": base64Challenge,
    },
  });
}

export async function handleX402Gate(
  req: Request,
  handler: (req: Request) => Promise<Response>
): Promise<Response> {
  const url = new URL(req.url);

  // Normalize Accept header for transport compliance (§16)
  const incomingAccept = req.headers.get("accept") || "";
  const headers = new Headers(req.headers);
  if (!incomingAccept.includes("text/event-stream")) {
    headers.set("accept", "application/json, text/event-stream");
  }
  const modifiedReq = new Request(req.url, {
    method: req.method,
    headers,
    body: req.body,
    // @ts-ignore
    duplex: "half",
  });

  if (req.method === "GET") {
    // GET /mcp returns 402 challenge (§7 of x402 runbook)
    return build402Response("audit_endpoint_compliance");
  }

  if (req.method === "POST") {
    let bodyText = "";
    try {
      bodyText = await modifiedReq.clone().text();
    } catch {
      return handler(modifiedReq);
    }

    let jsonRpc: any = null;
    try {
      jsonRpc = JSON.parse(bodyText);
    } catch {
      return handler(modifiedReq);
    }

    if (jsonRpc && jsonRpc.method === "tools/call" && jsonRpc.params) {
      const toolName = jsonRpc.params.name;
      if (isPaidTool(toolName)) {
        const paymentHeader = extractPaymentHeader(
          Object.fromEntries(req.headers.entries())
        );

        if (!paymentHeader) {
          return build402Response(toolName);
        }

        const settleResult = await verifyAndSettlePayment(paymentHeader, toolName);
        if (!settleResult.success) {
          return new Response(
            JSON.stringify({
              jsonrpc: "2.0",
              id: jsonRpc.id || 1,
              error: {
                code: -32002,
                message: `x402 payment settlement failed: ${settleResult.error}`,
              },
            }),
            {
              status: 402,
              headers: {
                "Content-Type": "application/json",
                "Cache-Control": "no-store",
              },
            }
          );
        }

        // Add settlement tx to request context header if needed
        const reqWithSettle = new Request(modifiedReq.url, {
          method: modifiedReq.method,
          headers: modifiedReq.headers,
          body: bodyText,
        });
        if (settleResult.txHash) {
          reqWithSettle.headers.set("x-settlement-tx", settleResult.txHash);
        }

        const res = await handler(reqWithSettle);

        // Append PAYMENT-RESPONSE header on success
        const responseHeaders = new Headers(res.headers);
        responseHeaders.set(
          "PAYMENT-RESPONSE",
          JSON.stringify({
            status: "settled",
            transaction: settleResult.txHash || "",
          })
        );

        return new Response(res.body, {
          status: res.status,
          statusText: res.statusText,
          headers: responseHeaders,
        });
      }
    }
  }

  return handler(modifiedReq);
}
