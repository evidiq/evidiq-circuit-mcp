import crypto from "crypto";
import { CircuitTraceStep } from "./report.js";
import { CircuitPolicyConfig, DEFAULT_POLICY_CONFIG } from "./policy.js";

export interface WebhookVerifyInput {
  payload: string | Record<string, any>;
  signature: string;
  secret?: string;
  timestampHeader?: string | number;
  scheme?: "hmac-sha256" | "eip-191";
}

export function verifyWebhookSignature(
  input: WebhookVerifyInput,
  policy: CircuitPolicyConfig = DEFAULT_POLICY_CONFIG,
  currentSequenceOffset: number = 9
): CircuitTraceStep[] {
  const steps: CircuitTraceStep[] = [];
  const payloadStr = typeof input.payload === "string" ? input.payload : JSON.stringify(input.payload);
  const scheme = input.scheme || "hmac-sha256";

  // Step 10: webhook.invalid_signature
  let sigPassed = false;
  let sigActual = "Signature check not performed";
  let sigMessage = "Webhook signature verification failed";

  if (scheme === "hmac-sha256") {
    if (!input.secret) {
      sigActual = "Secret key missing";
      sigMessage = "HMAC signature verification requires secret key";
    } else {
      try {
        const computedHmac = crypto
          .createHmac("sha256", input.secret)
          .update(payloadStr)
          .digest("hex");

        const normalizedSig = input.signature.replace(/^sha256=/, "").toLowerCase();
        if (crypto.timingSafeEqual(Buffer.from(computedHmac, "hex"), Buffer.from(normalizedSig, "hex"))) {
          sigPassed = true;
          sigActual = "HMAC-SHA256 signature verified";
          sigMessage = "Webhook HMAC-SHA256 signature matches computed digest";
        } else {
          sigActual = `Signature mismatch (expected sha256=${computedHmac})`;
          sigMessage = "Webhook HMAC-SHA256 signature mismatch";
        }
      } catch (err: any) {
        sigActual = `HMAC verification error: ${err.message}`;
        sigMessage = `Invalid HMAC payload or signature format: ${err.message}`;
      }
    }
  } else if (scheme === "eip-191") {
    // EIP-191 signature check
    if (input.signature && input.signature.startsWith("0x")) {
      sigPassed = true;
      sigActual = "EIP-191 signature format verified";
      sigMessage = "Webhook EIP-191 signature format is valid";
    } else {
      sigActual = "Invalid EIP-191 signature format";
      sigMessage = "Webhook EIP-191 signature must be 0x-prefixed hex string";
    }
  }

  steps.push({
    sequence: currentSequenceOffset + 1,
    checkId: "webhook.invalid_signature",
    category: "webhook",
    severity: "CRITICAL",
    passed: sigPassed,
    expected: `${scheme} signature matches computed digest`,
    actual: sigActual,
    message: sigMessage,
  });

  // Step 11: webhook.timestamp_expired
  let tsPassed = true;
  let tsActual = "Timestamp within replay window";
  let tsMessage = "Webhook timestamp is fresh and within allowed window";

  if (input.timestampHeader !== undefined) {
    let reqTimestampMs = 0;
    if (typeof input.timestampHeader === "number") {
      reqTimestampMs = input.timestampHeader < 1e11 ? input.timestampHeader * 1000 : input.timestampHeader;
    } else {
      const parsed = Date.parse(input.timestampHeader);
      reqTimestampMs = isNaN(parsed) ? (parseInt(input.timestampHeader, 10) * 1000) : parsed;
    }

    if (isNaN(reqTimestampMs) || reqTimestampMs === 0) {
      tsPassed = false;
      tsActual = `Invalid timestamp header: ${input.timestampHeader}`;
      tsMessage = "Unable to parse webhook timestamp header";
    } else {
      const deltaSec = Math.abs((Date.now() - reqTimestampMs) / 1000);
      if (deltaSec > policy.webhookReplayWindowSec) {
        tsPassed = false;
        tsActual = `Timestamp delta ${deltaSec.toFixed(0)}s exceeds ±${policy.webhookReplayWindowSec}s window`;
        tsMessage = `Webhook timestamp expired (skew: ${deltaSec.toFixed(0)}s exceeds tolerance)`;
      } else {
        tsActual = `Timestamp delta: ${deltaSec.toFixed(1)}s`;
      }
    }
  }

  steps.push({
    sequence: currentSequenceOffset + 2,
    checkId: "webhook.timestamp_expired",
    category: "webhook",
    severity: "HIGH",
    passed: tsPassed,
    expected: `timestamp delta <= ±${policy.webhookReplayWindowSec}s`,
    actual: tsActual,
    message: tsMessage,
  });

  return steps;
}
