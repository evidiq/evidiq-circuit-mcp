import crypto from "crypto";
import { privateKeyToAccount } from "viem/accounts";
import { hashMessage, recoverAddress } from "viem";

export type SeverityLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type EvaluationVerdict = "ALLOW" | "WARN" | "BLOCK";

export interface CircuitTraceStep {
  sequence: number;          // Strictly contiguous 1-indexed execution order (1, 2, 3...) following Rule Mapping (§6)
  checkId: string;
  category: "tls" | "schema" | "breaker" | "webhook" | "headers";
  severity: SeverityLevel;
  passed: boolean;
  expected: string;
  actual: string;
  message: string;
}

export interface CircuitViolation {
  ruleId: string;
  severity: SeverityLevel;
  action: "BLOCK" | "WARN";
  message: string;
  fieldPath?: string;
}

export interface CircuitMetadata {
  executionId: string;       // Formatted as "circuit_exec_<timestamp_ms>_<hashprefix8>"
  targetHost: string;
  targetUrl: string;
  checksEvaluated: number;   // Total trace checks executed (must equal trace.length)
  policyVersion: string;
  evaluationTimeMs: number;
  evaluationQuality: "FULL" | "DEGRADED";
  engineVersion: string;
  timestamp: string;         // ISO 8601 UTC string
}

export interface CircuitReceipt {
  reportDigest: string;      // 0x-prefixed 64-char hex SHA-256 string
  verdict: EvaluationVerdict;
  signerAddress: string;     // 0x-prefixed 40-char EVM address
  signature: string;         // EIP-191 signature (0x-prefixed 130-char hex)
  zeroGAnchorTx?: string;
  zeroGStorageRoot?: string;
}

export interface CircuitReport {
  metadata: CircuitMetadata;
  verdict: EvaluationVerdict;
  trace: CircuitTraceStep[];
  violations: CircuitViolation[];
  receipt: CircuitReceipt;
}

/**
 * RFC 8785 Canonical JSON Serialization (JCS)
 * Sorts object keys recursively by UTF-8 code point order.
 */
export function canonicalJsonStringify(obj: any): string {
  if (obj === null || typeof obj !== "object") {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    return "[" + obj.map((item) => canonicalJsonStringify(item)).join(",") + "]";
  }

  const sortedKeys = Object.keys(obj).sort((a, b) => {
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
  });

  const parts = sortedKeys.map((key) => {
    const val = obj[key];
    return `${JSON.stringify(key)}:${canonicalJsonStringify(val)}`;
  });

  return "{" + parts.join(",") + "}";
}

/**
 * Computes reportDigest = SHA-256(JCS(report \ {reportDigest, signature}))
 */
export function computeReportDigest(report: Omit<CircuitReport, "receipt"> & { receipt: Omit<CircuitReceipt, "reportDigest" | "signature"> }): string {
  const reportForHashing = {
    metadata: report.metadata,
    verdict: report.verdict,
    trace: report.trace,
    violations: report.violations,
    receipt: {
      verdict: report.receipt.verdict,
      signerAddress: report.receipt.signerAddress,
      zeroGAnchorTx: report.receipt.zeroGAnchorTx,
      zeroGStorageRoot: report.receipt.zeroGStorageRoot,
    },
  };

  const canonicalJson = canonicalJsonStringify(reportForHashing);
  const hashHex = crypto.createHash("sha256").update(canonicalJson, "utf-8").digest("hex");
  return "0x" + hashHex;
}

/**
 * Generate complete CircuitReport from trace steps, metadata input, and signing key.
 */
export async function createCircuitReport(params: {
  targetUrl: string;
  trace: CircuitTraceStep[];
  signerPrivateKey?: string;
  evaluationStartTimeMs: number;
  zeroGAnchorTx?: string;
  zeroGStorageRoot?: string;
}): Promise<CircuitReport> {
  const evaluationTimeMs = Date.now() - params.evaluationStartTimeMs;
  const timestamp = new Date().toISOString();
  const url = new URL(params.targetUrl);

  // Ensure sequence numbers in trace are strictly contiguous 1..N
  const orderedTrace: CircuitTraceStep[] = params.trace.map((step, idx) => ({
    ...step,
    sequence: idx + 1,
  }));

  // Deriving violations from failed trace steps
  const violations: CircuitViolation[] = orderedTrace
    .filter((step) => !step.passed)
    .map((step) => {
      const isBlock = step.severity === "CRITICAL" || step.severity === "HIGH";
      return {
        ruleId: step.checkId,
        severity: step.severity,
        action: isBlock ? "BLOCK" : "WARN",
        message: step.message,
      };
    });

  // Verdict Precedence Contract (§5.B)
  let verdict: EvaluationVerdict = "ALLOW";
  if (violations.some((v) => v.action === "BLOCK")) {
    verdict = "BLOCK";
  } else if (violations.some((v) => v.action === "WARN")) {
    verdict = "WARN";
  }

  // Generate executionId: circuit_exec_<timestamp_ms>_<hashprefix8>
  const executionHashPrefix = crypto
    .createHash("sha256")
    .update(`${params.targetUrl}_${timestamp}_${Math.random()}`)
    .digest("hex")
    .substring(0, 8);
  const executionId = `circuit_exec_${Date.now()}_${executionHashPrefix}`;

  const metadata: CircuitMetadata = {
    executionId,
    targetHost: url.hostname,
    targetUrl: params.targetUrl,
    checksEvaluated: orderedTrace.length,
    policyVersion: "v1.0.0",
    evaluationTimeMs,
    evaluationQuality: "FULL",
    engineVersion: "1.0.0",
    timestamp,
  };

  // Signer account setup (ensure 0x prefix)
  let rawPk = params.signerPrivateKey || process.env.CIRCUIT_SIGNER_PRIVATE_KEY || "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
  if (!rawPk.startsWith("0x")) {
    rawPk = `0x${rawPk}`;
  }
  const account = privateKeyToAccount(rawPk as `0x${string}`);

  const partialReceipt: Omit<CircuitReceipt, "reportDigest" | "signature"> = {
    verdict,
    signerAddress: account.address,
    zeroGAnchorTx: params.zeroGAnchorTx,
    zeroGStorageRoot: params.zeroGStorageRoot,
  };

  const reportDigest = computeReportDigest({
    metadata,
    verdict,
    trace: orderedTrace,
    violations,
    receipt: partialReceipt,
  });

  // EIP-191 Personal Sign over binary reportDigest
  const signature = await account.signMessage({
    message: { raw: reportDigest as `0x${string}` },
  });

  const fullReceipt: CircuitReceipt = {
    ...partialReceipt,
    reportDigest,
    signature,
  };

  return {
    metadata,
    verdict,
    trace: orderedTrace,
    violations,
    receipt: fullReceipt,
  };
}

/**
 * Offline verification of CircuitReport against all 4 mathematical invariants (§9)
 */
export async function verifyCircuitReport(report: CircuitReport): Promise<{ valid: boolean; errors: string[] }> {
  const errors: string[] = [];

  // Invariant 1: Trace Consistency
  if (report.metadata.checksEvaluated !== report.trace.length) {
    errors.push(`Invariant #1 failed: metadata.checksEvaluated (${report.metadata.checksEvaluated}) != trace.length (${report.trace.length})`);
  }

  // Invariant 2: Violation Count
  const failedTraceCount = report.trace.filter((t) => !t.passed).length;
  if (report.violations.length !== failedTraceCount) {
    errors.push(`Invariant #2 failed: violations.length (${report.violations.length}) != failed trace count (${failedTraceCount})`);
  }

  // Invariant 3: Verdict Determinism
  const hasBlockViolation = report.violations.some((v) => v.action === "BLOCK");
  if ((report.verdict === "BLOCK") !== hasBlockViolation) {
    errors.push(`Invariant #3 failed: verdict (${report.verdict}) does not match violation actions (hasBlock: ${hasBlockViolation})`);
  }

  // Invariant 4: Integrity Digest & EIP-191 Signature Verification
  const expectedDigest = computeReportDigest(report);
  if (report.receipt.reportDigest !== expectedDigest) {
    errors.push(`Invariant #4 failed: receipt.reportDigest (${report.receipt.reportDigest}) != computed digest (${expectedDigest})`);
  }

  try {
    const recoveredAddr = await recoverAddress({
      hash: hashMessage({ raw: report.receipt.reportDigest as `0x${string}` }),
      signature: report.receipt.signature as `0x${string}`,
    });

    if (recoveredAddr.toLowerCase() !== report.receipt.signerAddress.toLowerCase()) {
      errors.push(`Signature mismatch: recovered signer ${recoveredAddr} != claimed signer ${report.receipt.signerAddress}`);
    }
  } catch (err: any) {
    errors.push(`Signature verification failed: ${err.message || String(err)}`);
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}
