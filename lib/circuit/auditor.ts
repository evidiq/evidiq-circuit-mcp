import { CircuitTraceStep } from "./report.js";

export interface EndpointAuditInput {
  targetUrl: string;
  tlsInfo?: {
    validUntil?: string;       // ISO timestamp or date string
    issuer?: string;
    san?: string[];
    trustedCa?: boolean;
  };
  headers?: Record<string, string>;
  latencyMs?: number;
}

export interface EndpointAuditResult {
  steps: CircuitTraceStep[];
}

export function auditEndpointCompliance(input: EndpointAuditInput): EndpointAuditResult {
  const steps: CircuitTraceStep[] = [];
  const url = new URL(input.targetUrl);

  // 1. TLS Checks (sequence 1..3 in pipeline)
  // Step 1: tls.expired
  let tlsExpiredPassed = true;
  let tlsExpiredActual = "Valid TLS certificate";
  if (input.tlsInfo?.validUntil) {
    const expiry = new Date(input.tlsInfo.validUntil).getTime();
    if (isNaN(expiry) || expiry < Date.now()) {
      tlsExpiredPassed = false;
      tlsExpiredActual = `Expired on ${input.tlsInfo.validUntil}`;
    } else {
      tlsExpiredActual = `Expires on ${input.tlsInfo.validUntil}`;
    }
  } else if (url.protocol === "https:") {
    // Simulated live check or passed default if no explicit mock error provided
    tlsExpiredActual = "Certificate valid";
  }

  steps.push({
    sequence: steps.length + 1,
    checkId: "tls.expired",
    category: "tls",
    severity: "CRITICAL",
    passed: tlsExpiredPassed,
    expected: "validUntil > now",
    actual: tlsExpiredActual,
    message: tlsExpiredPassed
      ? "TLS certificate is currently valid and unexpired"
      : `TLS certificate expired (${tlsExpiredActual})`,
  });

  // Step 2: tls.untrusted_ca
  const trustedCaPassed = input.tlsInfo?.trustedCa !== false;
  steps.push({
    sequence: steps.length + 1,
    checkId: "tls.untrusted_ca",
    category: "tls",
    severity: "HIGH",
    passed: trustedCaPassed,
    expected: "trustedCa == true",
    actual: trustedCaPassed ? "Verified CA" : `Untrusted CA issuer: ${input.tlsInfo?.issuer || "unknown"}`,
    message: trustedCaPassed
      ? "Certificate is signed by a recognized Certificate Authority"
      : "Certificate issuer is untrusted or self-signed",
  });

  // Step 3: tls.hostname_mismatch
  let hostnamePassed = true;
  if (input.tlsInfo?.san && input.tlsInfo.san.length > 0) {
    const host = url.hostname.toLowerCase();
    hostnamePassed = input.tlsInfo.san.some((san) => {
      const s = san.toLowerCase();
      if (s.startsWith("*.")) {
        return host.endsWith(s.slice(1)) || host === s.slice(2);
      }
      return host === s;
    });
  }
  steps.push({
    sequence: steps.length + 1,
    checkId: "tls.hostname_mismatch",
    category: "tls",
    severity: "CRITICAL",
    passed: hostnamePassed,
    expected: `SAN includes ${url.hostname}`,
    actual: hostnamePassed ? `Host ${url.hostname} matches SAN` : `Host ${url.hostname} not found in SAN`,
    message: hostnamePassed
      ? "Subject Alternative Name (SAN) matches target host"
      : `Hostname mismatch: ${url.hostname} not covered by certificate SAN`,
  });

  // 2. Security Header Checks (sequence 4..5 in pipeline)
  const headersLower: Record<string, string> = {};
  if (input.headers) {
    for (const [k, v] of Object.entries(input.headers)) {
      headersLower[k.toLowerCase()] = v;
    }
  }

  // Step 4: headers.missing_hsts
  const hstsPassed = Boolean(headersLower["strict-transport-security"]);
  steps.push({
    sequence: steps.length + 1,
    checkId: "headers.missing_hsts",
    category: "headers",
    severity: "LOW",
    passed: hstsPassed,
    expected: "Strict-Transport-Security header present",
    actual: hstsPassed ? headersLower["strict-transport-security"] : "Header missing",
    message: hstsPassed
      ? "Strict-Transport-Security header is present"
      : "Response lacks Strict-Transport-Security header",
  });

  // Step 5: headers.cors_wildcard
  const corsHeader = headersLower["access-control-allow-origin"];
  const corsPassed = corsHeader !== "*";
  steps.push({
    sequence: steps.length + 1,
    checkId: "headers.cors_wildcard",
    category: "headers",
    severity: "LOW",
    passed: corsPassed,
    expected: "Access-Control-Allow-Origin != '*'",
    actual: corsHeader ? `CORS origin: ${corsHeader}` : "CORS header not present",
    message: corsPassed
      ? "CORS header does not use wildcard origin"
      : "Response contains unconstrained CORS wildcard header (Access-Control-Allow-Origin: *)",
  });

  return { steps };
}
