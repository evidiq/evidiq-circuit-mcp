import { CircuitTraceStep } from "./report.js";
import { CircuitPolicyConfig, DEFAULT_POLICY_CONFIG } from "./policy.js";

export type BreakerState = "CLOSED" | "HALF_OPEN" | "OPEN";

export interface BreakerMetrics {
  targetHost: string;
  totalCalls: number;
  errorCalls: number;          // 5xx error count over errorRateWindowMs
  latencyP95Ms: number;
  state?: BreakerState;
}

// In-memory breaker metrics storage for active targets
const HOST_METRICS = new Map<string, {
  state: BreakerState;
  calls: number;
  errors: number;
  latencies: number[];
  lastStateChangeMs: number;
}>();

export function getBreakerState(host: string): BreakerState {
  const data = HOST_METRICS.get(host);
  if (!data) return "CLOSED";
  return data.state;
}

export function evaluateCircuitBreaker(
  metrics: BreakerMetrics,
  policy: CircuitPolicyConfig = DEFAULT_POLICY_CONFIG,
  currentSequenceOffset: number = 7
): { steps: CircuitTraceStep[]; breakerState: BreakerState } {
  const steps: CircuitTraceStep[] = [];
  const host = metrics.targetHost;

  let currentData = HOST_METRICS.get(host);
  if (!currentData) {
    currentData = {
      state: metrics.state || "CLOSED",
      calls: metrics.totalCalls || 0,
      errors: metrics.errorCalls || 0,
      latencies: metrics.latencyP95Ms ? [metrics.latencyP95Ms] : [],
      lastStateChangeMs: Date.now(),
    };
    HOST_METRICS.set(host, currentData);
  } else if (metrics.state) {
    currentData.state = metrics.state;
  }

  const total = Math.max(metrics.totalCalls, 1);
  const errorPct = (metrics.errorCalls / total) * 100;

  // Step 8: circuit.error_rate_exceeded
  const errorRatePassed = errorPct <= policy.errorRateThresholdPct && currentData.state !== "OPEN";
  let breakerState: BreakerState = currentData.state;

  if (!errorRatePassed) {
    breakerState = "OPEN";
    currentData.state = "OPEN";
    currentData.lastStateChangeMs = Date.now();
  }

  steps.push({
    sequence: currentSequenceOffset + 1,
    checkId: "circuit.error_rate_exceeded",
    category: "breaker",
    severity: "HIGH",
    passed: errorRatePassed,
    expected: `errorRate <= ${policy.errorRateThresholdPct}%`,
    actual: `errorRate: ${errorPct.toFixed(1)}% (${metrics.errorCalls}/${total} calls); state: ${breakerState}`,
    message: errorRatePassed
      ? `Circuit breaker operating normally (${errorPct.toFixed(1)}% error rate)`
      : `Circuit breaker tripped to OPEN state (error rate ${errorPct.toFixed(1)}% exceeds ${policy.errorRateThresholdPct}% ceiling)`,
  });

  // Step 9: circuit.latency_p95_exceeded
  const latencyPassed = metrics.latencyP95Ms <= policy.latencyP95CeilingMs;
  steps.push({
    sequence: currentSequenceOffset + 2,
    checkId: "circuit.latency_p95_exceeded",
    category: "breaker",
    severity: "MEDIUM",
    passed: latencyPassed,
    expected: `latencyP95 <= ${policy.latencyP95CeilingMs}ms`,
    actual: `latencyP95: ${metrics.latencyP95Ms}ms`,
    message: latencyPassed
      ? `P95 latency is within SLA ceiling (${metrics.latencyP95Ms}ms)`
      : `P95 latency spike (${metrics.latencyP95Ms}ms exceeds ${policy.latencyP95CeilingMs}ms SLA ceiling)`,
  });

  return { steps, breakerState };
}
