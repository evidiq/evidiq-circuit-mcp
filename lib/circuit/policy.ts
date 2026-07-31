export interface CircuitPolicyConfig {
  latencyP95CeilingMs: number;     // default: 2500
  errorRateThresholdPct: number;   // default: 15
  errorRateWindowMs: number;       // default: 300000 (5 minutes)
  webhookReplayWindowSec: number;  // default: 300 (±300 seconds)
  breakerHalfOpenProbes: number;   // default: 3
}

export const DEFAULT_POLICY_CONFIG: CircuitPolicyConfig = {
  latencyP95CeilingMs: 2500,
  errorRateThresholdPct: 15,
  errorRateWindowMs: 300000,
  webhookReplayWindowSec: 300,
  breakerHalfOpenProbes: 3,
};
