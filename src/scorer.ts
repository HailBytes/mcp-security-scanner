import { Finding, Severity } from './types.js';

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  [Severity.CRITICAL]: 25,
  [Severity.HIGH]: 15,
  [Severity.MEDIUM]: 8,
  [Severity.LOW]: 3,
  [Severity.INFO]: 0,
};

/**
 * Compute a risk score from 0–100 based on findings.
 * Higher score = more risk.
 */
export function computeScore(findings: Finding[]): number {
  const total = findings.reduce((sum, f) => sum + SEVERITY_WEIGHTS[f.severity], 0);
  return Math.min(100, total);
}

/**
 * Compute a summary count of findings by severity.
 */
export function computeSummary(findings: Finding[]): {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
} {
  return {
    critical: findings.filter((f) => f.severity === Severity.CRITICAL).length,
    high: findings.filter((f) => f.severity === Severity.HIGH).length,
    medium: findings.filter((f) => f.severity === Severity.MEDIUM).length,
    low: findings.filter((f) => f.severity === Severity.LOW).length,
    info: findings.filter((f) => f.severity === Severity.INFO).length,
  };
}
