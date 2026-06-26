/**
 * Pure CLI exit-status logic for mcp-security-scanner.
 *
 * Kept free of side effects (no process.exit / console calls) so it can be
 * unit-tested directly, separate from the executable entry point in cli.ts.
 */

import { SecurityReport, Severity } from './types.js';

/**
 * Decide whether the CLI should exit with a non-zero status.
 *
 * The gate fails when either:
 *  - the scan did not pass (`report.passed` already accounts for the score,
 *    critical findings, and any `--fail-on` threshold), or
 *  - `--exit-code` was given and there is at least one *actionable* finding.
 *
 * Informational notes (INFO severity — e.g. the `URL_SCAN_LIMITED` note emitted
 * for every URL scan) are not vulnerabilities and must never trip the gate.
 * Counting them as "findings" would fail CI on every secure `https://`/`wss://`
 * endpoint, directly contradicting the report's own `passed: true`.
 */
export function shouldExitNonZero(
  report: SecurityReport,
  exitCodeFlag: boolean
): boolean {
  if (!report.passed) return true;
  if (!exitCodeFlag) return false;
  return report.findings.some((f) => f.severity !== Severity.INFO);
}
