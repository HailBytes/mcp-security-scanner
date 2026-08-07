/**
 * Pure exit-code policy for the mcp-security-scanner CLI.
 *
 * Kept free of side effects (no process.exit / console calls) so it can be
 * unit-tested directly, separate from the executable entry point in cli.ts —
 * mirroring the split between args.ts and cli.ts.
 */

import { SecurityReport, Severity } from './types.js';

/**
 * Decide whether the CLI should exit non-zero for a completed scan.
 *
 * The process fails when either:
 *  - the report did not pass the gate (`report.passed === false`), or
 *  - `--exit-code` was given AND the scan produced at least one *actionable*
 *    finding.
 *
 * INFO-severity entries are informational, not vulnerabilities, and must never
 * fail a gate. The `URL_SCAN_LIMITED` note is the concrete case: scanning a
 * secure `https://` / `wss://` endpoint produces only that INFO note, so the
 * report PASSES — but a naive "any finding" check would count the note and exit
 * 1, contradicting the PASSED result and breaking the documented CI gate on the
 * advertised URL-scan path.
 *
 * @param report   - The completed scan report.
 * @param exitCode - Whether the `--exit-code` flag was supplied.
 * @returns true if the process should exit with a non-zero status.
 */
export function shouldFailExit(report: SecurityReport, exitCode: boolean): boolean {
  if (!report.passed) return true;
  if (!exitCode) return false;
  return report.findings.some((f) => f.severity !== Severity.INFO);
}
