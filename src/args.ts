/**
 * Pure CLI argument parsing for mcp-security-scanner.
 *
 * Kept free of side effects (no process.exit / console calls) so it can be
 * unit-tested directly, separate from the executable entry point in cli.ts.
 */

import { ScanConfig, SecurityReport, Severity, RuleId } from './types.js';

export type OutputFormat = 'json' | 'sarif' | 'table';

/**
 * Result of parsing CLI arguments.
 *
 * - `run`   — arguments are valid; proceed with a scan.
 * - `help`  — show usage and exit with `exitCode`.
 * - `error` — invalid arguments; print `message` to stderr and exit with `exitCode`.
 */
export type CliParseResult =
  | {
      kind: 'run';
      target: string;
      isUrl: boolean;
      format: OutputFormat;
      exitCode: boolean;
      scanConfig: ScanConfig;
    }
  | { kind: 'help'; exitCode: number }
  | { kind: 'error'; message: string; exitCode: number };

/**
 * Rule IDs accepted by `--rule`. URL_SCAN_LIMITED is excluded — it is an
 * informational note synthesized in URL mode, not a selectable rule.
 */
const VALID_RULE_IDS = new Set<string>(
  Object.values(RuleId).filter((id) => id !== RuleId.URL_SCAN_LIMITED)
);
const VALID_RULE_IDS_LIST = Array.from(VALID_RULE_IDS).join(', ');

const SEVERITY_BY_NAME: Record<string, Severity> = {
  critical: Severity.CRITICAL,
  high: Severity.HIGH,
  medium: Severity.MEDIUM,
  low: Severity.LOW,
  info: Severity.INFO,
};

/**
 * Parse raw CLI arguments into a structured, side-effect-free result.
 */
export function parseArgs(args: string[]): CliParseResult {
  if (args.length === 0) {
    return { kind: 'help', exitCode: 2 };
  }
  if (args.includes('--help') || args.includes('-h')) {
    return { kind: 'help', exitCode: 0 };
  }

  let format: OutputFormat = 'json';
  let exitCode = false;
  let failOn: Severity | undefined;
  const rules: RuleId[] = [];
  let target: string | undefined;

  for (const arg of args) {
    // `--output` is a documented alias for `--format`.
    if (arg.startsWith('--format=') || arg.startsWith('--output=')) {
      const val = arg.slice(arg.indexOf('=') + 1);
      if (val === 'json' || val === 'sarif' || val === 'table') {
        format = val;
      } else {
        return {
          kind: 'error',
          message: `Error: Unknown format "${val}". Expected json, sarif, or table.`,
          exitCode: 2,
        };
      }
    } else if (arg === '--exit-code') {
      exitCode = true;
    } else if (arg.startsWith('--fail-on=')) {
      const val = arg.slice('--fail-on='.length).toLowerCase();
      if (val in SEVERITY_BY_NAME) {
        failOn = SEVERITY_BY_NAME[val];
      } else {
        return {
          kind: 'error',
          message: `Error: Unknown severity "${val}". Expected critical, high, medium, low, or info.`,
          exitCode: 2,
        };
      }
    } else if (arg.startsWith('--rule=')) {
      const ruleId = arg.slice('--rule='.length);
      if (!VALID_RULE_IDS.has(ruleId)) {
        return {
          kind: 'error',
          message:
            `Error: Unknown rule "${ruleId}". Valid rule IDs: ${VALID_RULE_IDS_LIST}.`,
          exitCode: 2,
        };
      }
      rules.push(ruleId as RuleId);
    } else if (!arg.startsWith('--')) {
      target = arg;
    } else {
      return {
        kind: 'error',
        message: `Error: Unknown flag "${arg}". Use --help to see available options.`,
        exitCode: 2,
      };
    }
  }

  if (!target) {
    return {
      kind: 'error',
      message: 'Error: No config path or URL provided.',
      exitCode: 2,
    };
  }

  const isUrl =
    target.startsWith('http://') ||
    target.startsWith('https://') ||
    target.startsWith('ws://') ||
    target.startsWith('wss://');

  const scanConfig: ScanConfig = isUrl ? { serverUrl: target } : { configPath: target };
  if (failOn !== undefined) scanConfig.failOn = failOn;
  if (rules.length > 0) scanConfig.rules = rules;

  return { kind: 'run', target, isUrl, format, exitCode, scanConfig };
}

/**
 * Decide whether the CLI should exit with a non-zero (failure) status.
 *
 * A scan fails the gate when the report did not pass, OR when `--exit-code` is
 * set and the scan produced at least one *actionable* finding. INFO-severity
 * findings are informational notes — e.g. `URL_SCAN_LIMITED`, which `types.ts`
 * documents as "Not a vulnerability — INFO severity, never fails a gate" — so
 * they are excluded from the `--exit-code` count.
 *
 * Without this exclusion, `--exit-code` would exit 1 on a secure `https://` /
 * `wss://` endpoint solely because URL mode always emits the INFO note, even
 * though the report itself reports `passed: true`. That contradicts both the
 * documented meaning of the note and the report's own pass/fail verdict.
 */
export function shouldExitNonZero(
  report: SecurityReport,
  exitCodeFlag: boolean
): boolean {
  if (!report.passed) return true;
  if (!exitCodeFlag) return false;
  return report.findings.some((f) => f.severity !== Severity.INFO);
}
