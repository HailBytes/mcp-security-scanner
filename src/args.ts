/**
 * CLI argument parsing for mcp-security-scanner.
 *
 * Kept free of side effects (no console output, no process.exit, no top-level
 * execution) so it can be unit-tested directly. `cli.ts` consumes the result
 * and is responsible for all I/O and exit codes.
 */

import { ScanConfig, Severity, RuleId } from './types.js';

export type OutputFormat = 'json' | 'sarif' | 'table';

/**
 * Result of parsing argv. A discriminated union so the caller can decide how
 * to render output and which exit code to use.
 */
export type ParseResult =
  | { kind: 'help'; exitCode: 0 | 2 }
  | { kind: 'error'; message: string; showHelp: boolean }
  | {
      kind: 'run';
      scanConfig: ScanConfig;
      format: OutputFormat;
      exitCode: boolean;
      target: string;
      isUrl: boolean;
    };

/** All valid rule identifiers, for validating the `--rule` flag. */
export const VALID_RULE_IDS: ReadonlySet<string> = new Set<string>(
  Object.values(RuleId)
);

const SEVERITY_MAP: Record<string, Severity> = {
  critical: Severity.CRITICAL,
  high: Severity.HIGH,
  medium: Severity.MEDIUM,
  low: Severity.LOW,
  info: Severity.INFO,
};

function isUrlTarget(target: string): boolean {
  return (
    target.startsWith('http://') ||
    target.startsWith('https://') ||
    target.startsWith('ws://') ||
    target.startsWith('wss://')
  );
}

/**
 * Parse CLI arguments (everything after `node cli.js`).
 *
 * Validates `--format`, `--fail-on`, and `--rule` and surfaces unknown values
 * as `error` results rather than silently ignoring them — an invalid value
 * must never produce a passing scan.
 */
export function parseArgs(args: string[]): ParseResult {
  if (args.length === 0) return { kind: 'help', exitCode: 2 };
  if (args.includes('--help') || args.includes('-h')) {
    return { kind: 'help', exitCode: 0 };
  }

  let format: OutputFormat = 'json';
  let exitCode = false;
  let failOn: Severity | undefined;
  const rules: RuleId[] = [];
  let target: string | undefined;

  for (const arg of args) {
    if (arg.startsWith('--format=')) {
      const val = arg.slice('--format='.length);
      if (val === 'json' || val === 'sarif' || val === 'table') {
        format = val;
      } else {
        return {
          kind: 'error',
          message: `Unknown format "${val}". Expected json, sarif, or table.`,
          showHelp: false,
        };
      }
    } else if (arg === '--exit-code') {
      exitCode = true;
    } else if (arg.startsWith('--fail-on=')) {
      const val = arg.slice('--fail-on='.length).toLowerCase();
      if (val in SEVERITY_MAP) {
        failOn = SEVERITY_MAP[val];
      } else {
        return {
          kind: 'error',
          message: `Unknown severity "${val}". Expected critical, high, medium, low, or info.`,
          showHelp: false,
        };
      }
    } else if (arg.startsWith('--rule=')) {
      const ruleId = arg.slice('--rule='.length);
      if (!VALID_RULE_IDS.has(ruleId)) {
        return {
          kind: 'error',
          message: `Unknown rule "${ruleId}". Use --help to see valid rule IDs.`,
          showHelp: false,
        };
      }
      rules.push(ruleId as RuleId);
    } else if (!arg.startsWith('--')) {
      target = arg;
    } else {
      return {
        kind: 'error',
        message: `Unknown flag "${arg}". Use --help to see available options.`,
        showHelp: false,
      };
    }
  }

  if (!target) {
    return { kind: 'error', message: 'No config path or URL provided.', showHelp: true };
  }

  const isUrl = isUrlTarget(target);
  const scanConfig: ScanConfig = isUrl ? { serverUrl: target } : { configPath: target };
  if (failOn !== undefined) scanConfig.failOn = failOn;
  if (rules.length > 0) scanConfig.rules = rules;

  return { kind: 'run', scanConfig, format, exitCode, target, isUrl };
}
