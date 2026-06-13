#!/usr/bin/env node
/**
 * mcp-security-scanner CLI
 *
 * Usage:
 *   mcp-security-scanner [options] <config-path-or-url>
 *
 * Options:
 *   --format=json|sarif|table   Output format (default: json)
 *   --output=json|sarif|table   Alias for --format
 *   --exit-code                 Exit 1 on any finding
 *   --fail-on=critical|high|medium|low  Force fail when finding meets severity
 *   --rule=RULE_ID              Run only this rule (can be repeated)
 *   --help, -h                  Show help
 */

import { pathToFileURL } from 'url';
import { scan } from './scanner.js';
import { toSarif } from './sarif.js';
import { ScanConfig, Severity, RuleId, Finding } from './types.js';

const SEVERITY_ORDER: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

function printHelp(): void {
  console.log('Usage: mcp-security-scanner [options] <config-path-or-url>');
  console.log('');
  console.log('Options:');
  console.log('  --format=json|sarif|table   Output format (default: json)');
  console.log('  --output=json|sarif|table   Alias for --format');
  console.log('  --exit-code                 Exit 1 on any finding (regardless of score)');
  console.log('  --fail-on=critical|high|medium|low');
  console.log('                              Force fail when any finding meets this severity');
  console.log('  --rule=RULE_ID              Run only the specified rule (repeatable)');
  console.log('  --help, -h                  Show this help message');
  console.log('');
  console.log('Examples:');
  console.log('  mcp-security-scanner ./mcp-server.json');
  console.log('  mcp-security-scanner --format=table ./mcp-server.json');
  console.log('  mcp-security-scanner --format=sarif --fail-on=high ./mcp-server.json');
  console.log('  mcp-security-scanner --rule=NO_AUTH --rule=MISSING_TLS ./mcp-server.json');
}

function printTable(findings: Finding[], passed: boolean): void {
  const SEVERITY_COL_W = 10;
  const RULEID_COL_W = 30;
  const TITLE_COL_W = 50;
  const sep = '-'.repeat(SEVERITY_COL_W + RULEID_COL_W + TITLE_COL_W + 6);

  // Sort by severity descending
  const sorted = [...findings].sort(
    (a, b) =>
      (SEVERITY_ORDER[b.severity] ?? 0) - (SEVERITY_ORDER[a.severity] ?? 0)
  );

  console.log(sep);
  console.log(
    'SEVERITY'.padEnd(SEVERITY_COL_W) +
    ' | ' +
    'RULE ID'.padEnd(RULEID_COL_W) +
    ' | ' +
    'TITLE'.padEnd(TITLE_COL_W)
  );
  console.log(sep);

  for (const f of sorted) {
    console.log(
      f.severity.toUpperCase().padEnd(SEVERITY_COL_W) +
      ' | ' +
      f.ruleId.padEnd(RULEID_COL_W) +
      ' | ' +
      f.title.slice(0, TITLE_COL_W).padEnd(TITLE_COL_W)
    );
  }

  console.log(sep);

  // Summary counts
  const counts = {
    critical: findings.filter((f) => f.severity === Severity.CRITICAL).length,
    high: findings.filter((f) => f.severity === Severity.HIGH).length,
    medium: findings.filter((f) => f.severity === Severity.MEDIUM).length,
    low: findings.filter((f) => f.severity === Severity.LOW).length,
  };
  console.log(
    `Found ${findings.length} finding(s): ` +
    `${counts.critical} critical, ${counts.high} high, ` +
    `${counts.medium} medium, ${counts.low} low`
  );
  console.log(passed ? 'PASSED' : 'FAILED');
}

/**
 * Successfully parsed CLI arguments.
 */
export interface ParsedArgs {
  format: 'json' | 'sarif' | 'table';
  exitCode: boolean;
  failOn?: Severity;
  rules: RuleId[];
  target?: string;
}

/**
 * Result of parsing CLI arguments: either the parsed args or an error message.
 * Kept side-effect free (no process.exit / console) so it can be unit-tested.
 */
export type ParseArgsResult =
  | { ok: true; args: ParsedArgs }
  | { ok: false; error: string };

/**
 * Parse raw CLI arguments into a normalized {@link ParsedArgs} object.
 *
 * `--output=` is accepted as an alias for `--format=` so the documented
 * quick-start examples (which use `--output=sarif`) work as written.
 */
export function parseArgs(args: string[]): ParseArgsResult {
  let format: 'json' | 'sarif' | 'table' = 'json';
  let exitCode = false;
  let failOn: Severity | undefined;
  const rules: RuleId[] = [];
  let target: string | undefined;

  for (const arg of args) {
    if (arg.startsWith('--format=') || arg.startsWith('--output=')) {
      const flag = arg.startsWith('--format=') ? '--format=' : '--output=';
      const val = arg.slice(flag.length);
      if (val === 'json' || val === 'sarif' || val === 'table') {
        format = val;
      } else {
        return { ok: false, error: `Unknown format "${val}". Expected json, sarif, or table.` };
      }
    } else if (arg === '--exit-code') {
      exitCode = true;
    } else if (arg.startsWith('--fail-on=')) {
      const val = arg.slice('--fail-on='.length).toLowerCase();
      const severityMap: Record<string, Severity> = {
        critical: Severity.CRITICAL,
        high: Severity.HIGH,
        medium: Severity.MEDIUM,
        low: Severity.LOW,
        info: Severity.INFO,
      };
      if (val in severityMap) {
        failOn = severityMap[val];
      } else {
        return { ok: false, error: `Unknown severity "${val}". Expected critical, high, medium, low, or info.` };
      }
    } else if (arg.startsWith('--rule=')) {
      const ruleId = arg.slice('--rule='.length) as RuleId;
      rules.push(ruleId);
    } else if (!arg.startsWith('--')) {
      target = arg;
    } else {
      return { ok: false, error: `Unknown flag "${arg}". Use --help to see available options.` };
    }
  }

  return { ok: true, args: { format, exitCode, failOn, rules, target } };
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);

  if (argv.length === 0 || argv.includes('--help') || argv.includes('-h')) {
    printHelp();
    if (argv.length === 0) process.exit(2);
    return;
  }

  const result = parseArgs(argv);
  if (!result.ok) {
    console.error(`Error: ${result.error}`);
    process.exit(2);
  }

  const { format, exitCode, failOn, rules, target } = result.args;

  if (!target) {
    console.error('Error: No config path or URL provided.');
    console.error('');
    printHelp();
    process.exit(2);
    return;
  }

  const isUrl = target.startsWith('http://') || target.startsWith('https://') ||
                target.startsWith('ws://') || target.startsWith('wss://');

  const scanConfig: ScanConfig = isUrl
    ? { serverUrl: target }
    : { configPath: target };

  if (failOn !== undefined) scanConfig.failOn = failOn;
  if (rules.length > 0) scanConfig.rules = rules;

  try {
    const report = await scan(scanConfig);

    if (format === 'json') {
      console.log(JSON.stringify(report, null, 2));
    } else if (format === 'sarif') {
      const configPath = isUrl ? undefined : target;
      console.log(JSON.stringify(toSarif(report, configPath), null, 2));
    } else {
      printTable(report.findings, report.passed);
    }

    const shouldFail =
      !report.passed ||
      (exitCode && report.findings.length > 0);

    if (shouldFail) {
      process.exit(1);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`Error: ${message}`);
    process.exit(2);
  }
}

// Only run when invoked directly as the CLI binary, not when imported (e.g. in tests).
const invokedPath = process.argv[1];
if (invokedPath && import.meta.url === pathToFileURL(invokedPath).href) {
  main();
}
