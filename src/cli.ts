#!/usr/bin/env node
/**
 * mcp-security-scanner CLI
 *
 * Usage:
 *   mcp-security-scanner [options] <config-path-or-url>
 *
 * Options:
 *   --format=json|sarif|table   Output format (default: json)
 *   --exit-code                 Exit 1 on any finding
 *   --fail-on=critical|high|medium|low  Force fail when finding meets severity
 *   --rule=RULE_ID              Run only this rule (can be repeated)
 *   --help, -h                  Show help
 */

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

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    printHelp();
    if (args.length === 0) process.exit(2);
    return;
  }

  let format: 'json' | 'sarif' | 'table' = 'json';
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
        console.error(`Error: Unknown format "${val}". Expected json, sarif, or table.`);
        process.exit(2);
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
        console.error(`Error: Unknown severity "${val}". Expected critical, high, medium, low, or info.`);
        process.exit(2);
      }
    } else if (arg.startsWith('--rule=')) {
      const ruleId = arg.slice('--rule='.length) as RuleId;
      rules.push(ruleId);
    } else if (!arg.startsWith('--')) {
      target = arg;
    } else {
      console.error(`Error: Unknown flag "${arg}". Use --help to see available options.`);
      process.exit(2);
    }
  }

  if (!target) {
    console.error('Error: No config path or URL provided.');
    console.error('');
    printHelp();
    process.exit(2);
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

main();
