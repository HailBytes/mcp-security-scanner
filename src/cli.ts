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

import { scan } from './scanner.js';
import { toSarif } from './sarif.js';
import { Severity, Finding, RuleId } from './types.js';
import { parseArgs } from './args.js';
import { shouldExitNonZero } from './exit.js';

/** Selectable rule IDs (excludes the URL_SCAN_LIMITED informational note). */
const VALID_RULE_IDS = Object.values(RuleId).filter(
  (id) => id !== RuleId.URL_SCAN_LIMITED
);

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
  console.log('Valid rule IDs:');
  for (const id of VALID_RULE_IDS) {
    console.log(`  ${id}`);
  }
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
  const parsed = parseArgs(process.argv.slice(2));

  if (parsed.kind === 'help') {
    printHelp();
    process.exit(parsed.exitCode);
  }

  if (parsed.kind === 'error') {
    console.error(parsed.message);
    if (parsed.message.includes('No config path')) {
      console.error('');
      printHelp();
    }
    process.exit(parsed.exitCode);
  }

  const { target, isUrl, format, exitCode, scanConfig } = parsed;

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

    if (shouldExitNonZero(report, exitCode)) {
      process.exit(1);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`Error: ${message}`);
    process.exit(2);
  }
}

main();
