import { ScanConfig, SecurityReport, Finding, RuleId, Severity } from './types.js';
import { parseConfig } from './parser.js';
import { getAllRules } from './rules/index.js';
import { computeScore, computeSummary } from './scorer.js';

/**
 * Severity ordering for failOn comparison.
 * Higher number = higher severity.
 */
const SEVERITY_ORDER: Record<Severity, number> = {
  [Severity.INFO]: 0,
  [Severity.LOW]: 1,
  [Severity.MEDIUM]: 2,
  [Severity.HIGH]: 3,
  [Severity.CRITICAL]: 4,
};

/**
 * Scan an MCP server configuration for security issues.
 *
 * @param config - Scan configuration (file path, server URL, and optional rule filters).
 * @returns A SecurityReport with findings, a risk score, and pass/fail status.
 */
export async function scan(config: ScanConfig): Promise<SecurityReport> {
  const startMs = Date.now();
  const scannedAt = new Date().toISOString();

  const parsedConfig = await parseConfig(config);

  let rules = getAllRules();

  // Filter to specific rule IDs if requested
  if (config.rules && config.rules.length > 0) {
    const ruleSet = new Set<RuleId>(config.rules);
    rules = rules.filter((r) => ruleSet.has(r.id));
  }

  const findings: Finding[] = [];
  for (const rule of rules) {
    const ruleFindings = rule.check(parsedConfig);
    findings.push(...ruleFindings);
  }

  const score = computeScore(findings);
  const summary = computeSummary(findings);
  const hasCritical = summary.critical > 0;
  let passed = score < 50 && !hasCritical;

  // Honour failOn: force passed=false if any finding meets or exceeds the threshold
  if (config.failOn !== undefined) {
    const threshold = SEVERITY_ORDER[config.failOn];
    const hasFailingFinding = findings.some(
      (f) => SEVERITY_ORDER[f.severity] >= threshold
    );
    if (hasFailingFinding) {
      passed = false;
    }
  }

  const durationMs = Date.now() - startMs;

  return {
    findings,
    score,
    passed,
    summary,
    scannedAt,
    durationMs,
  };
}
