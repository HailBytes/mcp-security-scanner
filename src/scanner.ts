import { ScanConfig, SecurityReport, Finding, RuleId } from './types.js';
import { parseConfig } from './parser.js';
import { getAllRules } from './rules/index.js';
import { computeScore, computeSummary } from './scorer.js';

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
  const passed = score < 50 && !hasCritical;
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
