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
 * Rules that can be meaningfully evaluated from a URL alone, without a config
 * file or live introspection. In URL mode only these run — the remaining rules
 * have no data to inspect, so reporting their missing inputs as findings would
 * be a false positive on every endpoint.
 */
const URL_EVALUABLE_RULES = new Set<RuleId>([
  RuleId.MISSING_TLS,
  RuleId.INSECURE_TRANSPORT,
]);

/**
 * Informational note emitted in URL mode explaining that live introspection is
 * not performed and that a config file is required for the full rule set.
 */
function urlScanLimitedNote(): Finding {
  return {
    ruleId: RuleId.URL_SCAN_LIMITED,
    severity: Severity.INFO,
    title: 'URL Scan — Transport Checks Only',
    description:
      'A URL/endpoint was scanned. URL mode does not connect to or introspect ' +
      'the live server; it only evaluates transport security derivable from the ' +
      'URL itself (TLS / WebSocket scheme). Authentication, rate limiting, CORS, ' +
      'tool, and secret rules require a config file to evaluate.',
    remediation:
      'To run the full rule set, scan the MCP server configuration file ' +
      '(.json/.yaml) instead of, or in addition to, the URL.',
    docsUrl: 'https://hailbytes.com/mcp/docs/rules/URL_SCAN_LIMITED',
  };
}

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

  // URL mode: a live URL was given with no config file. Only transport rules
  // are evaluable; the rest would report missing config data as false findings.
  const isUrlMode = Boolean(config.serverUrl) && !config.configPath;

  let rules = getAllRules();

  // Filter to specific rule IDs if requested
  if (config.rules && config.rules.length > 0) {
    const ruleSet = new Set<RuleId>(config.rules);
    rules = rules.filter((r) => ruleSet.has(r.id));
  }

  // In URL mode, restrict to the rules a URL can actually answer.
  if (isUrlMode) {
    rules = rules.filter((r) => URL_EVALUABLE_RULES.has(r.id));
  }

  const findings: Finding[] = [];
  for (const rule of rules) {
    const ruleFindings = rule.check(parsedConfig);
    findings.push(...ruleFindings);
  }

  // Surface, as a non-failing INFO note, what URL mode did and did not check.
  if (isUrlMode) {
    findings.push(urlScanLimitedNote());
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
