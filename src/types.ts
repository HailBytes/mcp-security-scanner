/**
 * Severity levels for security findings.
 * Higher severity = higher risk.
 */
export enum Severity {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFO = 'info',
}

/**
 * Unique identifiers for each security rule.
 */
export enum RuleId {
  NO_AUTH = 'NO_AUTH',
  WEAK_API_KEY = 'WEAK_API_KEY',
  MISSING_TLS = 'MISSING_TLS',
  TOOL_DESC_INJECTION = 'TOOL_DESC_INJECTION',
  UNSAFE_TOOL_OUTPUT_PATH = 'UNSAFE_TOOL_OUTPUT_PATH',
  WILDCARD_CORS = 'WILDCARD_CORS',
  VERBOSE_ERRORS = 'VERBOSE_ERRORS',
  OVERPRIVILEGED_TOOL = 'OVERPRIVILEGED_TOOL',
  INSECURE_TRANSPORT = 'INSECURE_TRANSPORT',
  MISSING_RATE_LIMIT = 'MISSING_RATE_LIMIT',
  DEBUG_MODE_ENABLED = 'DEBUG_MODE_ENABLED',
  EXPOSED_SECRETS = 'EXPOSED_SECRETS',
  UNRESTRICTED_FILE_ACCESS = 'UNRESTRICTED_FILE_ACCESS',
  /**
   * Informational note emitted when scanning a live URL/endpoint. URL mode can
   * only evaluate transport security from the URL itself; the full rule set
   * requires a config file. Not a vulnerability — INFO severity, never fails a gate.
   */
  URL_SCAN_LIMITED = 'URL_SCAN_LIMITED',
}

/**
 * A single security finding produced by a rule.
 */
export interface Finding {
  ruleId: RuleId;
  severity: Severity;
  title: string;
  description: string;
  evidence?: string;
  remediation: string;
  docsUrl?: string;
}

/**
 * Configuration for a scan run.
 */
export interface ScanConfig {
  /** Path to an MCP server config file (.json or .yaml/.yml). */
  configPath?: string;
  /** URL to a live MCP server. */
  serverUrl?: string;
  /** Subset of rule IDs to run. Runs all rules if omitted. */
  rules?: RuleId[];
  /** Minimum severity level that causes the scan to fail. */
  failOn?: Severity;
}

/**
 * Summary counts by severity.
 */
export interface SeveritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

/**
 * The output of a completed scan.
 */
export interface SecurityReport {
  findings: Finding[];
  /** Risk score 0 (safest) – 100 (most risk). */
  score: number;
  /** True when score < 50 and no critical findings. */
  passed: boolean;
  summary: SeveritySummary;
  scannedAt: string;
  durationMs: number;
}
