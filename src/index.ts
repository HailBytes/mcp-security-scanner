// @hailbytes/mcp-security-scanner
// TODO: Implement MCP security scanning logic.
// Planned exports:
//   - scan(config: ScanConfig): Promise<SecurityReport>
//   - ScanConfig
//   - SecurityReport
//   - Finding
//   - Severity

export interface ScanConfig {
  /** Path to an MCP server config file, or a live server URL. */
  configPath?: string;
  serverUrl?: string;
}

export interface Finding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  remediation?: string;
}

export interface SecurityReport {
  findings: Finding[];
  /** Risk score 0 (safest) – 100 (most risk). */
  score: number;
  passed: boolean;
  scannedAt: string;
}

/**
 * Scan an MCP server configuration for security issues.
 * @param config - Path to a config file or a live server URL.
 * @returns A SecurityReport with findings and an overall risk score.
 * @todo Implement scanner rules.
 */
export async function scan(_config: ScanConfig): Promise<SecurityReport> {
  // TODO: implement scanning logic
  return {
    findings: [],
    score: 0,
    passed: true,
    scannedAt: new Date().toISOString(),
  };
}
