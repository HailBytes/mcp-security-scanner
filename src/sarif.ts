import { createRequire } from 'module';
import { SecurityReport, Finding, Severity } from './types.js';

const require = createRequire(import.meta.url);
const pkgVersion = require('../package.json').version as string;

/**
 * A minimal SARIF 2.1.0 output structure.
 */
export interface SarifOutput {
  version: '2.1.0';
  $schema: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
  artifacts?: SarifArtifact[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  helpUri?: string;
  properties?: { 'security-severity': string };
}

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note' | 'none';
  message: { text: string };
  locations?: SarifLocation[];
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string };
  };
}

interface SarifArtifact {
  location: { uri: string };
}

/**
 * Map a Severity to a SARIF result level.
 * critical/high → error, medium → warning, low/info → note
 */
function severityToLevel(severity: Severity): 'error' | 'warning' | 'note' {
  switch (severity) {
    case Severity.CRITICAL:
    case Severity.HIGH:
      return 'error';
    case Severity.MEDIUM:
      return 'warning';
    case Severity.LOW:
    case Severity.INFO:
    default:
      return 'note';
  }
}

/**
 * Map a Severity to a GitHub Code Scanning `security-severity` score.
 *
 * GitHub reads this numeric string (0.0–10.0) from each rule's `properties`
 * bag to assign the Critical/High/Medium/Low badge in the Security tab and to
 * drive severity-based alert filtering and branch-protection rules. Without it,
 * GitHub can only rank by SARIF `level`, so CRITICAL and HIGH (both `error`)
 * become indistinguishable. The bands follow GitHub's documented thresholds:
 * 9.0+ → critical, 7.0–8.9 → high, 4.0–6.9 → medium, <4.0 → low.
 */
function severityToScore(severity: Severity): string {
  switch (severity) {
    case Severity.CRITICAL:
      return '9.0';
    case Severity.HIGH:
      return '8.0';
    case Severity.MEDIUM:
      return '5.0';
    case Severity.LOW:
      return '2.0';
    case Severity.INFO:
    default:
      return '0.0';
  }
}

/**
 * Convert a SecurityReport to a minimal SARIF 2.1.0 document.
 *
 * @param report     - The scan report produced by scan().
 * @param configPath - Optional path to the scanned config file (used as artifact URI).
 */
export function toSarif(report: SecurityReport, configPath?: string): SarifOutput {
  // Deduplicate rules from findings
  const ruleMap = new Map<string, SarifRule>();
  for (const finding of report.findings) {
    if (!ruleMap.has(finding.ruleId)) {
      ruleMap.set(finding.ruleId, {
        id: finding.ruleId,
        name: finding.title,
        shortDescription: { text: finding.title },
        helpUri: finding.docsUrl,
        properties: { 'security-severity': severityToScore(finding.severity) },
      });
    }
  }

  const results: SarifResult[] = report.findings.map((finding: Finding) => {
    const result: SarifResult = {
      ruleId: finding.ruleId,
      level: severityToLevel(finding.severity),
      message: { text: finding.description },
    };

    if (configPath) {
      result.locations = [
        {
          physicalLocation: {
            artifactLocation: { uri: configPath },
          },
        },
      ];
    }

    return result;
  });

  const run: SarifRun = {
    tool: {
      driver: {
        name: '@hailbytes/mcp-security-scanner',
        version: pkgVersion,
        rules: Array.from(ruleMap.values()),
      },
    },
    results,
  };

  if (configPath) {
    run.artifacts = [{ location: { uri: configPath } }];
  }

  return {
    version: '2.1.0',
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [run],
  };
}
