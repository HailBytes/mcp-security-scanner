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
  fullDescription?: { text: string };
  help?: { text: string };
  helpUri?: string;
  properties?: {
    /**
     * A CVSS-style 0.0–10.0 score, as a string. GitHub Code Scanning reads this
     * to rank alerts (≥9.0 Critical, 7.0–8.9 High, 4.0–6.9 Medium, 0.1–3.9 Low)
     * and to enforce severity thresholds on pull requests.
     */
    'security-severity'?: string;
    tags?: string[];
  };
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
 * Map a Severity to a SARIF `security-severity` score (a CVSS-style 0.0–10.0
 * value, serialized as a string). GitHub Code Scanning uses this — not the
 * SARIF `level` — to assign each alert a Critical / High / Medium / Low
 * severity and to enforce per-severity gates on pull requests. Without it,
 * critical and high findings both collapse to `error` and appear
 * indistinguishable (and unfilterable) in the Security tab.
 */
function severityToSecurityScore(severity: Severity): string {
  switch (severity) {
    case Severity.CRITICAL:
      return '9.0';
    case Severity.HIGH:
      return '7.0';
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
        fullDescription: { text: finding.description },
        help: { text: finding.remediation },
        helpUri: finding.docsUrl,
        properties: {
          'security-severity': severityToSecurityScore(finding.severity),
          tags: ['security'],
        },
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
