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
