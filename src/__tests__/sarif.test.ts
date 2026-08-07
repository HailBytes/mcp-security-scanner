import { createRequire } from 'module';
import { toSarif } from '../sarif';
import { SecurityReport, Finding, RuleId, Severity } from '../types';

const require = createRequire(import.meta.url);
const pkgVersion = require('../../package.json').version as string;

// ─── Helper to build a minimal SecurityReport ─────────────────────────────────

function makeReport(overrides: Partial<SecurityReport> = {}): SecurityReport {
  return {
    findings: [],
    score: 0,
    passed: true,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    scannedAt: new Date().toISOString(),
    durationMs: 1,
    ...overrides,
  };
}

function makeFinding(overrides: Partial<Finding> & { ruleId: RuleId; severity: Severity }): Finding {
  return {
    ruleId: overrides.ruleId,
    severity: overrides.severity,
    title: overrides.title ?? 'Test Finding',
    description: overrides.description ?? 'A test finding description.',
    remediation: overrides.remediation ?? 'Fix it.',
    evidence: overrides.evidence,
    docsUrl: overrides.docsUrl,
  };
}

// ─── toSarif() unit tests ─────────────────────────────────────────────────────

describe('toSarif()', () => {
  it('schema version is "2.1.0"', () => {
    const sarif = toSarif(makeReport());
    expect(sarif.version).toBe('2.1.0');
  });

  it('$schema contains the SARIF 2.1.0 schema URL', () => {
    const sarif = toSarif(makeReport());
    expect(sarif.$schema).toBe(
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json'
    );
  });

  it('produces exactly one run', () => {
    const sarif = toSarif(makeReport());
    expect(sarif.runs).toHaveLength(1);
  });

  it('run.tool.driver.name is "@hailbytes/mcp-security-scanner"', () => {
    const sarif = toSarif(makeReport());
    expect(sarif.runs[0].tool.driver.name).toBe('@hailbytes/mcp-security-scanner');
  });

  it('run.tool.driver.version matches the package version', () => {
    const sarif = toSarif(makeReport());
    expect(sarif.runs[0].tool.driver.version).toBe(pkgVersion);
  });

  it('empty findings → results: []', () => {
    const sarif = toSarif(makeReport({ findings: [] }));
    expect(sarif.runs[0].results).toEqual([]);
  });

  it('empty findings → driver.rules: []', () => {
    const sarif = toSarif(makeReport({ findings: [] }));
    expect(sarif.runs[0].tool.driver.rules).toEqual([]);
  });

  it('one CRITICAL finding → result level: "error"', () => {
    const finding = makeFinding({ ruleId: RuleId.NO_AUTH, severity: Severity.CRITICAL });
    const sarif = toSarif(makeReport({ findings: [finding] }));
    expect(sarif.runs[0].results).toHaveLength(1);
    expect(sarif.runs[0].results[0].level).toBe('error');
    expect(sarif.runs[0].results[0].ruleId).toBe(RuleId.NO_AUTH);
  });

  it('one HIGH finding → result level: "error"', () => {
    const finding = makeFinding({ ruleId: RuleId.MISSING_TLS, severity: Severity.HIGH });
    const sarif = toSarif(makeReport({ findings: [finding] }));
    expect(sarif.runs[0].results[0].level).toBe('error');
  });

  it('one MEDIUM finding → result level: "warning"', () => {
    const finding = makeFinding({ ruleId: RuleId.WILDCARD_CORS, severity: Severity.MEDIUM });
    const sarif = toSarif(makeReport({ findings: [finding] }));
    expect(sarif.runs[0].results[0].level).toBe('warning');
  });

  it('one LOW finding → result level: "note"', () => {
    const finding = makeFinding({ ruleId: RuleId.DEBUG_MODE_ENABLED, severity: Severity.LOW });
    const sarif = toSarif(makeReport({ findings: [finding] }));
    expect(sarif.runs[0].results[0].level).toBe('note');
  });

  it('one INFO finding → result level: "note"', () => {
    const finding = makeFinding({ ruleId: RuleId.VERBOSE_ERRORS, severity: Severity.INFO });
    const sarif = toSarif(makeReport({ findings: [finding] }));
    expect(sarif.runs[0].results[0].level).toBe('note');
  });

  it('result message.text equals finding description', () => {
    const finding = makeFinding({
      ruleId: RuleId.NO_AUTH,
      severity: Severity.CRITICAL,
      description: 'No authentication was found in the config.',
    });
    const sarif = toSarif(makeReport({ findings: [finding] }));
    expect(sarif.runs[0].results[0].message.text).toBe('No authentication was found in the config.');
  });

  it('multiple findings produce multiple results', () => {
    const findings: Finding[] = [
      makeFinding({ ruleId: RuleId.NO_AUTH, severity: Severity.CRITICAL }),
      makeFinding({ ruleId: RuleId.WILDCARD_CORS, severity: Severity.MEDIUM }),
      makeFinding({ ruleId: RuleId.DEBUG_MODE_ENABLED, severity: Severity.LOW }),
    ];
    const sarif = toSarif(makeReport({ findings }));
    expect(sarif.runs[0].results).toHaveLength(3);
  });

  it('driver.rules are derived from findings (deduplicated)', () => {
    const findings: Finding[] = [
      makeFinding({ ruleId: RuleId.NO_AUTH, severity: Severity.CRITICAL }),
      makeFinding({ ruleId: RuleId.NO_AUTH, severity: Severity.CRITICAL }), // duplicate
    ];
    const sarif = toSarif(makeReport({ findings }));
    // Should deduplicate the rule
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.rules[0].id).toBe(RuleId.NO_AUTH);
  });

  it('rules carry a GitHub "security-severity" property', () => {
    const finding = makeFinding({ ruleId: RuleId.NO_AUTH, severity: Severity.CRITICAL });
    const sarif = toSarif(makeReport({ findings: [finding] }));
    expect(sarif.runs[0].tool.driver.rules[0].properties).toEqual({
      'security-severity': '9.0',
    });
  });

  it('security-severity score maps to GitHub severity bands', () => {
    const cases: Array<[Severity, string]> = [
      [Severity.CRITICAL, '9.0'], // >= 9.0 → critical
      [Severity.HIGH, '8.0'], // 7.0–8.9 → high
      [Severity.MEDIUM, '5.0'], // 4.0–6.9 → medium
      [Severity.LOW, '2.0'], // < 4.0 → low
      [Severity.INFO, '0.0'],
    ];
    for (const [severity, score] of cases) {
      const finding = makeFinding({ ruleId: RuleId.NO_AUTH, severity });
      const sarif = toSarif(makeReport({ findings: [finding] }));
      expect(sarif.runs[0].tool.driver.rules[0].properties).toEqual({
        'security-severity': score,
      });
    }
  });

  it('configPath is included as artifact URI when provided', () => {
    const finding = makeFinding({ ruleId: RuleId.NO_AUTH, severity: Severity.CRITICAL });
    const sarif = toSarif(makeReport({ findings: [finding] }), './mcp-config.json');
    expect(sarif.runs[0].artifacts).toBeDefined();
    expect(sarif.runs[0].artifacts![0].location.uri).toBe('./mcp-config.json');
  });

  it('result locations are populated when configPath is provided', () => {
    const finding = makeFinding({ ruleId: RuleId.NO_AUTH, severity: Severity.CRITICAL });
    const sarif = toSarif(makeReport({ findings: [finding] }), './mcp-config.json');
    const result = sarif.runs[0].results[0];
    expect(result.locations).toBeDefined();
    expect(result.locations![0].physicalLocation.artifactLocation.uri).toBe('./mcp-config.json');
  });

  it('no artifacts field when configPath is not provided', () => {
    const sarif = toSarif(makeReport());
    expect(sarif.runs[0].artifacts).toBeUndefined();
  });
});
