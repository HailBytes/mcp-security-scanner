import { parseArgs, shouldExitNonZero } from '../args';
import { Severity, RuleId, SecurityReport, Finding } from '../types';

describe('parseArgs()', () => {
  it('returns help with exit code 2 when no args are given', () => {
    expect(parseArgs([])).toEqual({ kind: 'help', exitCode: 2 });
  });

  it('returns help with exit code 0 for --help and -h', () => {
    expect(parseArgs(['--help'])).toEqual({ kind: 'help', exitCode: 0 });
    expect(parseArgs(['-h'])).toEqual({ kind: 'help', exitCode: 0 });
  });

  it('defaults to json format for a bare config path', () => {
    const result = parseArgs(['./mcp.json']);
    expect(result).toMatchObject({
      kind: 'run',
      target: './mcp.json',
      isUrl: false,
      format: 'json',
      exitCode: false,
      scanConfig: { configPath: './mcp.json' },
    });
  });

  it('parses --format=sarif', () => {
    const result = parseArgs(['--format=sarif', './mcp.json']);
    expect(result).toMatchObject({ kind: 'run', format: 'sarif' });
  });

  // Regression: the README and dev.to launch post document `--output=sarif`,
  // which previously errored as an unknown flag.
  it('accepts --output as an alias for --format', () => {
    const result = parseArgs(['--output=sarif', './mcp.json']);
    expect(result).toMatchObject({ kind: 'run', format: 'sarif' });
  });

  it('parses the documented quick-start command: --output=sarif --exit-code', () => {
    const result = parseArgs(['./config.json', '--output=sarif', '--exit-code']);
    expect(result).toMatchObject({
      kind: 'run',
      target: './config.json',
      format: 'sarif',
      exitCode: true,
    });
  });

  it('rejects an invalid format value', () => {
    const result = parseArgs(['--format=xml', './mcp.json']);
    expect(result).toMatchObject({ kind: 'error', exitCode: 2 });
  });

  it('rejects an invalid --output value the same way as --format', () => {
    const result = parseArgs(['--output=xml', './mcp.json']);
    expect(result).toMatchObject({ kind: 'error', exitCode: 2 });
  });

  it('parses --fail-on into a Severity', () => {
    const result = parseArgs(['--fail-on=high', './mcp.json']);
    expect(result).toMatchObject({
      kind: 'run',
      scanConfig: { failOn: Severity.HIGH },
    });
  });

  it('rejects an unknown --fail-on value', () => {
    expect(parseArgs(['--fail-on=catastrophic', './mcp.json'])).toMatchObject({
      kind: 'error',
      exitCode: 2,
    });
  });

  it('collects repeated --rule flags', () => {
    const result = parseArgs(['--rule=NO_AUTH', '--rule=MISSING_TLS', './mcp.json']);
    expect(result).toMatchObject({
      kind: 'run',
      scanConfig: { rules: [RuleId.NO_AUTH, RuleId.MISSING_TLS] },
    });
  });

  // Regression for #11: an unknown/typo'd rule must fail loudly (exit 2), not
  // silently filter the rule set to nothing and report a false "PASSED".
  it('rejects an unknown --rule value with exit code 2', () => {
    const result = parseArgs(['--rule=NOAUTH', '--exit-code', './mcp.json']);
    expect(result).toMatchObject({ kind: 'error', exitCode: 2 });
    expect((result as { message: string }).message).toContain('Unknown rule "NOAUTH"');
  });

  it('accepts a valid --rule value', () => {
    const result = parseArgs(['--rule=NO_AUTH', './mcp.json']);
    expect(result).toMatchObject({
      kind: 'run',
      scanConfig: { rules: [RuleId.NO_AUTH] },
    });
  });

  it('detects URL targets and routes them to serverUrl', () => {
    for (const url of [
      'http://x.example.com',
      'https://x.example.com',
      'ws://x.example.com',
      'wss://x.example.com',
    ]) {
      expect(parseArgs([url])).toMatchObject({
        kind: 'run',
        isUrl: true,
        scanConfig: { serverUrl: url },
      });
    }
  });

  it('rejects an unknown flag', () => {
    expect(parseArgs(['--nope', './mcp.json'])).toMatchObject({
      kind: 'error',
      exitCode: 2,
    });
  });

  it('errors when no target is provided', () => {
    expect(parseArgs(['--format=json'])).toMatchObject({
      kind: 'error',
      exitCode: 2,
      message: expect.stringContaining('No config path'),
    });
  });
});

describe('shouldExitNonZero()', () => {
  function report(findings: Finding[], passed: boolean): SecurityReport {
    return {
      findings,
      score: 0,
      passed,
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      scannedAt: '1970-01-01T00:00:00.000Z',
      durationMs: 0,
    };
  }

  const infoNote: Finding = {
    ruleId: RuleId.URL_SCAN_LIMITED,
    severity: Severity.INFO,
    title: 'URL Scan — Transport Checks Only',
    description: 'info note',
    remediation: 'scan a config file',
  };

  const highFinding: Finding = {
    ruleId: RuleId.MISSING_TLS,
    severity: Severity.HIGH,
    title: 'Missing TLS',
    description: 'plain http',
    remediation: 'use https',
  };

  it('fails whenever the report did not pass, regardless of --exit-code', () => {
    expect(shouldExitNonZero(report([highFinding], false), false)).toBe(true);
    expect(shouldExitNonZero(report([highFinding], false), true)).toBe(true);
  });

  it('passes a clean report when --exit-code is not set', () => {
    expect(shouldExitNonZero(report([], true), false)).toBe(false);
  });

  // Regression: a secure https:// / wss:// endpoint reports passed:true but URL
  // mode always emits the INFO URL_SCAN_LIMITED note. --exit-code must NOT treat
  // that informational note as a finding, or it would fail the gate on every
  // secure endpoint while the report itself says PASSED.
  it('does not fail on an INFO-only report under --exit-code', () => {
    expect(shouldExitNonZero(report([infoNote], true), true)).toBe(false);
  });

  it('fails on an actionable finding under --exit-code', () => {
    expect(shouldExitNonZero(report([infoNote, highFinding], true), true)).toBe(true);
  });
});
