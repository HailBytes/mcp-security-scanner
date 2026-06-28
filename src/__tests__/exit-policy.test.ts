import { shouldFailExit } from '../exit-policy';
import { Finding, RuleId, Severity, SecurityReport } from '../types';

function makeFinding(ruleId: RuleId, severity: Severity): Finding {
  return {
    ruleId,
    severity,
    title: 'Test',
    description: 'Test finding',
    remediation: 'Fix it',
  };
}

function makeReport(partial: Partial<SecurityReport>): SecurityReport {
  return {
    findings: [],
    score: 0,
    passed: true,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    scannedAt: '2026-01-01T00:00:00.000Z',
    durationMs: 0,
    ...partial,
  };
}

describe('shouldFailExit()', () => {
  it('fails whenever the report did not pass, regardless of --exit-code', () => {
    const report = makeReport({ passed: false });
    expect(shouldFailExit(report, false)).toBe(true);
    expect(shouldFailExit(report, true)).toBe(true);
  });

  it('passes a clean report when --exit-code is not set', () => {
    const report = makeReport({ passed: true, findings: [] });
    expect(shouldFailExit(report, false)).toBe(false);
  });

  it('fails a passing report with --exit-code when an actionable finding exists', () => {
    const report = makeReport({
      passed: true,
      findings: [makeFinding(RuleId.MISSING_RATE_LIMIT, Severity.MEDIUM)],
    });
    expect(shouldFailExit(report, true)).toBe(true);
  });

  // Regression (secure URL scan + --exit-code): scanning a secure https:// /
  // wss:// endpoint produces only the INFO URL_SCAN_LIMITED note. The report
  // PASSES, so --exit-code must NOT fail solely because of that informational
  // note — otherwise the documented CI gate reports PASSED yet exits 1.
  it('does not fail a passing URL scan whose only finding is the INFO note', () => {
    const report = makeReport({
      passed: true,
      findings: [makeFinding(RuleId.URL_SCAN_LIMITED, Severity.INFO)],
    });
    expect(shouldFailExit(report, true)).toBe(false);
    expect(shouldFailExit(report, false)).toBe(false);
  });

  it('still fails when an INFO note accompanies a real finding under --exit-code', () => {
    const report = makeReport({
      passed: true,
      findings: [
        makeFinding(RuleId.URL_SCAN_LIMITED, Severity.INFO),
        makeFinding(RuleId.DEBUG_MODE_ENABLED, Severity.LOW),
      ],
    });
    expect(shouldFailExit(report, true)).toBe(true);
  });
});
