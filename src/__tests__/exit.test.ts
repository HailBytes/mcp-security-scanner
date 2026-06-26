import { shouldExitNonZero } from '../exit';
import { Finding, RuleId, SecurityReport, Severity } from '../types';

function makeFinding(severity: Severity, ruleId: RuleId = RuleId.NO_AUTH): Finding {
  return {
    ruleId,
    severity,
    title: 'Test',
    description: 'Test finding',
    remediation: 'Fix it',
  };
}

function makeReport(findings: Finding[], passed: boolean): SecurityReport {
  return {
    findings,
    score: 0,
    passed,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    scannedAt: '2026-01-01T00:00:00.000Z',
    durationMs: 1,
  };
}

describe('shouldExitNonZero', () => {
  it('exits non-zero when the scan did not pass, regardless of --exit-code', () => {
    const report = makeReport([makeFinding(Severity.CRITICAL)], false);
    expect(shouldExitNonZero(report, false)).toBe(true);
    expect(shouldExitNonZero(report, true)).toBe(true);
  });

  it('exits zero on a passing scan without --exit-code', () => {
    const report = makeReport([makeFinding(Severity.LOW)], true);
    expect(shouldExitNonZero(report, false)).toBe(false);
  });

  it('exits non-zero with --exit-code when an actionable finding is present', () => {
    const report = makeReport([makeFinding(Severity.LOW)], true);
    expect(shouldExitNonZero(report, true)).toBe(true);
  });

  // Regression: URL mode emits a URL_SCAN_LIMITED INFO note for every scan.
  // It is documented as "never fails a gate", so --exit-code on a secure
  // https:// / wss:// endpoint (whose only finding is that note) must exit 0.
  it('does not exit non-zero with --exit-code when the only finding is an INFO note', () => {
    const report = makeReport(
      [makeFinding(Severity.INFO, RuleId.URL_SCAN_LIMITED)],
      true
    );
    expect(shouldExitNonZero(report, true)).toBe(false);
  });

  it('exits non-zero with --exit-code when an actionable finding accompanies an INFO note', () => {
    const report = makeReport(
      [
        makeFinding(Severity.INFO, RuleId.URL_SCAN_LIMITED),
        makeFinding(Severity.MEDIUM, RuleId.MISSING_RATE_LIMIT),
      ],
      true
    );
    expect(shouldExitNonZero(report, true)).toBe(true);
  });

  it('exits zero with no findings and no --exit-code', () => {
    const report = makeReport([], true);
    expect(shouldExitNonZero(report, false)).toBe(false);
    expect(shouldExitNonZero(report, true)).toBe(false);
  });
});
