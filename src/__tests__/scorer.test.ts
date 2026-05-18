import { computeScore, computeSummary } from '../scorer';
import { Finding, RuleId, Severity } from '../types';

function makeFinding(severity: Severity): Finding {
  return {
    ruleId: RuleId.NO_AUTH,
    severity,
    title: 'Test',
    description: 'Test finding',
    remediation: 'Fix it',
  };
}

describe('computeScore', () => {
  it('returns 0 for empty findings', () => {
    expect(computeScore([])).toBe(0);
  });

  it('returns 25 for a single CRITICAL finding', () => {
    expect(computeScore([makeFinding(Severity.CRITICAL)])).toBe(25);
  });

  it('returns 15 for a single HIGH finding', () => {
    expect(computeScore([makeFinding(Severity.HIGH)])).toBe(15);
  });

  it('returns 8 for a single MEDIUM finding', () => {
    expect(computeScore([makeFinding(Severity.MEDIUM)])).toBe(8);
  });

  it('returns 3 for a single LOW finding', () => {
    expect(computeScore([makeFinding(Severity.LOW)])).toBe(3);
  });

  it('returns 0 for a single INFO finding', () => {
    expect(computeScore([makeFinding(Severity.INFO)])).toBe(0);
  });

  it('caps at 100 with many findings', () => {
    const manyFindings = Array.from({ length: 10 }, () => makeFinding(Severity.CRITICAL));
    expect(computeScore(manyFindings)).toBe(100);
  });

  it('sums multiple findings correctly', () => {
    const findings = [
      makeFinding(Severity.CRITICAL), // 25
      makeFinding(Severity.HIGH),     // 15
      makeFinding(Severity.MEDIUM),   // 8
    ];
    expect(computeScore(findings)).toBe(48);
  });
});

describe('computeSummary', () => {
  it('returns zeros for empty findings', () => {
    expect(computeSummary([])).toEqual({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  });

  it('counts each severity correctly', () => {
    const findings = [
      makeFinding(Severity.CRITICAL),
      makeFinding(Severity.CRITICAL),
      makeFinding(Severity.HIGH),
      makeFinding(Severity.MEDIUM),
      makeFinding(Severity.LOW),
      makeFinding(Severity.INFO),
    ];
    expect(computeSummary(findings)).toEqual({
      critical: 2,
      high: 1,
      medium: 1,
      low: 1,
      info: 1,
    });
  });
});
