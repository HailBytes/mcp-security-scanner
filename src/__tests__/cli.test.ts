import { parseArgs } from '../cli';
import { RuleId, Severity } from '../types';

// ─── parseArgs() unit tests ───────────────────────────────────────────────────

describe('parseArgs()', () => {
  it('defaults format to json', () => {
    const result = parseArgs(['./config.json']);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.args.format).toBe('json');
      expect(result.args.target).toBe('./config.json');
    }
  });

  it('parses --format=sarif', () => {
    const result = parseArgs(['--format=sarif', './config.json']);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.args.format).toBe('sarif');
  });

  it('accepts --output= as an alias for --format= (documented quick-start)', () => {
    const result = parseArgs(['--output=sarif', '--exit-code', './config.json']);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.args.format).toBe('sarif');
      expect(result.args.exitCode).toBe(true);
      expect(result.args.target).toBe('./config.json');
    }
  });

  it('--output=table is accepted', () => {
    const result = parseArgs(['--output=table', './config.json']);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.args.format).toBe('table');
  });

  it('rejects an invalid --output value', () => {
    const result = parseArgs(['--output=xml', './config.json']);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toMatch(/Unknown format "xml"/);
  });

  it('rejects an invalid --format value', () => {
    const result = parseArgs(['--format=xml', './config.json']);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toMatch(/Unknown format "xml"/);
  });

  it('parses --fail-on= into a Severity', () => {
    const result = parseArgs(['--fail-on=high', './config.json']);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.args.failOn).toBe(Severity.HIGH);
  });

  it('rejects an unknown --fail-on value', () => {
    const result = parseArgs(['--fail-on=bogus', './config.json']);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toMatch(/Unknown severity "bogus"/);
  });

  it('collects repeated --rule= flags', () => {
    const result = parseArgs(['--rule=NO_AUTH', '--rule=MISSING_TLS', './config.json']);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.args.rules).toEqual([RuleId.NO_AUTH, RuleId.MISSING_TLS]);
    }
  });

  it('rejects an unknown flag', () => {
    const result = parseArgs(['--nope', './config.json']);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toMatch(/Unknown flag "--nope"/);
  });

  it('leaves target undefined when no positional arg is given', () => {
    const result = parseArgs(['--format=json']);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.args.target).toBeUndefined();
  });
});
