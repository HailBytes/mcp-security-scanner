import { parseArgs } from '../args';
import { RuleId, Severity } from '../types';

// ─── parseArgs() unit tests ──────────────────────────────────────────────────

describe('parseArgs', () => {
  describe('--rule validation (regression for issue #11)', () => {
    it('rejects an unknown/typo’d rule ID instead of silently passing', () => {
      // NO_AUTH mistyped as NOAUTH previously filtered the rule set to nothing,
      // producing a perfect score + passed:true + exit 0 (a false security gate).
      const result = parseArgs(['--rule=NOAUTH', './config.json']);
      expect(result.kind).toBe('error');
      if (result.kind === 'error') {
        expect(result.message).toContain('Unknown rule "NOAUTH"');
        expect(result.showHelp).toBe(false);
      }
    });

    it('accepts a valid rule ID', () => {
      const result = parseArgs(['--rule=NO_AUTH', './config.json']);
      expect(result.kind).toBe('run');
      if (result.kind === 'run') {
        expect(result.scanConfig.rules).toEqual([RuleId.NO_AUTH]);
      }
    });

    it('accepts multiple valid rule IDs', () => {
      const result = parseArgs([
        '--rule=NO_AUTH',
        '--rule=MISSING_TLS',
        './config.json',
      ]);
      expect(result.kind).toBe('run');
      if (result.kind === 'run') {
        expect(result.scanConfig.rules).toEqual([
          RuleId.NO_AUTH,
          RuleId.MISSING_TLS,
        ]);
      }
    });

    it('rejects the batch if any rule ID is invalid', () => {
      const result = parseArgs([
        '--rule=NO_AUTH',
        '--rule=BOGUS',
        './config.json',
      ]);
      expect(result.kind).toBe('error');
      if (result.kind === 'error') {
        expect(result.message).toContain('Unknown rule "BOGUS"');
      }
    });
  });

  describe('target resolution', () => {
    it('treats a file path as configPath', () => {
      const result = parseArgs(['./mcp-config.json']);
      expect(result.kind).toBe('run');
      if (result.kind === 'run') {
        expect(result.isUrl).toBe(false);
        expect(result.scanConfig.configPath).toBe('./mcp-config.json');
        expect(result.scanConfig.serverUrl).toBeUndefined();
      }
    });

    it('treats an http(s)/ws(s) URL as serverUrl', () => {
      for (const url of [
        'https://mcp.example.com',
        'http://localhost:3000',
        'wss://mcp.example.com',
      ]) {
        const result = parseArgs([url]);
        expect(result.kind).toBe('run');
        if (result.kind === 'run') {
          expect(result.isUrl).toBe(true);
          expect(result.scanConfig.serverUrl).toBe(url);
          expect(result.scanConfig.configPath).toBeUndefined();
        }
      }
    });

    it('errors with showHelp when no target is provided', () => {
      const result = parseArgs(['--format=table']);
      expect(result.kind).toBe('error');
      if (result.kind === 'error') {
        expect(result.message).toContain('No config path or URL provided');
        expect(result.showHelp).toBe(true);
      }
    });
  });

  describe('--format / --fail-on / --exit-code', () => {
    it('defaults format to json', () => {
      const result = parseArgs(['./config.json']);
      if (result.kind === 'run') expect(result.format).toBe('json');
    });

    it('accepts sarif and table formats', () => {
      expect((parseArgs(['--format=sarif', './c.json']) as { format: string }).format).toBe('sarif');
      expect((parseArgs(['--format=table', './c.json']) as { format: string }).format).toBe('table');
    });

    it('rejects an unknown format', () => {
      const result = parseArgs(['--format=xml', './config.json']);
      expect(result.kind).toBe('error');
      if (result.kind === 'error') expect(result.message).toContain('Unknown format "xml"');
    });

    it('maps --fail-on to a Severity (case-insensitive)', () => {
      const result = parseArgs(['--fail-on=HIGH', './config.json']);
      if (result.kind === 'run') expect(result.scanConfig.failOn).toBe(Severity.HIGH);
    });

    it('rejects an unknown --fail-on severity', () => {
      const result = parseArgs(['--fail-on=urgent', './config.json']);
      expect(result.kind).toBe('error');
      if (result.kind === 'error') expect(result.message).toContain('Unknown severity "urgent"');
    });

    it('sets exitCode when --exit-code is present', () => {
      const result = parseArgs(['--exit-code', './config.json']);
      if (result.kind === 'run') expect(result.exitCode).toBe(true);
    });
  });

  describe('help and unknown flags', () => {
    it('returns help with exit code 2 when no args are given', () => {
      expect(parseArgs([])).toEqual({ kind: 'help', exitCode: 2 });
    });

    it('returns help with exit code 0 for --help / -h', () => {
      expect(parseArgs(['--help'])).toEqual({ kind: 'help', exitCode: 0 });
      expect(parseArgs(['-h'])).toEqual({ kind: 'help', exitCode: 0 });
    });

    it('rejects an unknown flag', () => {
      const result = parseArgs(['--nope', './config.json']);
      expect(result.kind).toBe('error');
      if (result.kind === 'error') expect(result.message).toContain('Unknown flag "--nope"');
    });
  });
});
