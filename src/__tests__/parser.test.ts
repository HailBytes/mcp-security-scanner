import { promises as fs } from 'fs';
import * as os from 'os';
import * as path from 'path';
import { parseConfig } from '../parser';
import { runtimeRules } from '../rules/runtime-rules';
import { RuleId } from '../types';

const exposedSecretsRule = runtimeRules.find((r) => r.id === RuleId.EXPOSED_SECRETS)!;

async function withTempConfig<T>(
  contents: string,
  ext: string,
  fn: (configPath: string) => Promise<T>
): Promise<T> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-scan-'));
  const configPath = path.join(dir, `config${ext}`);
  await fs.writeFile(configPath, contents, 'utf-8');
  try {
    return await fn(configPath);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

describe('extractStrings key context (secret scanning)', () => {
  it('preserves "key: value" context so the password pattern can match', async () => {
    const raw = JSON.stringify({
      serverUrl: 'https://x.example.com',
      database: { password: 'hunter2supersecret' },
    });

    await withTempConfig(raw, '.json', async (configPath) => {
      const parsed = await parseConfig({ configPath });

      // The reconstructed "key: value" form must be present for key-aware patterns.
      expect(parsed.rawStrings).toContain('password: hunter2supersecret');

      // Regression: a hardcoded password in a config must be flagged as a secret.
      const findings = exposedSecretsRule.check(parsed);
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe(RuleId.EXPOSED_SECRETS);
    });
  });

  it('still matches token-shaped secrets (sk-, ghp_, AKIA) inside key: value', async () => {
    const raw = JSON.stringify({
      transport: { auth: { type: 'bearer', apiKey: 'sk-abcdefghijklmnopqrstuvwxyz0123456789' } },
    });

    await withTempConfig(raw, '.json', async (configPath) => {
      const parsed = await parseConfig({ configPath });
      const findings = exposedSecretsRule.check(parsed);
      expect(findings).toHaveLength(1);
    });
  });

  it('does not flag a clean config with no secrets', async () => {
    const raw = JSON.stringify({
      serverUrl: 'https://x.example.com',
      transport: { tls: true, auth: { type: 'oauth' } },
    });

    await withTempConfig(raw, '.json', async (configPath) => {
      const parsed = await parseConfig({ configPath });
      expect(exposedSecretsRule.check(parsed)).toHaveLength(0);
    });
  });
});
