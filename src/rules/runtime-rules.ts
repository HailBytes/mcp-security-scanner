import { Finding, RuleId, Severity } from '../types.js';
import { ParsedMcpConfig } from '../parser.js';
import { Rule } from './index.js';

/**
 * A labeled secret pattern. The `name` is surfaced in the finding so users know
 * which kind of credential was matched, and the patterns are intentionally
 * anchored on distinctive vendor prefixes / structures to keep false positives
 * low (a high-entropy random token without a known prefix will not match).
 */
interface SecretPattern {
  name: string;
  pattern: RegExp;
}

const SECRET_PATTERNS: SecretPattern[] = [
  // Anthropic keys (`sk-ant-…`) and OpenAI project keys (`sk-proj-…`) contain
  // hyphens, so the generic OpenAI pattern below (which stops at the first
  // hyphen) misses them — they need their own, hyphen-tolerant matchers.
  { name: 'Anthropic API key', pattern: /sk-ant-[A-Za-z0-9_-]{20,}/ },
  { name: 'OpenAI API key', pattern: /sk-(?:proj-)?[A-Za-z0-9_-]{20,}/ },
  { name: 'GitHub token', pattern: /gh[pousr]_[A-Za-z0-9]{36,}/ },
  { name: 'GitHub fine-grained PAT', pattern: /github_pat_[A-Za-z0-9_]{22,}/ },
  // AWS access key IDs are strictly uppercase — matching case-insensitively
  // (the previous behaviour) flags any lowercase "akia…" substring as a key.
  { name: 'AWS access key ID', pattern: /AKIA[0-9A-Z]{16}/ },
  { name: 'Google API key', pattern: /AIza[0-9A-Za-z_-]{35}/ },
  { name: 'Slack token', pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/ },
  { name: 'Stripe secret key', pattern: /[sr]k_live_[A-Za-z0-9]{16,}/ },
  { name: 'Private key block', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/ },
  // Credentials embedded in a connection-string URL (`scheme://user:pass@host`).
  // Requires both a user and a password before the `@`, so plain URLs such as
  // `https://api.example.com` (no userinfo) do not match.
  { name: 'Credentials in URL', pattern: /[a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:[^\s/:@]+@/i },
  { name: 'Hardcoded password', pattern: /[Pp]assword\s*[=:]\s*\S{8,}/ },
];

/**
 * Redact a matched secret for safe display. Scan reports can be printed to logs
 * or uploaded to GitHub Code Scanning as SARIF, so the full credential must not
 * be echoed. Only a short, non-sensitive prefix is shown alongside the length.
 */
function redactSecret(value: string): string {
  const head = value.slice(0, 6);
  return `${head}…(${value.length} chars, redacted)`;
}

export const runtimeRules: Rule[] = [
  {
    id: RuleId.INSECURE_TRANSPORT,
    severity: Severity.HIGH,
    title: 'Insecure WebSocket Transport (ws://)',
    check(config: ParsedMcpConfig): Finding[] {
      const url = config.transport?.url;
      if (url && url.startsWith('ws://')) {
        return [
          {
            ruleId: RuleId.INSECURE_TRANSPORT,
            severity: Severity.HIGH,
            title: 'Insecure WebSocket Transport (ws://)',
            description:
              'The transport URL uses an unencrypted WebSocket connection (ws://). ' +
              'All data — including authentication tokens and tool payloads — is sent in cleartext.',
            evidence: `transport.url: ${url}`,
            remediation:
              'Switch to a secure WebSocket connection using wss:// and configure TLS on the server.',
            docsUrl: 'https://hailbytes.com/mcp/docs/rules/INSECURE_TRANSPORT',
          },
        ];
      }
      return [];
    },
  },

  {
    id: RuleId.MISSING_RATE_LIMIT,
    severity: Severity.MEDIUM,
    title: 'Rate Limiting Not Configured',
    check(config: ParsedMcpConfig): Finding[] {
      const rl = config.rateLimit;
      if (!rl || rl.enabled === false) {
        return [
          {
            ruleId: RuleId.MISSING_RATE_LIMIT,
            severity: Severity.MEDIUM,
            title: 'Rate Limiting Not Configured',
            description:
              'The MCP server has no rate limiting configured. ' +
              'Without rate limits, the server is vulnerable to abuse, brute-force attacks, ' +
              'and denial-of-service conditions.',
            evidence: rl ? 'rateLimit.enabled: false' : 'rateLimit: absent',
            remediation:
              'Configure rateLimit.enabled: true and set an appropriate requestsPerMinute threshold.',
            docsUrl: 'https://hailbytes.com/mcp/docs/rules/MISSING_RATE_LIMIT',
          },
        ];
      }
      return [];
    },
  },

  {
    id: RuleId.DEBUG_MODE_ENABLED,
    severity: Severity.LOW,
    title: 'Debug Mode Enabled in Production',
    check(config: ParsedMcpConfig): Finding[] {
      if (config.debug === true) {
        return [
          {
            ruleId: RuleId.DEBUG_MODE_ENABLED,
            severity: Severity.LOW,
            title: 'Debug Mode Enabled in Production',
            description:
              'The server is running with debug mode enabled. ' +
              'Debug mode can expose internal implementation details, stack traces, ' +
              'and sensitive configuration data to potential attackers.',
            evidence: 'debug: true',
            remediation:
              'Set debug: false (or remove the flag) in production environments. ' +
              'Use structured logging with appropriate log levels instead.',
            docsUrl: 'https://hailbytes.com/mcp/docs/rules/DEBUG_MODE_ENABLED',
          },
        ];
      }
      return [];
    },
  },

  {
    id: RuleId.EXPOSED_SECRETS,
    severity: Severity.CRITICAL,
    title: 'Potential Secret Exposed in Configuration',
    check(config: ParsedMcpConfig): Finding[] {
      const rawStrings = config.rawStrings ?? [];
      const matched: Array<{ kind: string; preview: string }> = [];

      for (const s of rawStrings) {
        for (const { name, pattern } of SECRET_PATTERNS) {
          if (pattern.test(s)) {
            matched.push({ kind: name, preview: redactSecret(s) });
            break;
          }
        }
      }

      if (matched.length > 0) {
        const kinds = Array.from(new Set(matched.map((m) => m.kind)));
        const previews = matched
          .slice(0, 3)
          .map((m) => `${m.kind}: ${m.preview}`)
          .join('; ');
        return [
          {
            ruleId: RuleId.EXPOSED_SECRETS,
            severity: Severity.CRITICAL,
            title: 'Potential Secret Exposed in Configuration',
            description:
              `The configuration appears to contain ${matched.length} hardcoded secret(s) ` +
              `(${kinds.join(', ')}). Secrets committed to config files can be ` +
              'extracted by anyone with access to the file.',
            evidence: `Matched ${matched.length} value(s) — ${previews}`,
            remediation:
              'Remove secrets from configuration files. Use environment variables, a secrets manager ' +
              '(e.g., AWS Secrets Manager, HashiCorp Vault), or a .env file excluded from version control.',
            docsUrl: 'https://hailbytes.com/mcp/docs/rules/EXPOSED_SECRETS',
          },
        ];
      }
      return [];
    },
  },

  {
    id: RuleId.UNRESTRICTED_FILE_ACCESS,
    severity: Severity.HIGH,
    title: 'Tool Has Unrestricted File System Access',
    check(config: ParsedMcpConfig): Finding[] {
      const findings: Finding[] = [];
      for (const tool of config.tools ?? []) {
        if (!tool.permissions || tool.permissions.length === 0) continue;

        const perms = tool.permissions;
        const hasWildcard = perms.includes('filesystem:*');
        const hasRead = perms.includes('filesystem:read');
        const hasWrite = perms.includes('filesystem:write');

        if (hasWildcard || (hasRead && hasWrite)) {
          const evidence = `tool: ${tool.name}, permissions: [${perms.join(', ')}]`;
          findings.push({
            ruleId: RuleId.UNRESTRICTED_FILE_ACCESS,
            severity: Severity.HIGH,
            title: 'Tool Has Unrestricted File System Access',
            description:
              `Tool "${tool.name}" has been granted both read and write (or wildcard) filesystem permissions. ` +
              'This allows the tool to read and modify arbitrary files on the host, ' +
              'which can lead to data exfiltration or system compromise.',
            evidence,
            remediation:
              'Apply the principle of least privilege. Grant either filesystem:read OR filesystem:write ' +
              'based on what the tool actually needs, and restrict paths where possible. ' +
              'Never grant filesystem:* (wildcard) access.',
            docsUrl: 'https://hailbytes.com/mcp/docs/rules/UNRESTRICTED_FILE_ACCESS',
          });
        }
      }
      return findings;
    },
  },
];
