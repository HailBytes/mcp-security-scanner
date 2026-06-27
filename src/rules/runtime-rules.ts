import { Finding, RuleId, Severity } from '../types.js';
import { ParsedMcpConfig } from '../parser.js';
import { Rule } from './index.js';

/** A labelled secret-detection pattern. The label names the secret *type* so a
 * finding can say what was detected without echoing the secret value itself. */
interface SecretPattern {
  label: string;
  pattern: RegExp;
}

/**
 * High-confidence patterns for credentials that should never be hardcoded in a
 * config file. Each is anchored on a distinctive prefix or structure to keep the
 * false-positive rate low — we deliberately avoid generic "long random-looking
 * string" heuristics, which would flag legitimate opaque tokens (e.g. a JWT in
 * `transport.auth.token`, which the auth rules treat as valid authentication).
 */
const SECRET_PATTERNS: SecretPattern[] = [
  { label: 'OpenAI API key', pattern: /sk-[a-zA-Z0-9]{20,}/i },
  // Classic and scoped GitHub tokens: ghp_/gho_/ghu_/ghs_/ghr_.
  { label: 'GitHub token', pattern: /gh[opusr]_[A-Za-z0-9]{36,}/ },
  { label: 'GitHub fine-grained PAT', pattern: /github_pat_[A-Za-z0-9_]{22,}/ },
  // AWS long-term (AKIA) and temporary (ASIA) access key IDs are uppercase.
  { label: 'AWS access key ID', pattern: /(?:AKIA|ASIA)[0-9A-Z]{16}/ },
  { label: 'Google API key', pattern: /AIza[0-9A-Za-z_-]{35}/ },
  { label: 'Slack token', pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/ },
  { label: 'Stripe secret key', pattern: /[sr]k_live_[0-9a-zA-Z]{16,}/ },
  // PEM-encoded private key of any flavour (RSA, EC, OPENSSH, DSA, PGP, …).
  { label: 'PEM private key', pattern: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/ },
  { label: 'hardcoded password', pattern: /[Pp]assword\s*[=:]\s*\S{8,}/ },
];

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
      // Collect the *types* of secret detected, not the secret values. Echoing a
      // matched credential into the finding (and from there into CI logs / SARIF
      // uploads) would re-expose the very secret this rule is meant to protect.
      const detected = new Set<string>();

      for (const s of rawStrings) {
        for (const { label, pattern } of SECRET_PATTERNS) {
          if (pattern.test(s)) {
            detected.add(label);
          }
        }
      }

      if (detected.size > 0) {
        const labels = Array.from(detected);
        return [
          {
            ruleId: RuleId.EXPOSED_SECRETS,
            severity: Severity.CRITICAL,
            title: 'Potential Secret Exposed in Configuration',
            description:
              'The configuration file appears to contain one or more hardcoded secrets ' +
              '(API keys, tokens, or passwords). Secrets committed to config files can be ' +
              'extracted by anyone with access to the file.',
            evidence: `Detected ${labels.length} likely secret type(s): ${labels.join(', ')}`,
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
