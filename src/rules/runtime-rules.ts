import { Finding, RuleId, Severity } from '../types.js';
import { ParsedMcpConfig } from '../parser.js';
import { Rule } from './index.js';

/** A labelled secret signature. The label names the credential type in the
 * finding's evidence so users know what leaked, without echoing the raw value. */
interface SecretPattern {
  label: string;
  pattern: RegExp;
}

/**
 * Signatures for the most common high-confidence secret formats. Each prefix is
 * vendor-specific and long enough that false positives on ordinary config
 * values are negligible. Anthropic is listed before the broader OpenAI `sk-`
 * pattern so a `sk-ant-…` key is attributed to the correct vendor.
 */
const SECRET_PATTERNS: SecretPattern[] = [
  { label: 'Anthropic API key', pattern: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{24,}/ },
  { label: 'OpenAI API key', pattern: /\bsk-(?:proj-)?[A-Za-z0-9]{20,}/ },
  { label: 'GitHub fine-grained PAT', pattern: /\bgithub_pat_[A-Za-z0-9_]{30,}/ },
  // Classic GitHub tokens share a `gh<x>_` + 36-char shape: ghp_ (PAT), gho_
  // (OAuth), ghu_ (user-to-server), ghs_ (server), ghr_ (refresh).
  { label: 'GitHub token', pattern: /\bgh[oprsu]_[A-Za-z0-9]{36}\b/ },
  { label: 'AWS access key ID', pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { label: 'Google API key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { label: 'Slack token', pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,}/ },
  { label: 'Stripe secret key', pattern: /\b[sr]k_live_[0-9A-Za-z]{16,}\b/ },
  { label: 'Private key (PEM)', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { label: 'Hardcoded password', pattern: /password\s*[=:]\s*\S{8,}/i },
];

/**
 * Mask a matched secret so the finding identifies it without re-exposing it.
 * Scan reports are frequently uploaded (e.g. SARIF to GitHub Code Scanning), so
 * echoing the raw value would leak the very credential the rule exists to catch.
 * Keeps only a short non-sensitive prefix plus the length.
 */
function redactSecret(value: string): string {
  const trimmed = value.trim();
  const prefix = trimmed.slice(0, 4);
  return `${prefix}…[redacted, ${trimmed.length} chars]`;
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
      const matched: string[] = [];

      for (const s of rawStrings) {
        for (const { label, pattern } of SECRET_PATTERNS) {
          if (pattern.test(s)) {
            matched.push(`${label} (${redactSecret(s)})`);
            break;
          }
        }
      }

      if (matched.length > 0) {
        return [
          {
            ruleId: RuleId.EXPOSED_SECRETS,
            severity: Severity.CRITICAL,
            title: 'Potential Secret Exposed in Configuration',
            description:
              'The configuration file appears to contain one or more hardcoded secrets ' +
              '(API keys, tokens, or passwords). Secrets committed to config files can be ' +
              'extracted by anyone with access to the file.',
            evidence: `Matched value(s): ${matched.slice(0, 3).join('; ')}`,
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
