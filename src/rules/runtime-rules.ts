import { Finding, RuleId, Severity } from '../types.js';
import { ParsedMcpConfig } from '../parser.js';
import { Rule } from './index.js';

const SECRET_PATTERNS: Array<{ label: string; pattern: RegExp }> = [
  { label: 'OpenAI API key', pattern: /sk-[a-zA-Z0-9]{20,}/i },
  { label: 'GitHub personal access token', pattern: /ghp_[a-zA-Z0-9]{36}/i },
  { label: 'AWS access key ID', pattern: /AKIA[0-9A-Z]{16}/i },
  { label: 'hardcoded password', pattern: /[Pp]assword\s*[=:]\s*\S{8,}/ },
];

/**
 * Produce a non-reversible preview of a matched secret for use in finding
 * evidence. Scan reports are routinely written to CI logs, SARIF artifacts, and
 * GitHub Code Scanning — surfaces that are often more visible and longer-lived
 * than the config file itself. Echoing the raw secret there would re-expose the
 * very credential the rule is asking the user to rotate. We reveal only the
 * leading characters (which for every pattern above are a structural prefix such
 * as `sk-`, `ghp_`, `AKIA`, or the word `password`, not entropy) plus the total
 * length, which is enough to locate the value without reproducing it.
 */
function maskSecret(value: string): string {
  const visible = value.slice(0, Math.min(4, value.length));
  return `${visible}…[redacted, ${value.length} chars]`;
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
            // Never echo the raw secret into the report — only a masked preview.
            matched.push(`${label} (${maskSecret(s)})`);
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
            evidence: `Detected ${matched.length} likely secret(s): ${matched.slice(0, 3).join('; ')}`,
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
