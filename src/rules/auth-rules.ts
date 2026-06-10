import { Finding, RuleId, Severity } from '../types.js';
import { ParsedMcpConfig } from '../parser.js';
import { Rule } from './index.js';

export const authRules: Rule[] = [
  {
    id: RuleId.NO_AUTH,
    severity: Severity.CRITICAL,
    title: 'No Authentication Configured',
    check(config: ParsedMcpConfig): Finding[] {
      const hasAuth = config.transport?.auth &&
        (config.transport.auth.apiKey ||
         config.transport.auth.token ||
         config.transport.auth.type);

      if (!hasAuth) {
        return [
          {
            ruleId: RuleId.NO_AUTH,
            severity: Severity.CRITICAL,
            title: 'No Authentication Configured',
            description:
              'The MCP server transport has no authentication configured. ' +
              'Any client can connect and invoke tools without credentials.',
            remediation:
              'Configure authentication in transport.auth (e.g., apiKey, bearer token, or mTLS).',
            docsUrl: 'https://hailbytes.com/mcp/docs/rules/NO_AUTH',
          },
        ];
      }
      return [];
    },
  },

  {
    id: RuleId.WEAK_API_KEY,
    severity: Severity.HIGH,
    title: 'Weak API Key (< 32 characters)',
    check(config: ParsedMcpConfig): Finding[] {
      const apiKey = config.transport?.auth?.apiKey;
      if (typeof apiKey === 'string' && apiKey.length < 32) {
        return [
          {
            ruleId: RuleId.WEAK_API_KEY,
            severity: Severity.HIGH,
            title: 'Weak API Key (< 32 characters)',
            description:
              `The configured API key is only ${apiKey.length} characters long. ` +
              'Short keys are vulnerable to brute-force attacks.',
            evidence: `apiKey length: ${apiKey.length}`,
            remediation:
              'Generate a cryptographically random API key of at least 32 characters ' +
              '(preferably 64+). Use a secrets manager to store it.',
            docsUrl: 'https://hailbytes.com/mcp/docs/rules/WEAK_API_KEY',
          },
        ];
      }
      return [];
    },
  },

  {
    id: RuleId.MISSING_TLS,
    severity: Severity.HIGH,
    title: 'Missing TLS — Server Uses Plain HTTP',
    check(config: ParsedMcpConfig): Finding[] {
      const url = config.transport?.url ?? config.serverUrl;
      const isTls = config.transport?.tls;

      // WebSocket transports are out of scope for this rule: ws:// is reported by
      // INSECURE_TRANSPORT, and wss:// is already TLS-encrypted. Without this guard a
      // secure wss:// endpoint is wrongly flagged as "plain HTTP" because it neither
      // starts with https:// nor sets transport.tls.
      const isWebSocket =
        !!url && (url.startsWith('ws://') || url.startsWith('wss://'));

      if (
        url &&
        !isWebSocket &&
        (url.startsWith('http://') || (!isTls && !url.startsWith('https://')))
      ) {
        return [
          {
            ruleId: RuleId.MISSING_TLS,
            severity: Severity.HIGH,
            title: 'Missing TLS — Server Uses Plain HTTP',
            description:
              'The server URL uses plain HTTP (not HTTPS). ' +
              'All traffic — including authentication tokens and tool payloads — is sent in cleartext.',
            evidence: `serverUrl: ${url}`,
            remediation:
              'Configure TLS on the server and use an https:// URL. ' +
              'Obtain a certificate from a trusted CA or use Let\'s Encrypt.',
            docsUrl: 'https://hailbytes.com/mcp/docs/rules/MISSING_TLS',
          },
        ];
      }
      return [];
    },
  },
];
