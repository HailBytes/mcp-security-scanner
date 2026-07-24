import { Finding, RuleId, Severity } from '../types.js';
import { ParsedMcpConfig } from '../parser.js';
import { Rule } from './index.js';

/**
 * Auth `type` values that explicitly mean "no authentication". A config that
 * declares one of these is unauthenticated, even though the `auth` block exists.
 */
const DISABLED_AUTH_TYPES = new Set(['none', 'disabled', 'off', 'false', 'anonymous']);

/**
 * Auth `type` values that name a mechanism whose secret is carried in the
 * config itself (`auth.apiKey` / `auth.token`). Declaring one of these types
 * WITHOUT also providing a credential is not authentication — the server would
 * accept unauthenticated clients because there is no secret to check against.
 *
 * Certificate-based mechanisms (e.g. `mtls`) are deliberately excluded: their
 * credential is a certificate configured outside this block, so a bare
 * `type: "mtls"` is treated as meaningful auth rather than a missing credential.
 */
const CREDENTIAL_REQUIRING_AUTH_TYPES = new Set([
  'bearer',
  'token',
  'apikey',
  'api_key',
  'api-key',
  'basic',
  'oauth',
  'oauth2',
  'digest',
]);

/** True when a value looks like a JWT: three non-empty base64url segments. */
function isJwt(value: string): boolean {
  return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value);
}

export const authRules: Rule[] = [
  {
    id: RuleId.NO_AUTH,
    severity: Severity.CRITICAL,
    title: 'No Authentication Configured',
    check(config: ParsedMcpConfig): Finding[] {
      const auth = config.transport?.auth;
      // A real credential always counts as auth.
      const hasCredential = Boolean(auth?.apiKey || auth?.token);
      const type = auth?.type?.trim().toLowerCase();
      // Values like "none" or "disabled" explicitly opt out of authentication.
      const typeIsDisabled = Boolean(type) && DISABLED_AUTH_TYPES.has(type as string);
      // Mechanisms whose secret lives in this block (bearer/apikey/basic/…) are
      // only real auth once that secret is actually present — a bare type with
      // no credential leaves the server open. See #54.
      const typeRequiresCredential =
        Boolean(type) && CREDENTIAL_REQUIRING_AUTH_TYPES.has(type as string);
      // A non-empty type that names neither a disabled nor a credential-in-config
      // mechanism (e.g. "mtls", "certificate", or a custom scheme) is treated as
      // meaningful auth on its own — its credential is configured elsewhere.
      const hasMeaningfulType = Boolean(type) && !typeIsDisabled && !typeRequiresCredential;
      const hasAuth = hasCredential || hasMeaningfulType;

      if (!hasAuth) {
        let evidence: string;
        let description: string;
        if (typeRequiresCredential) {
          // "Mechanism declared, secret missing": the config names a
          // credential-based scheme but ships no apiKey/token to enforce it.
          evidence = `transport.auth.type: "${auth?.type}" declared, but no credential (apiKey/token) is configured`;
          description =
            `The MCP server declares "${auth?.type}" authentication but provides no credential. ` +
            'With no secret to verify, the server cannot actually authenticate clients — ' +
            'any client can connect and invoke tools.';
        } else if (typeIsDisabled) {
          evidence = `transport.auth.type: "${auth?.type}" (authentication explicitly disabled)`;
          description =
            'The MCP server transport has no authentication configured. ' +
            'Any client can connect and invoke tools without credentials.';
        } else {
          evidence = 'transport.auth: absent';
          description =
            'The MCP server transport has no authentication configured. ' +
            'Any client can connect and invoke tools without credentials.';
        }

        return [
          {
            ruleId: RuleId.NO_AUTH,
            severity: Severity.CRITICAL,
            title: 'No Authentication Configured',
            description,
            evidence,
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
    title: 'Weak Credential (< 32 characters)',
    check(config: ParsedMcpConfig): Finding[] {
      const auth = config.transport?.auth;
      const findings: Finding[] = [];

      // Both `apiKey` and `token` are accepted as credentials by NO_AUTH, so
      // both must be strength-checked. A short opaque credential of either kind
      // is equally brute-forceable.
      const candidates: Array<{ field: 'apiKey' | 'token'; label: string }> = [
        { field: 'apiKey', label: 'API key' },
        { field: 'token', label: 'bearer token' },
      ];

      for (const { field, label } of candidates) {
        const value = auth?.[field];
        if (typeof value !== 'string') continue;
        // Skip JWTs: they are structured (three base64url segments) and
        // effectively always longer than 32 chars, so length is not meaningful.
        if (field === 'token' && isJwt(value)) continue;
        if (value.length >= 32) continue;

        findings.push({
          ruleId: RuleId.WEAK_API_KEY,
          severity: Severity.HIGH,
          title: `Weak ${label === 'API key' ? 'API Key' : 'Bearer Token'} (< 32 characters)`,
          description:
            `The configured ${label} is only ${value.length} characters long. ` +
            'Short credentials are vulnerable to brute-force attacks.',
          evidence: `${field} length: ${value.length}`,
          remediation:
            `Generate a cryptographically random ${label} of at least 32 characters ` +
            '(preferably 64+). Use a secrets manager to store it.',
          docsUrl: 'https://hailbytes.com/mcp/docs/rules/WEAK_API_KEY',
        });
      }

      return findings;
    },
  },

  {
    id: RuleId.MISSING_TLS,
    severity: Severity.HIGH,
    title: 'Missing TLS — Server Uses Plain HTTP',
    check(config: ParsedMcpConfig): Finding[] {
      const url = config.transport?.url ?? config.serverUrl;
      const isTls = config.transport?.tls;

      // This rule is specifically about the HTTP family ("Server Uses Plain
      // HTTP"). WebSocket security is owned by INSECURE_TRANSPORT: ws:// is
      // flagged there, and wss:// is already TLS-encrypted. Excluding both
      // avoids a false positive on wss:// and double-counting on ws://.
      const isWebSocket = url?.startsWith('ws://') || url?.startsWith('wss://');

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
