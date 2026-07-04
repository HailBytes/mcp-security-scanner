import { Finding, RuleId, Severity } from '../types.js';
import { ParsedMcpConfig } from '../parser.js';
import { Rule } from './index.js';
import { isLoopbackHost } from './url-utils.js';

/**
 * Auth `type` values that explicitly mean "no authentication". A config that
 * declares one of these is unauthenticated, even though the `auth` block exists.
 */
const DISABLED_AUTH_TYPES = new Set(['none', 'disabled', 'off', 'false', 'anonymous']);

/**
 * Auth `type` values whose credential is an *in-config* secret (an `apiKey` or
 * `token`). For these, declaring the type without also supplying the secret is
 * not authentication — it is exactly the "auth looks configured but isn't"
 * misconfiguration NO_AUTH exists to catch (e.g. a templated `token:
 * "${MCP_TOKEN}"` whose env var never populated). Contrast with mechanisms like
 * `mtls`/`oauth`/`oidc`, whose credential lives outside the config (a client
 * cert, an IdP handshake) and so legitimately pass on the type alone.
 */
const CREDENTIAL_REQUIRED_AUTH_TYPES = new Set([
  'bearer',
  'token',
  'apikey',
  'api_key',
  'api-key',
  'basic',
]);

/** True when a value is a present, non-blank string credential. */
function hasCredentialValue(value?: string): boolean {
  return typeof value === 'string' && value.trim() !== '';
}

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
      // A real credential always counts as auth. Empty/blank strings do not —
      // `apiKey: ""` is an absent secret, not a (weak) one.
      const hasCredential =
        hasCredentialValue(auth?.apiKey) || hasCredentialValue(auth?.token);
      // An auth `type` only counts when it names a real mechanism — values like
      // "none" or "disabled" explicitly opt out of authentication.
      const type = auth?.type?.trim().toLowerCase();
      const hasType = Boolean(type);
      const isDisabledType = hasType && DISABLED_AUTH_TYPES.has(type as string);
      const isCredentialRequiredType =
        hasType && CREDENTIAL_REQUIRED_AUTH_TYPES.has(type as string);
      // A meaningful type is one that is neither "off" nor a mechanism that
      // still needs an in-config secret to actually authenticate anything.
      const hasExternalCredentialType =
        hasType && !isDisabledType && !isCredentialRequiredType;

      // Authenticated when a real credential is present, or the mechanism keeps
      // its credential outside the config (mtls/oauth/…). A credential-required
      // type with no in-config secret is NOT authenticated.
      const hasAuth = hasCredential || hasExternalCredentialType;

      if (!hasAuth) {
        let evidence: string;
        let description: string;
        if (isCredentialRequiredType) {
          evidence = `transport.auth.type: "${auth?.type}" declared, but no apiKey/token credential is set`;
          description =
            `The MCP server declares "${auth?.type}" authentication but supplies no ` +
            'apiKey/token credential, so no client is actually required to authenticate. ' +
            'This is the classic "auth looks configured but isn\'t" gap — e.g. a ' +
            'deploy-time secret that never populated.';
        } else if (isDisabledType) {
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
        // An empty/blank value is an *absent* credential, not a weak one — that
        // case is owned by NO_AUTH. Reporting it here would mislabel "no
        // credential" as "short credential" (and let a hollow apiKey pass the
        // gate as a mere HIGH).
        if (value.trim() === '') continue;
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
    id: RuleId.CREDENTIALS_IN_URL,
    severity: Severity.HIGH,
    title: 'Credentials Embedded in Transport URL',
    check(config: ParsedMcpConfig): Finding[] {
      const url = config.transport?.url ?? config.serverUrl;
      if (!url) return [];

      let parsed: URL;
      try {
        parsed = new URL(url);
      } catch {
        return []; // Not a parseable URL — nothing to inspect.
      }

      // The userinfo component (`user[:password]@host`) embeds credentials
      // directly in the connection string. A bare `user@` still leaks the
      // account identity, so any non-empty username is worth flagging.
      if (parsed.username === '') return [];

      const hasPassword = parsed.password !== '';
      // Never echo the secret back. Redact the password, keep enough of the
      // URL for the finding to be actionable.
      const path = parsed.pathname === '/' ? '' : parsed.pathname;
      const redacted = `${parsed.protocol}//${parsed.username}${
        hasPassword ? ':***' : ''
      }@${parsed.host}${path}`;

      return [
        {
          ruleId: RuleId.CREDENTIALS_IN_URL,
          severity: Severity.HIGH,
          title: 'Credentials Embedded in Transport URL',
          description:
            'The transport URL embeds credentials in its userinfo component ' +
            '(user:password@host). Credentials placed in a URL routinely leak ' +
            'through access logs, proxy logs, browser history, and Referer ' +
            'headers — TLS does not protect them, because the exposure happens ' +
            'at the endpoints, not on the wire.',
          evidence: `transport.url: ${redacted}`,
          remediation:
            'Remove the credentials from the URL. Authenticate via ' +
            'transport.auth (apiKey, bearer token, or mTLS) or an Authorization ' +
            'header instead, and source the secret from an environment variable ' +
            'or a secrets manager rather than the connection string.',
          docsUrl: 'https://hailbytes.com/mcp/docs/rules/CREDENTIALS_IN_URL',
        },
      ];
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

      // Cleartext to a loopback host (localhost / 127.0.0.0/8 / ::1) never
      // traverses the network, so it is not an eavesdropping risk. Suppress the
      // finding to avoid a false HIGH on the common local-dev setup. See #48.
      if (
        url &&
        !isWebSocket &&
        !isLoopbackHost(url) &&
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
