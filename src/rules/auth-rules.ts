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

/**
 * Common default/weak credentials. Matched against the *whole* normalized
 * credential (lowercased, separators removed) so a real random key can never
 * collide — only a credential that is exactly one of these values is flagged.
 */
const DEFAULT_CREDENTIALS = new Set([
  'password', 'passw0rd', 'password123', 'admin', 'administrator', 'root',
  'secret', 'test', 'testing', 'changeit', 'changeme', 'default', 'letmein',
  'qwerty', '123456', '12345678', '123456789', 'abc123', 'foobar', 'foo',
  'bar', 'baz', 'example', 'dummy', 'sample', 'token', 'apikey', 'key',
  'mysecret', 'topsecret', 'supersecret', 'hunter2', 'guest', 'demo',
]);

/**
 * High-signal placeholder phrases. If the normalized credential *contains* one
 * of these, it is almost certainly an unfilled placeholder rather than a real
 * secret (e.g. `your-api-key-here`, `CHANGE_ME`, `<replace-me>`). Kept to
 * multi-character, unambiguous phrases to hold the false-positive rate near
 * zero — no bare `key`/`token`/`test` substrings.
 */
const PLACEHOLDER_SUBSTRINGS = [
  'changeme', 'changethis', 'replaceme', 'replacethis', 'yourapikey',
  'yourtoken', 'yoursecret', 'yourkey', 'yourpassword', 'placeholder',
  'insertyour', 'apikeyhere', 'tokenhere', 'keyhere', 'secrethere',
  'putyourkey', 'notarealkey', 'notreal', 'examplekey', 'exampletoken',
  'sampletoken', 'samplekey', 'redacted',
];

/** Normalize a credential for comparison: lowercase, strip non-alphanumerics. */
function normalizeCredential(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/**
 * Decide whether a credential value is a placeholder / default / example.
 * Returns a short reason label for the finding, or null if it looks real.
 */
function placeholderReason(value: string): string | null {
  // Unresolved template markers: <your-key>, {{API_KEY}}, ${API_KEY}.
  if (/<[^>]+>/.test(value) || /\{\{.*\}\}/.test(value) || /\$\{.*\}/.test(value)) {
    return 'unresolved template placeholder';
  }
  // A run of 8+ identical filler characters (e.g. "xxxxxxxx", "00000000").
  if (/(.)\1{7,}/.test(value)) {
    return 'filler/repeated-character placeholder';
  }
  const norm = normalizeCredential(value);
  if (DEFAULT_CREDENTIALS.has(norm)) {
    return 'known default/weak credential';
  }
  if (PLACEHOLDER_SUBSTRINGS.some((p) => norm.includes(p))) {
    return 'placeholder/example credential';
  }
  return null;
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
    id: RuleId.PLACEHOLDER_CREDENTIAL,
    severity: Severity.HIGH,
    title: 'Placeholder or Default Credential',
    check(config: ParsedMcpConfig): Finding[] {
      const auth = config.transport?.auth;
      const findings: Finding[] = [];

      // Only the credential fields are inspected: NO_AUTH accepts any non-empty
      // apiKey/token as "auth configured", and WEAK_API_KEY only checks length —
      // so a *long* placeholder (e.g. "your-api-key-here-replace-before-prod")
      // sails through both. This rule closes that gap.
      const candidates: Array<{ field: 'apiKey' | 'token'; label: string }> = [
        { field: 'apiKey', label: 'API key' },
        { field: 'token', label: 'bearer token' },
      ];

      for (const { field, label } of candidates) {
        const value = auth?.[field];
        if (typeof value !== 'string' || value === '') continue;
        const reason = placeholderReason(value);
        if (!reason) continue;

        findings.push({
          ruleId: RuleId.PLACEHOLDER_CREDENTIAL,
          severity: Severity.HIGH,
          title: 'Placeholder or Default Credential',
          description:
            `The configured ${label} appears to be a ${reason} rather than a real, ` +
            'unique secret. Placeholder or default credentials are publicly known ' +
            'and let anyone authenticate as a legitimate client.',
          // The matched value is a placeholder/default (not a real secret), so
          // echoing a short slice of it is safe and helps locate the field.
          evidence: `${field}: "${value.length > 32 ? value.slice(0, 29) + '...' : value}" (${reason})`,
          remediation:
            `Replace the ${label} with a cryptographically random value of at least ` +
            '32 characters and store it in a secrets manager, never committed to config.',
          docsUrl: 'https://hailbytes.com/mcp/docs/rules/PLACEHOLDER_CREDENTIAL',
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
