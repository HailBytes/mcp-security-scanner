/**
 * Host-based transport-security helpers shared by the TLS/transport rules
 * (`MISSING_TLS`, `INSECURE_TRANSPORT`).
 */

/**
 * Extract the lowercased hostname from a transport URL, without the scheme,
 * userinfo, port, or path.
 *
 * Hand-rolled rather than using the WHATWG `URL` parser because the schemes we
 * inspect include `ws://` / `wss://`, and we only ever need the authority's
 * host — a tolerant, dependency-free extraction is enough.
 */
function extractHost(url: string): string | undefined {
  const schemeSep = url.indexOf('://');
  if (schemeSep === -1) return undefined;

  // Everything after the scheme, up to the first path/query/fragment delimiter.
  let authority = url.slice(schemeSep + 3).split(/[/?#]/, 1)[0];

  // Drop any `user:pass@` userinfo prefix.
  const at = authority.lastIndexOf('@');
  if (at !== -1) authority = authority.slice(at + 1);

  if (authority === '') return undefined;

  // IPv6 literal, e.g. `[::1]:8080` → `::1`.
  if (authority.startsWith('[')) {
    const end = authority.indexOf(']');
    if (end === -1) return undefined;
    return authority.slice(1, end).toLowerCase();
  }

  // Strip a `:port` suffix from `host:port`.
  const colon = authority.indexOf(':');
  return (colon === -1 ? authority : authority.slice(0, colon)).toLowerCase();
}

/**
 * True when the URL's host is a loopback address — traffic to it never leaves
 * the local machine, so plaintext HTTP/WS is not a network-interception risk.
 *
 * Loopback hosts are `localhost` (and any `*.localhost` subdomain), the whole
 * IPv4 `127.0.0.0/8` block, and the IPv6 `::1`. This mirrors the W3C Secure
 * Contexts "potentially trustworthy" loopback carve-out that every major
 * browser applies before warning about insecure transport.
 *
 * NOTE: the wildcard bind addresses `0.0.0.0` and `[::]` are deliberately **not**
 * loopback. They make the server reachable on every network interface, so
 * plaintext transport bound there is a genuine exposure and must still be
 * flagged.
 */
export function isLoopbackHost(url: string | undefined): boolean {
  if (!url) return false;
  const host = extractHost(url);
  if (!host) return false;

  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  if (host === '::1') return true;
  // IPv4 127.0.0.0/8 — any 127.x.y.z address.
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) return true;

  return false;
}
