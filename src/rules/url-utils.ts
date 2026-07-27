/**
 * Shared URL helpers for transport-security rules.
 */

/**
 * True when `url` targets a loopback host — `localhost` (and any `*.localhost`
 * name, per RFC 6761), the IPv4 loopback range `127.0.0.0/8`, or IPv6 `::1`.
 *
 * Cleartext transport (`http://`, `ws://`) to a loopback address never leaves
 * the machine, so it is not a network-eavesdropping risk. The `MISSING_TLS` and
 * `INSECURE_TRANSPORT` rules use this to avoid firing a false HIGH on the most
 * common local-development setup (e.g. `http://localhost:3000`).
 */
export function isLoopbackHost(url: string): boolean {
  if (!url) return false;

  let host: string;
  try {
    host = new URL(url).hostname;
  } catch {
    // Fall back to manual extraction for inputs the WHATWG parser rejects:
    // drop the scheme, any userinfo, the path/query/fragment, and the port.
    const noScheme = url.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, '');
    host = noScheme.split(/[/?#]/)[0].split('@').pop() ?? '';
    host = host.replace(/:\d+$/, '');
  }

  // Strip IPv6 brackets (`[::1]` → `::1`) and normalize case.
  host = host.replace(/^\[|\]$/g, '').toLowerCase();

  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  if (host === '::1') return true;
  // IPv4 loopback: 127.0.0.0/8 (the WHATWG parser normalizes shorthands like
  // `127.1` to `127.0.0.1`, so a dotted-quad test is sufficient here).
  if (/^127(?:\.\d{1,3}){3}$/.test(host)) return true;

  return false;
}
