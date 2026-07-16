/**
 * Loopback-host detection shared by the transport-security rules
 * (`MISSING_TLS`, `INSECURE_TRANSPORT`).
 *
 * Traffic to a loopback address never leaves the machine, so there is no
 * network segment on which plaintext HTTP/WS could be intercepted. Flagging
 * `http://localhost` as a transport-interception risk reports a threat that
 * cannot exist for that host. This mirrors the W3C "Secure Contexts" spec,
 * which classifies `localhost`, `127.0.0.0/8`, and `::1` as *potentially
 * trustworthy*, and matches how browsers exempt loopback from mixed-content
 * and secure-context requirements.
 */

/**
 * True when `url`'s host is a loopback / non-routable local address:
 *   - `localhost` and any `*.localhost` subdomain (RFC 6761)
 *   - IPv4 loopback range `127.0.0.0/8`
 *   - IPv6 loopback `::1`
 *   - the unspecified address `0.0.0.0`, which is never a routable destination
 *
 * Returns false for any non-loopback host and for URLs that cannot be parsed.
 */
export function isLoopbackHost(url: string | undefined): boolean {
  if (!url) return false;

  let host: string;
  try {
    host = new URL(url).hostname;
  } catch {
    return false;
  }

  // URL.hostname wraps IPv6 literals in brackets (e.g. "[::1]") — strip them.
  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.slice(1, -1);
  }
  host = host.toLowerCase();

  // localhost and any *.localhost subdomain.
  if (host === 'localhost' || host.endsWith('.localhost')) return true;

  // IPv6 loopback.
  if (host === '::1') return true;

  // The unspecified address resolves to loopback locally and is never routable.
  if (host === '0.0.0.0') return true;

  // IPv4 loopback range 127.0.0.0/8.
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const octets = m.slice(1).map(Number);
    if (octets.every((o) => o <= 255) && octets[0] === 127) return true;
  }

  return false;
}
