/**
 * Network-address helpers shared by the transport-security rules.
 */

/**
 * True when `url`'s host is a loopback address — traffic to it never leaves the
 * machine, so plaintext HTTP/WS on it is not a network-interception risk.
 *
 * Mirrors the W3C "Secure Contexts" loopback carve-out (localhost, 127.0.0.0/8,
 * ::1), which every major browser treats as "potentially trustworthy". The
 * bind-all addresses `0.0.0.0` / `::` are included too: a URL naming one is a
 * local dev target, not a public network endpoint.
 *
 * Any non-loopback host (including a URL that cannot be parsed) returns false so
 * the caller's transport check runs as before.
 */
export function isLoopbackHost(url: string): boolean {
  let hostname: string;
  try {
    hostname = new URL(url).hostname;
  } catch {
    return false;
  }

  // URL.hostname keeps IPv6 addresses bracketed (e.g. "[::1]"); strip them.
  const host = hostname.replace(/^\[/, '').replace(/\]$/, '').toLowerCase();

  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  if (host === '::1' || host === '::' || host === '0.0.0.0') return true;
  // 127.0.0.0/8 — any 127.x.x.x address.
  if (/^127(?:\.\d{1,3}){3}$/.test(host)) return true;

  return false;
}
