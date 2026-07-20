/**
 * Loopback-host detection, shared by the transport-security rules
 * (`MISSING_TLS`, `INSECURE_TRANSPORT`).
 *
 * Traffic to a loopback address never leaves the machine, so plaintext HTTP/WS
 * on loopback is not a network-interception risk. This mirrors the W3C Secure
 * Contexts "potentially trustworthy" carve-out that every major browser applies
 * to `localhost`, `127.0.0.0/8`, and `::1` — the dominant deployment shape for
 * local MCP servers (Claude Desktop, Cursor, VS Code, Windsurf). See issue #48.
 *
 * Note: `0.0.0.0` (and `[::]`) are deliberately NOT treated as loopback. Those
 * are "all interfaces" bind addresses; a server reachable there is reachable
 * over the network, so cleartext transport remains a genuine risk and should
 * still be flagged.
 */

/**
 * True when `host` is a loopback address whose traffic is confined to the local
 * machine: `localhost` (and any `*.localhost` subdomain), the IPv4 range
 * `127.0.0.0/8`, or the IPv6 loopback `::1`.
 */
export function isLoopbackHost(host: string): boolean {
  // Normalise: lowercase, strip an IPv6 bracket wrapper (`[::1]` → `::1`), and
  // drop any IPv6 zone id (`::1%eth0` → `::1`).
  let h = host.trim().toLowerCase();
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  const zone = h.indexOf('%');
  if (zone !== -1) h = h.slice(0, zone);

  // localhost and any *.localhost subdomain (per W3C Secure Contexts).
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  // IPv6 loopback (compressed and fully-expanded forms).
  if (h === '::1' || h === '0:0:0:0:0:0:0:1') return true;
  // IPv4 loopback range 127.0.0.0/8.
  if (/^127(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(h)) return true;

  return false;
}

/**
 * True when `url` parses as a URL whose host is a loopback address. Returns
 * false for anything that does not parse as a URL (a bare host, a stdio
 * command, etc.), so callers fall back to their existing behaviour rather than
 * silently exempting an unparseable target.
 */
export function isLoopbackUrl(url: string): boolean {
  let host: string;
  try {
    host = new URL(url).hostname;
  } catch {
    return false;
  }
  return isLoopbackHost(host);
}
