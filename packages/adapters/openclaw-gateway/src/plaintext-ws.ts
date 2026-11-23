/**
 * Plaintext `ws://` carries the gateway token and every message in the clear, so it
 * is accepted only toward hosts that are not on the public internet: loopback,
 * private and link-local ranges, CGNAT/tailnet addresses, and local-only names.
 * Everything else must use `wss://`. `PAPERCLIP_ALLOW_INSECURE_GATEWAY_WS=1` lifts the
 * rule for an operator who accepts the risk.
 */
const LOCAL_SUFFIXES = [".local", ".lan", ".internal", ".ts.net", ".home.arpa"];

function ipv4Octets(host: string): number[] | null {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!match) return null;
  const octets = match.slice(1).map(Number);
  return octets.every((n) => n <= 255) ? octets : null;
}

export function isNonPublicHost(hostname: string): boolean {
  const host = hostname.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (!host) return false;
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  const v4 = ipv4Octets(host);
  if (v4) {
    const [a, b] = v4 as [number, number, number, number];
    return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
      || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
  }
  if (host.includes(":")) {
    return host === "::1" || /^f[cd][0-9a-f]{2}:/.test(host) || /^fe[89ab][0-9a-f]:/.test(host);
  }
  return LOCAL_SUFFIXES.some((suffix) => host.endsWith(suffix));
}

export function insecureGatewayWsOverride(env: NodeJS.ProcessEnv = process.env): boolean {
  return ["1", "true", "yes", "on"].includes((env.PAPERCLIP_ALLOW_INSECURE_GATEWAY_WS ?? "").trim().toLowerCase());
}

/** True when this URL may be used: wss, or ws toward a non-public host (or the override). */
export function gatewayTransportAllowed(url: URL, env: NodeJS.ProcessEnv = process.env): boolean {
  if (url.protocol === "wss:") return true;
  if (url.protocol !== "ws:") return false;
  return isNonPublicHost(url.hostname) || insecureGatewayWsOverride(env);
}
