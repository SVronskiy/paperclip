/**
 * Vets a redirect URL before the board navigates the whole window to it.
 *
 * Only `https:` URLs, `http:` URLs on a loopback host (native OAuth clients
 * listen there, RFC 8252) and same-origin relative paths are allowed. `javascript:`,
 * `data:`, `file:` and URLs with embedded credentials are rejected, so a bad
 * value from a response body cannot run script or send the user somewhere
 * unexpected.
 */
export function resolveSafeNavigationUrl(value: string | null | undefined, base?: string): string | null {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096) return null;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f\\]/.test(value)) return null;
  const origin = base ?? (typeof window !== "undefined" ? window.location.origin : "http://localhost");
  let url: URL;
  try {
    url = new URL(value, origin);
  } catch {
    return null;
  }
  if (url.username || url.password) return null;
  if (url.protocol === "https:") return url.href;
  if (url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) return url.href;
  if (url.origin === origin && (url.protocol === "http:" || url.protocol === "https:")) return url.href;
  return null;
}

/** Navigates the window to `value` when it passes `resolveSafeNavigationUrl`; returns whether it navigated. */
export function navigateIfSafe(value: string | null | undefined): boolean {
  const safe = resolveSafeNavigationUrl(value);
  if (!safe) return false;
  window.location.assign(safe);
  return true;
}
