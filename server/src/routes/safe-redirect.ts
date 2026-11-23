import type { Response } from "express";
import { logger } from "../middleware/logger.js";

/**
 * A same-origin path that a browser cannot interpret as another host: it starts
 * with exactly one `/` and has no backslash, control character or whitespace.
 * `//evil.example`, `/\evil.example`, `https://evil.example` and
 * `javascript:alert(1)` are all rejected.
 */
export function isSafeInternalPath(target: unknown): target is string {
  if (typeof target !== "string" || target.length === 0 || target.length > 4096) return false;
  if (!target.startsWith("/") || target.startsWith("//")) return false;
  // eslint-disable-next-line no-control-regex
  return !/[\\\u0000- \u007f]/.test(target);
}

/**
 * Redirects only to an internal path (or, when listed, an absolute URL on an
 * allowed origin). Anything else is replaced by `fallback`, so a value that
 * ends up attacker-influenced can never send the browser to another site.
 */
export function safeRedirect(
  res: Pick<Response, "redirect">,
  status: 301 | 302 | 303 | 307 | 308,
  target: unknown,
  options: { allowedOrigins?: readonly string[]; fallback?: string } = {},
): void {
  const fallback = options.fallback ?? "/";
  if (isSafeInternalPath(target)) {
    res.redirect(status, target);
    return;
  }
  if (typeof target === "string" && options.allowedOrigins?.length) {
    try {
      const url = new URL(target);
      if ((url.protocol === "https:" || url.protocol === "http:") && !url.username && !url.password
        && options.allowedOrigins.includes(url.origin)) {
        res.redirect(status, url.href);
        return;
      }
    } catch {
      // Not an absolute URL: fall through to the fallback.
    }
  }
  logger.warn({ rejectedRedirect: true }, "blocked a redirect to a target outside the allowed origins");
  res.redirect(status, fallback);
}

/** Absolute URL a service may hand back: https, or http only on a loopback host, no credentials. */
export function isSafeAbsoluteRedirect(target: unknown): target is string {
  if (typeof target !== "string" || target.length === 0 || target.length > 4096) return false;
  try {
    const url = new URL(target);
    if (url.username || url.password) return false;
    return url.protocol === "https:"
      || (url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname));
  } catch {
    return false;
  }
}

/**
 * For redirects whose target a service already validated against a registered
 * client or a fixed integration (OAuth `redirect_uri`, GitHub app callbacks):
 * this is the last gate in front of `res.redirect`. It accepts only an internal
 * path or an absolute https (or loopback http) URL without credentials, and
 * replaces anything else (`javascript:`, `//host`, `data:`) with `fallback`.
 */
export function redirectToValidatedLocation(
  res: Pick<Response, "redirect">,
  status: 301 | 302 | 303 | 307 | 308,
  target: unknown,
  fallback = "/",
): void {
  if (isSafeInternalPath(target) || isSafeAbsoluteRedirect(target)) {
    res.redirect(status, target);
    return;
  }
  logger.warn({ rejectedRedirect: true }, "blocked a redirect to an unsupported target");
  res.redirect(status, fallback);
}
