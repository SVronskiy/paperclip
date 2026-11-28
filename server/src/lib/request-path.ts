import type { Request } from "express";
import { isSafeInternalPath } from "../routes/safe-redirect.js";

/**
 * The request's own path and query, for code that echoes it into HTML (a
 * template render or an interstitial page). Returns null unless it is a plain
 * same-origin path: `//host`, backslashes, control characters, whitespace and
 * absolute URLs are refused, so no request can make a renderer resolve another
 * host or file scheme.
 */
export function sameOriginRequestPath(req: Pick<Request, "originalUrl">): string | null {
  const value = req.originalUrl;
  return isSafeInternalPath(value) ? value : null;
}
