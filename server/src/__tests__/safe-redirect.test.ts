import { describe, expect, it, vi } from "vitest";
import { isSafeInternalPath, safeRedirect } from "../routes/safe-redirect.js";

function redirectedTo(target: unknown, options?: Parameters<typeof safeRedirect>[3]) {
  const redirect = vi.fn();
  safeRedirect({ redirect } as never, 303, target, options);
  expect(redirect).toHaveBeenCalledTimes(1);
  return redirect.mock.calls[0]!;
}

describe("safe redirects", () => {
  it.each([
    "/PAP/apps/connections?cloud_connector=enrolled",
    "/",
    "/PAP/apps/chat/connect?provider=slack&resume=abc",
    "/%2F%2Fevil.example",
  ])("allows the internal path %s", (path) => {
    expect(isSafeInternalPath(path)).toBe(true);
    expect(redirectedTo(path)).toEqual([303, path]);
  });

  it.each([
    "//evil.example",
    "//evil.example/path",
    "/\\evil.example",
    "\\\\evil.example",
    "https://evil.example",
    "http://evil.example/",
    "javascript:alert(1)",
    "data:text/html,<script>1</script>",
    "evil.example",
    "",
    " /spaces",
    "/line\nbreak",
    "/tab\tbed",
    undefined,
    null,
    42,
  ])("replaces %j with the fallback", (target) => {
    expect(isSafeInternalPath(target)).toBe(false);
    expect(redirectedTo(target)).toEqual([303, "/"]);
    expect(redirectedTo(target, { fallback: "/home" })).toEqual([303, "/home"]);
  });

  it("allows absolute URLs only on listed origins", () => {
    const options = { allowedOrigins: ["https://github.com"] };
    expect(redirectedTo("https://github.com/apps/example/installations/new", options)[1]).toBe("https://github.com/apps/example/installations/new");
    expect(redirectedTo("https://github.com.evil.example/x", options)[1]).toBe("/");
    expect(redirectedTo("https://user:pass@github.com/x", options)[1]).toBe("/");
    expect(redirectedTo("https://evil.example/", options)[1]).toBe("/");
  });
});
