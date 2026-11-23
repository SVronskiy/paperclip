import { describe, expect, it } from "vitest";
import { resolveSafeNavigationUrl } from "./safe-navigation";

const base = "https://board.example.test";

describe("resolveSafeNavigationUrl", () => {
  it.each([
    ["https://client.example.com/callback?code=1&state=2", "https://client.example.com/callback?code=1&state=2"],
    ["http://127.0.0.1:8123/callback", "http://127.0.0.1:8123/callback"],
    ["http://localhost:3000/cb", "http://localhost:3000/cb"],
    ["/PAP/issues", "https://board.example.test/PAP/issues"],
  ])("allows %s", (value, expected) => {
    expect(resolveSafeNavigationUrl(value, base)).toBe(expected);
  });

  it.each([
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "file:///etc/passwd",
    "http://evil.example.test/cb",
    "https://user:pass@client.example.com/cb",
    "//evil.example.test/cb\\x",
    "/\\evil.example.test",
    "https://client.example.com/\ninjected",
    "",
    null,
    undefined,
  ])("rejects %j", (value) => {
    expect(resolveSafeNavigationUrl(value as string | null | undefined, base)).toBeNull();
  });
});
