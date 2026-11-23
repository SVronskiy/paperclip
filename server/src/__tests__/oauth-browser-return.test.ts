import { describe, expect, it } from "vitest";
import { oauthCallbackInterstitialHtml } from "../lib/oauth-browser-return.js";

describe("OAuth callback interstitial", () => {
  it("repeats the same-origin callback request through a meta refresh", () => {
    const html = oauthCallbackInterstitialHtml("/api/tool-access/callback?code=abc&state=xyz");
    expect(html).toContain('content="0;url=/api/tool-access/callback?code=abc&amp;state=xyz"');
  });

  it("escapes every character that can break out of the attribute", () => {
    const html = oauthCallbackInterstitialHtml(`/cb?x="><script>alert(1)</script>'&y=1`);
    expect(html).not.toContain("<script>");
    expect(html).toContain("&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;&#39;&amp;y=1");
  });

  it.each(["https://evil.example/", "//evil.example/", "/\\evil.example", "javascript:alert(1)", "/a b", "/a\nb"])(
    "does not redirect to %j",
    (target) => {
      const html = oauthCallbackInterstitialHtml(target);
      expect(html).toContain('content="0"');
      expect(html).not.toContain("url=");
    },
  );

  it("refreshes immediately without a target when none is given", () => {
    expect(oauthCallbackInterstitialHtml()).toContain('content="0"');
  });
});
