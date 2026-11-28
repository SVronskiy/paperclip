import { describe, expect, it } from "vitest";
import { sameOriginRequestPath } from "../lib/request-path.js";

const path = (originalUrl: string) => sameOriginRequestPath({ originalUrl });

describe("sameOriginRequestPath", () => {
  it("keeps a plain path and query", () => {
    expect(path("/companies/c1/issues?tab=open")).toBe("/companies/c1/issues?tab=open");
    expect(path("/api/tool-access/oauth/callback?code=a%20b&state=s")).toBe("/api/tool-access/oauth/callback?code=a%20b&state=s");
  });
  it.each(["//evil.example/x", "/\\evil.example", "https://evil.example/", "file:///etc/passwd", "/a b", "/a\nb", ""])(
    "refuses %j", (value) => expect(path(value)).toBeNull());
});
