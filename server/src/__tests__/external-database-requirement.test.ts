import { describe, expect, it } from "vitest";
import { assertEmbeddedDatabaseAllowed, isExternalDatabaseRequired } from "../external-database-requirement.js";

describe("external database requirement", () => {
  it("allows the embedded database by default", () => {
    expect(isExternalDatabaseRequired({})).toBe(false);
    expect(() => assertEmbeddedDatabaseAllowed({})).not.toThrow();
    expect(() => assertEmbeddedDatabaseAllowed({ PAPERCLIP_REQUIRE_EXTERNAL_DATABASE: "0" })).not.toThrow();
  });

  it.each(["1", "true", "TRUE", "yes", "on", " 1 "])("refuses the embedded database when the flag is %j", (value) => {
    expect(isExternalDatabaseRequired({ PAPERCLIP_REQUIRE_EXTERNAL_DATABASE: value })).toBe(true);
    expect(() => assertEmbeddedDatabaseAllowed({ PAPERCLIP_REQUIRE_EXTERNAL_DATABASE: value })).toThrow(/external database/);
  });
});
