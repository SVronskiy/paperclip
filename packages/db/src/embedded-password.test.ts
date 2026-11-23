import { mkdtempSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  LEGACY_EMBEDDED_POSTGRES_PASSWORD,
  embeddedPasswordFilePath,
  embeddedPostgresUrl,
  resolveEmbeddedPostgresPassword,
  upgradeLegacyEmbeddedPassword,
} from "./embedded-password.js";

const saved = process.env.PAPERCLIP_EMBEDDED_DB_PASSWORD;
afterEach(() => {
  if (saved === undefined) delete process.env.PAPERCLIP_EMBEDDED_DB_PASSWORD;
  else process.env.PAPERCLIP_EMBEDDED_DB_PASSWORD = saved;
});

function instance() {
  delete process.env.PAPERCLIP_EMBEDDED_DB_PASSWORD;
  const root = mkdtempSync(path.join(os.tmpdir(), "pc-pw-"));
  const dataDir = path.join(root, "db");
  mkdirSync(dataDir);
  return { root, dataDir };
}

describe("embedded postgres password", () => {
  it("generates a random password for a new cluster and keeps it", () => {
    const { dataDir } = instance();
    const first = resolveEmbeddedPostgresPassword(dataDir);
    expect(first).not.toBe(LEGACY_EMBEDDED_POSTGRES_PASSWORD);
    expect(first).toMatch(/^[0-9a-f]{48}$/);
    expect(resolveEmbeddedPostgresPassword(dataDir)).toBe(first);
    expect(statSync(embeddedPasswordFilePath(dataDir)).mode & 0o777).toBe(0o600);
  });

  it("keeps the legacy password for a cluster that already exists", () => {
    const { dataDir } = instance();
    writeFileSync(path.join(dataDir, "PG_VERSION"), "17\n");
    expect(resolveEmbeddedPostgresPassword(dataDir)).toBe(LEGACY_EMBEDDED_POSTGRES_PASSWORD);
  });

  it("upgrades a legacy cluster and stores the new password", async () => {
    const { dataDir } = instance();
    writeFileSync(path.join(dataDir, "PG_VERSION"), "17\n");
    const calls: string[] = [];
    const next = await upgradeLegacyEmbeddedPassword(dataDir, async (pw, sql) => {
      calls.push(`${pw}|${sql.slice(0, 16)}`);
    });
    expect(next).not.toBe(LEGACY_EMBEDDED_POSTGRES_PASSWORD);
    expect(calls).toEqual([`${LEGACY_EMBEDDED_POSTGRES_PASSWORD}|ALTER USER paper`]);
    expect(readFileSync(embeddedPasswordFilePath(dataDir), "utf8").trim()).toBe(next);
    expect(resolveEmbeddedPostgresPassword(dataDir)).toBe(next);
  });

  it("honours the environment override", () => {
    const { dataDir } = instance();
    process.env.PAPERCLIP_EMBEDDED_DB_PASSWORD = "from env/1";
    expect(embeddedPostgresUrl(dataDir, 5, "x")).toBe("postgres://paperclip:from%20env%2F1@127.0.0.1:5/x");
  });
});
