import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

/** Password used by clusters created before the password became random. */
export const LEGACY_EMBEDDED_POSTGRES_PASSWORD = "paperclip";

export function embeddedPasswordFilePath(dataDir: string): string {
  const resolved = path.resolve(dataDir);
  return path.join(path.dirname(resolved), `${path.basename(resolved)}.password`);
}

function readPasswordFile(file: string): string | null {
  try {
    const value = readFileSync(file, "utf8").trim();
    return value.length > 0 ? value : null;
  } catch {
    return null;
  }
}

/**
 * Password for the embedded PostgreSQL superuser of `dataDir`.
 * Order: PAPERCLIP_EMBEDDED_DB_PASSWORD, the stored file, the legacy value for a
 * cluster that already exists, otherwise a fresh random value stored with mode 0600.
 */
export function resolveEmbeddedPostgresPassword(dataDir: string): string {
  const fromEnv = process.env.PAPERCLIP_EMBEDDED_DB_PASSWORD?.trim();
  if (fromEnv) return fromEnv;
  const file = embeddedPasswordFilePath(dataDir);
  const stored = readPasswordFile(file);
  if (stored) return stored;
  if (existsSync(path.join(dataDir, "PG_VERSION"))) return LEGACY_EMBEDDED_POSTGRES_PASSWORD;
  const generated = randomBytes(24).toString("hex");
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, `${generated}\n`, { mode: 0o600 });
  chmodSync(file, 0o600);
  return generated;
}

/** Replaces the legacy password of an existing cluster; returns the password to use afterwards. */
export async function upgradeLegacyEmbeddedPassword(
  dataDir: string,
  runSql: (password: string, sql: string) => Promise<void>,
): Promise<string> {
  const current = resolveEmbeddedPostgresPassword(dataDir);
  if (current !== LEGACY_EMBEDDED_POSTGRES_PASSWORD) return current;
  if (process.env.PAPERCLIP_EMBEDDED_DB_PASSWORD?.trim()) return current;
  const next = randomBytes(24).toString("hex");
  await runSql(current, `ALTER USER paperclip PASSWORD '${next}'`);
  const file = embeddedPasswordFilePath(dataDir);
  writeFileSync(file, `${next}\n`, { mode: 0o600 });
  chmodSync(file, 0o600);
  return next;
}

export function embeddedPostgresUrl(dataDir: string, port: number, database: string): string {
  const password = encodeURIComponent(resolveEmbeddedPostgresPassword(dataDir));
  return `postgres://paperclip:${password}@127.0.0.1:${port}/${database}`;
}

/** Best-effort upgrade of a legacy cluster that is already running on `port`. */
export async function upgradeLegacyEmbeddedPasswordOnPort(dataDir: string, port: number): Promise<void> {
  const { default: postgres } = await import("postgres");
  await upgradeLegacyEmbeddedPassword(dataDir, async (password, sql) => {
    const client = postgres(
      `postgres://paperclip:${encodeURIComponent(password)}@127.0.0.1:${port}/postgres`,
      { max: 1 },
    );
    try {
      await client.unsafe(sql);
    } finally {
      await client.end();
    }
  });
}
