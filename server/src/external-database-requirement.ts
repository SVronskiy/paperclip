/**
 * The embedded PostgreSQL cluster is for local development: its superuser
 * password is fixed and it lives on the same host as the server. An operator
 * who needs an external database (a pilot, a shared environment) sets
 * `PAPERCLIP_REQUIRE_EXTERNAL_DATABASE`, and startup then refuses to fall back
 * to the embedded cluster instead of silently using it.
 */
export function isExternalDatabaseRequired(env: NodeJS.ProcessEnv = process.env): boolean {
  const value = env.PAPERCLIP_REQUIRE_EXTERNAL_DATABASE?.trim().toLowerCase();
  return value === "1" || value === "true" || value === "yes" || value === "on";
}

export function assertEmbeddedDatabaseAllowed(env: NodeJS.ProcessEnv = process.env): void {
  if (!isExternalDatabaseRequired(env)) return;
  throw new Error(
    "PAPERCLIP_REQUIRE_EXTERNAL_DATABASE is set, but no external database is configured. " +
      "Set DATABASE_URL (or database.connectionString in the config file) to an external PostgreSQL server; " +
      "the embedded database is for local development only.",
  );
}
