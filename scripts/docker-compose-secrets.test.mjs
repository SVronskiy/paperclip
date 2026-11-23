import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("../", import.meta.url));
const baseEnv = Object.fromEntries(
  ["PATH", "HOME", "SystemRoot", "ComSpec", "TEMP", "TMP", "USERPROFILE"]
    .filter((key) => process.env[key] !== undefined)
    .map((key) => [key, process.env[key]]),
);
const compose = spawnSync("docker", ["compose", "version"], { env: baseEnv });
assert.equal(compose.status, 0, "Docker Compose is required for this integration check.");

for (const [file, service] of [
  ["docker/docker-compose.quickstart.yml", "paperclip"],
  ["docker/docker-compose.yml", "server"],
]) {
  test(`${file} forwards the independent tool signing secret`, () => {
    const temporary = mkdtempSync(path.join(os.tmpdir(), "paperclip-compose-secrets-"));
    const envFile = path.join(temporary, "empty.env");
    writeFileSync(envFile, "");
    try {
      for (const signingSecret of ["test-tool-signing-secret", undefined]) {
        const env = { ...baseEnv, BETTER_AUTH_SECRET: "test-session-secret", POSTGRES_PASSWORD: "test-db-password" };
        if (signingSecret !== undefined) env.PAPERCLIP_TOOL_ACTION_SIGNING_SECRET = signingSecret;
        const result = spawnSync("docker", [
          "compose", "--env-file", envFile, "-f", file, "config", "--format", "json",
        ], { cwd: repoRoot, env, encoding: "utf8" });
        assert.equal(result.status, 0, result.stderr);
        const containerEnv = JSON.parse(result.stdout).services[service].environment;
        assert.equal(containerEnv.PAPERCLIP_TOOL_ACTION_SIGNING_SECRET, signingSecret ?? "");
        assert.equal(containerEnv.BETTER_AUTH_SECRET, "test-session-secret");
      }
    } finally {
      rmSync(temporary, { recursive: true, force: true });
    }
  });
}

test("docker/docker-compose.yml has no default database password and does not publish the database port", () => {
  const run = (env) => spawnSync("docker", [
    "compose", "--env-file", process.platform === "win32" ? "NUL" : "/dev/null", "-f", "docker/docker-compose.yml", "config", "--format", "json",
  ], { cwd: repoRoot, env: { ...baseEnv, ...env }, encoding: "utf8" });

  const missing = run({ BETTER_AUTH_SECRET: "test-session-secret" });
  assert.notEqual(missing.status, 0, "compose must refuse to start without POSTGRES_PASSWORD");
  assert.match(missing.stderr, /POSTGRES_PASSWORD must be set/);

  const configured = run({ BETTER_AUTH_SECRET: "test-session-secret", POSTGRES_PASSWORD: "test-db-password" });
  assert.equal(configured.status, 0, configured.stderr);
  const services = JSON.parse(configured.stdout).services;
  assert.equal(services.db.ports, undefined, "the database port must not be published");
  assert.equal(services.db.environment.POSTGRES_PASSWORD, "test-db-password");
  assert.equal(services.server.environment.DATABASE_URL, "postgres://paperclip:test-db-password@db:5432/paperclip");
  assert.ok(!JSON.stringify(services).includes("paperclip:paperclip@"));
});
