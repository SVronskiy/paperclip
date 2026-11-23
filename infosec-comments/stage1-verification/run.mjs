#!/usr/bin/env node
// Autonomous verification of stage 1 of the security remediation plan.
//
// Run it against a checkout of the branch under test (default: the git
// repository in the current directory). It changes nothing in that checkout: it
// only reads files, runs tests and probes, and writes a report.
//
//   node infosec-comments/stage1-verification/run.mjs [options]
//
//   --repo <path>      repository to verify (default: git top level of the cwd)
//   --out <dir>        report directory (default: <this folder>/results/<timestamp>)
//   --only <streams>   comma-separated stream ids, e.g. E1-1,E1-6 (default: all)
//   --with-docker      also build and inspect the smoke images and the compose file
//   --with-scanners    also re-run Semgrep and Horusec in Docker (about an hour)
//   --list             print the checks and exit
//
// Exit code: 0 when no check failed, 1 when at least one check failed.
// Statuses: PASS, FAIL, OPEN (known remaining work, reported not failed), SKIP, INFO.
//
// Confidentiality: the report describes vulnerabilities. Keep it out of public places.

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const option = (name) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};
const flag = (name) => args.includes(name);

function run(command, commandArgs, options = {}) {
  const result = spawnSync(command, commandArgs, {
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
    shell: false,
    ...options,
  });
  return {
    status: result.status ?? (result.error ? 127 : 1),
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? (result.error ? String(result.error) : ""),
  };
}

const repoArg = option("--repo");
const repo = path.resolve(repoArg ?? run("git", ["rev-parse", "--show-toplevel"]).stdout.trim() ?? ".");
const only = option("--only")?.split(",").map((id) => id.trim().toUpperCase());
const withDocker = flag("--with-docker");
const withScanners = flag("--with-scanners");
const stamp = new Date().toISOString().replace(/[:.]/g, "-");
const outDir = path.resolve(option("--out") ?? path.join(here, "results", stamp));
const probeDir = path.join(outDir, "probes");

const tsx = ["server/node_modules/.bin/tsx", "cli/node_modules/.bin/tsx", "node_modules/.bin/tsx"]
  .map((candidate) => path.join(repo, candidate))
  .find((candidate) => existsSync(candidate));

const read = (relative) => readFileSync(path.join(repo, relative), "utf8");
const exists = (relative) => existsSync(path.join(repo, relative));
const pass = (detail) => ({ status: "PASS", detail });
const fail = (detail) => ({ status: "FAIL", detail });
const open = (detail) => ({ status: "OPEN", detail });
const skip = (detail) => ({ status: "SKIP", detail });
const info = (detail) => ({ status: "INFO", detail });
const tail = (text, lines = 12) => text.trim().split("\n").slice(-lines).join("\n");

/** Runs a vitest project from its package directory. */
function vitest(packageDir, files) {
  // A generous timeout: the first test of some suites cold-imports the whole server.
  const result = run("npx", ["vitest", "run", "--testTimeout=90000", ...files], { cwd: path.join(repo, packageDir), env: { ...process.env, CI: "1" } });
  const summary = result.stdout.split("\n").filter((line) => /Test Files|Tests\s/.test(line)).join(" | ").replace(/\s+/g, " ");
  return result.status === 0 ? pass(summary || "passed") : fail(`${summary}\n${tail(result.stdout + result.stderr)}`);
}

function nodeTest(files) {
  const result = run("node", ["--test", ...files], { cwd: repo });
  const summary = result.stdout.split("\n").filter((line) => /^ℹ (pass|fail)/.test(line)).join(" ");
  return result.status === 0 ? pass(summary) : fail(`${summary}\n${tail(result.stdout + result.stderr)}`);
}

/** Runs a TypeScript probe in the repository's own tsx and returns its parsed JSON output. */
function probe(name, source, env = {}) {
  if (!tsx) return { error: "tsx is not installed; run pnpm install in the repository" };
  mkdirSync(probeDir, { recursive: true });
  const file = path.join(probeDir, `${name}.mts`);
  writeFileSync(file, source.replaceAll("__REPO__", repo.split(path.sep).join("/")));
  const result = run(tsx, [file], { cwd: repo, env: { ...cleanEnv(), ...env } });
  if (result.status !== 0) return { error: tail(result.stdout + result.stderr) };
  // The server logger also writes to stdout, so find the JSON line instead of taking the last line.
  for (const line of result.stdout.trim().split("\n")) {
    if (!line.startsWith("{")) continue;
    try { return { value: JSON.parse(line) }; } catch { /* keep looking */ }
  }
  return { error: `probe printed no JSON: ${tail(result.stdout)}` };
}

function cleanEnv() {
  const env = { ...process.env };
  for (const key of ["CI", "CONTINUOUS_INTEGRATION", "BUILD_NUMBER", "GITHUB_ACTIONS", "GITLAB_CI", "DO_NOT_TRACK",
    "PAPERCLIP_TELEMETRY_DISABLED", "PAPERCLIP_TELEMETRY_ENABLED", "PAPERCLIP_TELEMETRY_ENDPOINT",
    "PAPERCLIP_FEEDBACK_EXPORT_BACKEND_URL", "PAPERCLIP_TELEMETRY_BACKEND_URL"]) delete env[key];
  return env;
}

const baselineJson = () => run("node", ["scripts/check-security-baseline.mjs", "--json"], { cwd: repo });

const checks = [];
const check = (stream, id, title, fn, needs = []) => checks.push({ stream, id, title, fn, needs });

// ---------------------------------------------------------------- preflight
check("E1-0", "preflight.repo", "The repository is the stage 1 branch with its dependencies installed", () => {
  const head = run("git", ["rev-parse", "--short", "HEAD"], { cwd: repo }).stdout.trim();
  const branch = run("git", ["rev-parse", "--abbrev-ref", "HEAD"], { cwd: repo }).stdout.trim();
  const dirty = run("git", ["status", "--porcelain"], { cwd: repo }).stdout.trim();
  const problems = [];
  if (!exists("node_modules")) problems.push("node_modules is missing: run pnpm install");
  if (!exists("scripts/check-security-baseline.mjs")) problems.push("scripts/check-security-baseline.mjs is missing: this is not the stage 1 branch");
  if (problems.length) return fail(problems.join("; "));
  return info(`branch ${branch} at ${head}${dirty ? " (working tree has uncommitted changes)" : ""}`);
});

// ------------------------------------------------------------------- E1-1
check("E1-1", "telemetry.static", "No built-in telemetry collector address in product code", () => {
  const result = baselineJson();
  let violations = [];
  try { violations = JSON.parse(result.stdout).violations.filter((v) => v.rule === "telemetry"); } catch { return fail(tail(result.stdout + result.stderr)); }
  return violations.length === 0 ? pass("no telemetry.paperclip.ing or execute-api.us-east-1 address") : fail(violations.map((v) => `${v.file}:${v.line}`).join(", "));
});

check("E1-1", "telemetry.config", "Telemetry is opt-in and every opt-out spelling wins", () => {
  const { value, error } = probe("telemetry-config", `
import { resolveTelemetryConfig } from "file://__REPO__/packages/shared/src/telemetry/config.ts";
const keys = ["PAPERCLIP_TELEMETRY_ENABLED","PAPERCLIP_TELEMETRY_DISABLED","DO_NOT_TRACK","CI","GITHUB_ACTIONS"];
const reset = () => { for (const k of keys) delete process.env[k]; };
const out: Record<string, unknown> = {};
reset(); out.defaultOff = resolveTelemetryConfig().enabled === false;
reset(); out.fileDefaultOff = resolveTelemetryConfig({}).enabled === false;
reset(); process.env.PAPERCLIP_TELEMETRY_ENABLED = "1"; out.envOptIn = resolveTelemetryConfig().enabled === true;
const optOut: Record<string, boolean> = {};
for (const key of ["PAPERCLIP_TELEMETRY_DISABLED", "DO_NOT_TRACK"]) {
  for (const value of ["1", "true", "TRUE", "yes", "on"]) {
    reset(); process.env.PAPERCLIP_TELEMETRY_ENABLED = "1"; process.env[key] = value;
    optOut[key + "=" + value] = resolveTelemetryConfig({ enabled: true }).enabled === false;
  }
}
out.optOut = optOut;
reset(); process.env.PAPERCLIP_TELEMETRY_ENABLED = "1"; out.fileDisabledWins = resolveTelemetryConfig({ enabled: false }).enabled === false;
reset(); process.env.PAPERCLIP_TELEMETRY_ENABLED = "1"; process.env.CI = "true"; out.ciWins = resolveTelemetryConfig().enabled === false;
console.log(JSON.stringify(out));
`);
  if (error) return fail(error);
  const bad = [];
  if (!value.defaultOff) bad.push("telemetry is on by default");
  if (!value.fileDefaultOff) bad.push("an empty config file turns telemetry on");
  if (!value.envOptIn) bad.push("PAPERCLIP_TELEMETRY_ENABLED=1 does not opt in");
  for (const [name, ok] of Object.entries(value.optOut)) if (!ok) bad.push(`${name} does not disable telemetry`);
  if (!value.fileDisabledWins) bad.push("telemetry.enabled:false does not win over env opt-in");
  if (!value.ciWins) bad.push("CI=true does not win over env opt-in");
  return bad.length ? fail(bad.join("; ")) : pass("default off; opt-in works; 1/true/yes/on opt-outs win");
});

check("E1-1", "telemetry.network", "A client with default settings, and one with DO_NOT_TRACK=true, make no network request", () => {
  const { value, error } = probe("telemetry-network", `
import { TelemetryClient, resolveTelemetryConfig } from "file://__REPO__/packages/shared/src/telemetry/index.ts";
const calls: string[] = [];
(globalThis as any).fetch = async (url: string) => { calls.push(String(url)); return { ok: true, status: 200 }; };
const state = () => ({ installId: "i", salt: "s", createdAt: "2026-01-01T00:00:00Z", firstSeenVersion: "0" });
const result: Record<string, unknown> = {};
// Opted in but no endpoint configured: the client must drop events, not send them anywhere.
delete process.env.PAPERCLIP_TELEMETRY_ENDPOINT;
process.env.PAPERCLIP_TELEMETRY_ENABLED = "1";
const optedIn = resolveTelemetryConfig({ enabled: true });
const client = new TelemetryClient({ ...optedIn, endpoint: undefined }, state, "0.0.0");
client.track("install.started", {} as never);
await client.flush(); client.stop();
result.optedInWithoutEndpoint = calls.length;
// DO_NOT_TRACK=true: telemetry must be disabled, so no client is created at all.
process.env.DO_NOT_TRACK = "true";
result.doNotTrackEnabled = resolveTelemetryConfig({ enabled: true }).enabled;
console.log(JSON.stringify(result));
`);
  if (error) return fail(error);
  if (value.optedInWithoutEndpoint !== 0) return fail(`fetch was called ${value.optedInWithoutEndpoint} time(s) with no endpoint configured`);
  if (value.doNotTrackEnabled !== false) return fail("DO_NOT_TRACK=true did not disable telemetry");
  return pass("0 requests without an operator endpoint; DO_NOT_TRACK=true disables telemetry");
});

check("E1-1", "feedback.disabled", "Feedback trace export is disabled without an explicit backend URL", () => {
  const { value, error } = probe("feedback-client", `
import { createFeedbackTraceShareClientFromConfig } from "file://__REPO__/server/src/services/feedback-share-client.ts";
const none = createFeedbackTraceShareClientFromConfig({ feedbackExportBackendUrl: undefined, feedbackExportBackendToken: undefined });
const blank = createFeedbackTraceShareClientFromConfig({ feedbackExportBackendUrl: "  ", feedbackExportBackendToken: undefined });
console.log(JSON.stringify({ none: none === undefined, blank: blank === undefined }));
`);
  if (error) return fail(error);
  return value.none && value.blank ? pass("no client is created without PAPERCLIP_FEEDBACK_EXPORT_BACKEND_URL") : fail(JSON.stringify(value));
});

check("E1-1", "telemetry.tests", "Telemetry and feedback unit tests pass", () => {
  const server = vitest("server", ["src/__tests__/feedback-share-client.test.ts", "src/__tests__/telemetry-client-flush.test.ts", "src/__tests__/telemetry-startup.test.ts"]);
  const shared = vitest("packages/shared", ["src/telemetry"]);
  return server.status === "PASS" && shared.status === "PASS" ? pass(`${server.detail} / ${shared.detail}`) : fail(`${server.detail}\n${shared.detail}`);
});

// ------------------------------------------------------------------- E1-2
check("E1-2", "shell.static", "No spawn with a shell (shell: true or a platform-dependent shell flag) in product code and scripts", () => {
  let violations = [];
  const result = baselineJson();
  try { violations = JSON.parse(result.stdout).violations.filter((v) => v.rule === "shell"); } catch { return fail(tail(result.stdout + result.stderr)); }
  return violations.length === 0 ? pass("no shell spawning found") : fail(violations.map((v) => `${v.file}:${v.line}`).join(", "));
});

check("E1-2", "shell.helper", "The pnpm launcher passes shell metacharacters as one literal argument", () => nodeTest(["scripts/pnpm-invocation.test.mjs"]));

check("E1-2", "boardauth.windows", "The CLI opens approval URLs on Windows without cmd and rejects command-injection URLs", () => {
  const { value, error } = probe("open-url", `
import { resolveOpenUrlCommand, normalizeUrlToOpen } from "file://__REPO__/cli/src/client/board-auth.ts";
const good = resolveOpenUrlCommand("https://paperclip.example.test/cli-auth/abc?x=1&y=2", "win32");
const attacks = ["calc.exe", "https://example.test/a b", "javascript:alert(1)", "file:///C:/Windows/System32/calc.exe", "https://u:p@example.test/", "https://example.test/\\nx"];
console.log(JSON.stringify({ good, rejected: attacks.map((u) => normalizeUrlToOpen(u) === null) }));
`);
  if (error) return fail(error);
  if (value.good?.command !== "rundll32") return fail(`Windows command is ${value.good?.command}, expected rundll32`);
  if (JSON.stringify(value.good).toLowerCase().includes("cmd")) return fail("the Windows command line still mentions cmd");
  if (value.rejected.some((ok) => !ok)) return fail(`an unsafe URL was accepted: ${JSON.stringify(value.rejected)}`);
  return pass("rundll32 url.dll,FileProtocolHandler; 6 unsafe URL forms rejected");
});

check("E1-2", "boardauth.tests", "CLI board-auth tests pass", () => vitest("cli", ["src/__tests__/board-auth.test.ts"]));

// ------------------------------------------------------------------- E1-3
check("E1-3", "images.static", "Every stage of the smoke Dockerfiles sets a non-root USER", () => {
  const problems = [];
  for (const file of ["docker/openclaw-smoke/Dockerfile", "docker/runner-image/Dockerfile.smoke"]) {
    const text = read(file);
    const stages = text.split("\n").filter((line) => /^FROM\s/i.test(line)).length;
    const users = text.split("\n").filter((line) => /^USER\s+(?!root\b|0\b)/i.test(line)).length;
    if (users < stages) problems.push(`${file}: ${stages} stage(s) but only ${users} non-root USER line(s)`);
  }
  return problems.length ? fail(problems.join("; ")) : pass("both smoke Dockerfiles run unprivileged in every stage");
});

check("E1-3", "images.trivy", "Trivy reports no DS002 (root user) finding for the two smoke Dockerfiles", () => {
  const trivy = run("trivy", ["--version"]);
  if (trivy.status !== 0) return skip("trivy is not installed");
  const bad = [];
  for (const file of ["docker/openclaw-smoke", "docker/runner-image"]) {
    const result = run("trivy", ["config", "--quiet", "--format", "json", "--skip-version-check", path.join(repo, file)]);
    let ids = [];
    try { ids = (JSON.parse(result.stdout).Results ?? []).flatMap((r) => (r.Misconfigurations ?? []).map((m) => m.ID)); } catch { return fail(tail(result.stdout + result.stderr)); }
    if (ids.includes("DS002") || ids.includes("DS-0002")) bad.push(file);
  }
  return bad.length ? fail(`DS002 still reported for ${bad.join(", ")}`) : pass("no DS002");
});

check("E1-3", "images.build", "The openclaw smoke image builds and runs as a non-root user", () => {
  const build = run("docker", ["build", "-q", "-t", "paperclip-stage1-openclaw-smoke", path.join(repo, "docker/openclaw-smoke")]);
  if (build.status !== 0) return fail(tail(build.stderr));
  const id = run("docker", ["run", "--rm", "paperclip-stage1-openclaw-smoke", "id", "-u"]);
  return id.status === 0 && id.stdout.trim() !== "0" ? pass(`runs as uid ${id.stdout.trim()}`) : fail(`uid ${id.stdout.trim() || "unknown"}: ${tail(id.stderr)}`);
}, ["docker"]);

// ------------------------------------------------------------------- E1-4
check("E1-4", "compose.static", "docker-compose.yml publishes no database port and has no default database password", () => {
  const text = read("docker/docker-compose.yml");
  const problems = [];
  if (/["']?5432:5432["']?/.test(text)) problems.push("port 5432 is published");
  if (/POSTGRES_PASSWORD:\s*["']?paperclip["']?\s*$/m.test(text)) problems.push("POSTGRES_PASSWORD defaults to paperclip");
  if (/paperclip:paperclip@/.test(text)) problems.push("DATABASE_URL contains the default password");
  if (!/POSTGRES_PASSWORD:\?/.test(text)) problems.push("POSTGRES_PASSWORD is not required");
  return problems.length ? fail(problems.join("; ")) : pass("no published port; POSTGRES_PASSWORD is required");
});

check("E1-4", "compose.config", "docker compose refuses to render without POSTGRES_PASSWORD and renders without ports with it", () => nodeTest(["scripts/docker-compose-secrets.test.mjs"]), ["docker"]);

check("E1-4", "passwords.docs", "No default database password in .env.example, docs and CLI help", () => {
  const result = run("git", ["grep", "-n", "paperclip:paperclip@", "--", ".env.example", "doc", "docs", "README.md", "docker"], { cwd: repo });
  return result.stdout.trim() === "" ? pass("none found") : fail(result.stdout.trim());
});

check("E1-4", "passwords.embedded", "The embedded development database no longer uses the fixed paperclip/paperclip credentials", () => {
  const result = run("git", ["grep", "-lE", "paperclip:paperclip@|password: *\"paperclip\"", "--", "server/src", "cli/src", "packages/db/src", "packages/db/scripts", "scripts", ":!**/*.test.*", ":!**/__tests__/**"], { cwd: repo });
  const files = result.stdout.trim().split("\n").filter(Boolean);
  return files.length === 0
    ? pass("no fixed credentials left")
    : open(`${files.length} file(s) still build the embedded-database connection with the fixed password (127.0.0.1 only; random password at initialization is still to do): ${files.join(", ")}`);
});

// ------------------------------------------------------------- E1-5 .. E1-9
check("E1-5", "baseline", "Security baseline: no Math.random, MD5/SHA-1 (outside documented protocol uses), shell spawning or built-in telemetry address", () => {
  const result = baselineJson();
  try {
    const parsed = JSON.parse(result.stdout);
    return parsed.ok ? pass("security baseline: ok") : fail(parsed.violations.map((v) => `${v.file}:${v.line} [${v.rule}]`).join("; "));
  } catch { return fail(tail(result.stdout + result.stderr)); }
});

check("E1-5", "baseline.tests", "The baseline check has tests and they pass", () => nodeTest(["scripts/check-security-baseline.test.mjs"]));

check("E1-6", "random.module", "secure-random helpers never use Math.random and stay in range", () => vitest("packages/shared", ["src/secure-random.test.ts"]));

check("E1-6", "random.ui", "UI tests that depended on Math.random pass with crypto-backed randomness", () =>
  vitest("ui", ["src/lib/optimistic-issue-comments.test.ts", "src/pages/tools/profiles/WizardToolsStep.test.tsx", "src/components/PageLoadTracker.test.tsx"]));

check("E1-6", "random.server", "Server retry/backoff tests that depended on Math.random pass", () =>
  vitest("server", ["src/__tests__/storage-s3-multipart-backoff.test.ts", "src/__tests__/storage-s3-multipart-throttle.test.ts"]));

check("E1-7", "hash.sha256", "Hash replacements: ETag, redaction version and attention content use SHA-256", () => {
  const problems = [];
  if (/createHash\("md5"\)/.test(read("server/src/routes/plugin-ui-static.ts"))) problems.push("plugin-ui-static still uses MD5");
  if (/\bmd5\(/.test(read("server/src/services/run-secret-redaction.ts"))) problems.push("run-secret-redaction still uses md5()");
  if (/\bmd5\(/.test(read("server/src/services/attention.ts"))) problems.push("attention still uses md5()");
  if (!/sha256/.test(read("server/src/services/attention.ts"))) problems.push("attention does not use sha256");
  return problems.length ? fail(problems.join("; ")) : pass("MD5 replaced by SHA-256 in the three server places");
});

check("E1-7", "hash.exceptions", "Remaining SHA-1/MD5 uses are exactly the documented protocol exceptions", () => {
  const result = run("git", ["grep", "-nE", "createHash\\(\\s*[\"'](sha1|md5)[\"']", "--", "server/src", "cli/src", "packages/*/src", "packages/*/scripts", "scripts", ":!**/*.test.*", ":!**/__tests__/**", ":!**/provider-assets/**", ":!scripts/check-security-baseline*"], { cwd: repo });
  const lines = result.stdout.trim().split("\n").filter(Boolean);
  const allowed = ["codex-app-server-unix-proxy.ts", "durable-prp-control-plane.ts", "services/routines.ts", "benchmark-workspace-snapshot-crypto.ts"];
  const unexpected = lines.filter((line) => !allowed.some((name) => line.includes(name)));
  return unexpected.length ? fail(unexpected.join("; ")) : info(`${lines.length} protocol-mandated use(s): WebSocket accept x2, UUIDv5 x1, S3 Content-MD5 benchmark fake x1. A security-service exception request is still needed.`);
});

check("E1-8", "redirect.tests", "Redirect, OAuth-return and registration tests pass", () => {
  const server = vitest("server", ["src/__tests__/safe-redirect.test.ts", "src/__tests__/oauth-browser-return.test.ts", "src/__tests__/public-mcp-client-metadata.test.ts"]);
  const ui = vitest("ui", ["src/lib/safe-navigation.test.ts"]);
  return server.status === "PASS" && ui.status === "PASS" ? pass(`${server.detail} / ${ui.detail}`) : fail(`${server.detail}\n${ui.detail}`);
});

check("E1-8", "redirect.probe", "Open-redirect payloads never reach res.redirect", () => {
  const { value, error } = probe("redirect-payloads", `
import { safeRedirect } from "file://__REPO__/server/src/routes/safe-redirect.ts";
const payloads = ["//evil.example", "https://evil.example", "/\\\\evil.example", "\\\\\\\\evil.example", "javascript:alert(1)", "data:text/html,x", "/a\\nb", "evil.example"];
const leaked: string[] = [];
for (const payload of payloads) {
  let target = "";
  safeRedirect({ redirect: (_s: number, t: string) => { target = t; } } as never, 303, payload);
  if (target !== "/") leaked.push(payload);
}
console.log(JSON.stringify({ leaked }));
`);
  if (error) return fail(error);
  return value.leaked.length ? fail(`redirected to: ${value.leaked.join(", ")}`) : pass("8 payloads all replaced by the fallback");
});

check("E1-8", "redirect.coverage", "Every res.redirect in the audited routes goes through safeRedirect", () => {
  const files = ["tool-access.ts", "chat-channels.ts", "tailscale-connections.ts", "slack-tools.ts"].map((f) => `server/src/routes/${f}`);
  const bad = files.filter((file) => /\bres\.redirect\(/.test(read(file)));
  return bad.length ? fail(`direct res.redirect in ${bad.join(", ")}`) : pass("4 route files use safeRedirect only");
});

check("E1-9", "plugin-ui.dotfiles", "Plugin UI static route denies hidden files and keeps dot-directory installs working", () => vitest("server", ["src/__tests__/plugin-ui-static.test.ts"]));

// ------------------------------------------------------------------ E1-10
check("E1-10", "deps.grpc", "@grpc/grpc-js is at or above 1.14.5 (the version that fixes the Trivy finding)", () => {
  const lock = read("pnpm-lock.yaml");
  const versions = [...lock.matchAll(/^ {2}'@grpc\/grpc-js@(\d+\.\d+\.\d+)':/gm)].map((m) => m[1]);
  if (versions.length === 0) return skip("@grpc/grpc-js is not in pnpm-lock.yaml");
  const older = versions.filter((v) => { const [a, b, c] = v.split(".").map(Number); return a < 1 || (a === 1 && (b < 14 || (b === 14 && c < 5))); });
  return older.length ? fail(`older versions in pnpm-lock.yaml: ${older.join(", ")}`) : pass(`pnpm-lock.yaml: ${versions.join(", ")}`);
});

check("E1-10", "deps.hyper", "hyper in the Rust runner lockfile (Dependency-Track critical finding)", () => {
  const lock = read("packages/paperclip-runner/runner/Cargo.lock");
  const version = /name = "hyper"\nversion = "([^"]+)"/.exec(lock)?.[1];
  return open(`hyper ${version} is still locked. CVE-2024-23741 describes the Hyper terminal for macOS, not the Rust crate, so this looks like a false match by CPE; confirm with the secure-development team and record the analysis in Dependency-Track. The SBOM for it is infosec-comments/reports/stage1/sbom-cyclonedx.json.`);
});

check("E1-10", "deps.lockfile.gate", "Dependency changes in this branch respect the reviewed-lockfile gate", () => {
  const changed = run("git", ["diff", "--name-only", "origin/master...HEAD", "--", "pnpm-lock.yaml"], { cwd: repo }).stdout.trim();
  return changed ? info("pnpm-lock.yaml differs from master: the documented lock refresh workflow must review it (tests/runner-e2e/report-lock.json)") : pass("pnpm-lock.yaml is unchanged from master, so the reviewed-lock gate is untouched");
});

// ------------------------------------------------------------- scanners
check("E1-11", "scanners.horusec", "Horusec re-run: weak random and MD5 findings are gone", () => {
  const script = path.join(repo, "infosec-comments/reports/stage1/hs-run.sh");
  const scriptPath = exists("infosec-comments/reports/stage1/hs-run.sh") ? script : path.join(here, "..", "reports", "stage1", "hs-run.sh");
  if (!existsSync(scriptPath)) return skip("hs-run.sh is not available next to the plan");
  const work = path.join(outDir, "scanners");
  mkdirSync(path.join(work, "hs"), { recursive: true });
  const dirs = ["server", "ui", "cli", "packages/adapter-utils", "packages/adapters", "packages/db", "packages/shared", "packages/plugins", "packages/paperclip-runner"];
  const result = run("bash", [scriptPath, work, ...dirs], { env: { ...process.env } });
  return result.status === 0
    ? info("scan finished; compare counts with infosec-comments/stage1-registry.csv (Horusec rows) using compare.py in reports/stage1")
    : fail(tail(result.stdout + result.stderr));
}, ["docker", "scanners"]);

// ------------------------------------------------------------------ run
const selected = checks.filter((c) => !only || only.includes(c.stream));
if (flag("--list")) {
  for (const c of selected) console.log(`${c.stream.padEnd(6)} ${c.id.padEnd(22)} ${c.title}${c.needs.length ? `  [needs: ${c.needs.join(", ")}]` : ""}`);
  process.exit(0);
}

mkdirSync(outDir, { recursive: true });
const results = [];
for (const c of selected) {
  let outcome;
  if (c.needs.includes("docker") && !withDocker) outcome = skip("use --with-docker");
  else if (c.needs.includes("scanners") && !withScanners) outcome = skip("use --with-scanners");
  else if (c.needs.includes("docker") && run("docker", ["info"]).status !== 0) outcome = skip("Docker is not running");
  else {
    const started = Date.now();
    try { outcome = c.fn(); } catch (error) { outcome = fail(`check crashed: ${error instanceof Error ? error.message : String(error)}`); }
    outcome.seconds = Math.round((Date.now() - started) / 1000);
  }
  results.push({ stream: c.stream, id: c.id, title: c.title, ...outcome });
  console.log(`${outcome.status.padEnd(5)} ${c.stream.padEnd(6)} ${c.id.padEnd(22)} ${c.title}`);
  if (outcome.status === "FAIL") console.log(outcome.detail.split("\n").map((line) => `        ${line}`).join("\n"));
}

const count = (status) => results.filter((r) => r.status === status).length;
const summary = { PASS: count("PASS"), FAIL: count("FAIL"), OPEN: count("OPEN"), SKIP: count("SKIP"), INFO: count("INFO") };
const head = run("git", ["rev-parse", "HEAD"], { cwd: repo }).stdout.trim();
const report = { generatedAt: new Date().toISOString(), repo, commit: head, options: { withDocker, withScanners, only: only ?? "all" }, summary, results };
writeFileSync(path.join(outDir, "report.json"), JSON.stringify(report, null, 2));
const icon = { PASS: "PASS", FAIL: "**FAIL**", OPEN: "OPEN", SKIP: "skip", INFO: "info" };
writeFileSync(path.join(outDir, "report.md"), [
  "# Stage 1 verification report",
  "",
  `- Commit: \`${head}\``,
  `- Generated: ${report.generatedAt}`,
  `- Result: ${summary.PASS} passed, ${summary.FAIL} failed, ${summary.OPEN} open, ${summary.SKIP} skipped, ${summary.INFO} informational`,
  "",
  "> This report describes vulnerabilities. Keep it out of public places.",
  "",
  "| Stream | Check | Status | Detail |",
  "|---|---|---|---|",
  ...results.map((r) => `| ${r.stream} | ${r.title.replaceAll("|", "/")} | ${icon[r.status]} | ${r.detail.replaceAll("\n", "<br>").replaceAll("|", "/")} |`),
  "",
].join("\n"));
console.log(`\n${summary.PASS} passed, ${summary.FAIL} failed, ${summary.OPEN} open, ${summary.SKIP} skipped, ${summary.INFO} info`);
console.log(`report: ${path.join(outDir, "report.md")}`);
process.exitCode = summary.FAIL === 0 ? 0 : 1;
