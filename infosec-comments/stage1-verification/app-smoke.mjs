// Starts the real server on an isolated home with the embedded database and checks that the
// application still works after the stage 1 changes. Prints one JSON line. Usage:
//   node app-smoke.mjs --repo <path>
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, statSync, existsSync, writeFileSync } from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

const repo = path.resolve(process.argv[process.argv.indexOf("--repo") + 1] ?? ".");
const home = mkdtempSync(path.join(os.tmpdir(), "pc-app-smoke-"));
const instance = "smoke";
const steps = [];
const note = (name, ok, detail = "") => steps.push({ name, ok, detail });

const freePort = () => new Promise((resolve) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => resolve(p)); }); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const env = (port) => {
  const e = { ...process.env, PAPERCLIP_HOME: home, PAPERCLIP_INSTANCE_ID: instance, PORT: String(port), SERVE_UI: "false",
    PAPERCLIP_TELEMETRY_ENABLED: "0", PAPERCLIP_EMBEDDED_POSTGRES_PORT: String(port + 1) };
  delete e.DATABASE_URL; delete e.PAPERCLIP_EMBEDDED_DB_PASSWORD;
  return e;
};

async function start(port) {
  const child = spawn("npx", ["tsx", "src/index.ts"], { cwd: path.join(repo, "server"), env: env(port), stdio: "ignore", detached: true });
  for (let i = 0; i < 80; i++) {
    await sleep(3000);
    try { const r = await fetch(`http://127.0.0.1:${port}/api/health`); if (r.ok) return { child, health: await r.json() }; } catch { /* not up yet */ }
    if (child.exitCode !== null) break;
  }
  stop(child); return null;
}
function stop(child) { try { process.kill(-child.pid, "SIGTERM"); } catch { /* gone */ } }
async function waitStopped(dataDir) { for (let i = 0; i < 40; i++) { if (!existsSync(path.join(dataDir, "postmaster.pid"))) return; await sleep(1000); } }

try {
  const port = await freePort();
  const root = path.join(home, "instances", instance);
  const passwordFile = path.join(root, "db.password");

  // 1. Fresh start: random password, migrations, health.
  let run = await start(port);
  note("fresh start reaches /api/health", !!run, run ? `status ${run.health.status}` : "server did not become healthy");
  if (!run) throw new Error("stop");
  const mode = statSync(passwordFile).mode & 0o777;
  const pw = readFileSync(passwordFile, "utf8").trim();
  note("database password is random and stored with mode 0600", mode === 0o600 && pw.length >= 32 && pw !== "paperclip", `mode ${mode.toString(8)}, ${pw.length} chars`);
  const companies = await fetch(`http://127.0.0.1:${port}/api/companies`).then((r) => r.status);
  note("an API route backed by the database answers", companies === 200, `GET /api/companies -> ${companies}`);
  const dbPort = Number(readFileSync(path.join(root, "db", "postmaster.pid"), "utf8").split("\n")[3]);
  const sql = (password, text) => spawnSync("node", ["--input-type=module", "-e", `
    import postgres from "postgres";
    const c = postgres(${JSON.stringify(`postgres://paperclip:${encodeURIComponent("__PW__")}@127.0.0.1:${dbPort}/postgres`)}.replace("__PW__", process.env.PW), { max: 1 });
    try { await c.unsafe(process.env.SQL); console.log("ok"); } catch (e) { console.log("err " + e.message); } finally { await c.end(); }`],
    { cwd: path.join(repo, "packages", "db"), env: { ...process.env, PW: password, SQL: text }, encoding: "utf8" }).stdout.trim();
  note("the old fixed password is rejected", sql("paperclip", "select 1").startsWith("err"), "connect as paperclip/paperclip");
  note("the stored password is accepted", sql(pw, "select 1") === "ok");
  // 2. Make the cluster look like one created before this change, then restart.
  sql(pw, "ALTER USER paperclip PASSWORD 'paperclip'");
  stop(run.child); await waitStopped(path.join(root, "db"));
  rmSync(passwordFile);
  run = await start(port);
  note("a legacy cluster (old password, no password file) starts", !!run);
  if (run) {
    const upgraded = existsSync(passwordFile) ? readFileSync(passwordFile, "utf8").trim() : "";
    note("the legacy cluster is moved to a random password", upgraded.length >= 32 && upgraded !== "paperclip");
    note("the upgraded password works and the old one no longer does", sql(upgraded, "select 1") === "ok" && sql("paperclip", "select 1").startsWith("err"));
    stop(run.child); await waitStopped(path.join(root, "db"));
    // 3. Restart on the stored password.
    run = await start(port);
    note("a restart reuses the stored password", !!run);
    if (run) stop(run.child);
  }
} catch (error) {
  if (error.message !== "stop") note("smoke run crashed", false, String(error.message ?? error));
} finally {
  await sleep(3000);
  try { rmSync(home, { recursive: true, force: true }); } catch { /* best effort */ }
}
console.log(JSON.stringify({ ok: steps.every((s) => s.ok), steps }));
