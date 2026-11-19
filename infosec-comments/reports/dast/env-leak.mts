import { runChildProcess } from "../../../packages/adapter-utils/src/server-utils.ts";
let out = "";
await runChildProcess("dast-env-leak", "/usr/bin/env", [], {
  cwd: "/tmp", env: { PAPERCLIP_API_URL: "http://127.0.0.1:3197" }, timeoutSec: 10, graceSec: 1,
  onLog: async (_s, c) => { out += c; },
});
const keys = ["BETTER_AUTH_SECRET","DATABASE_URL","ANTHROPIC_API_KEY","AWS_SECRET_ACCESS_KEY","PAPERCLIP_AGENT_JWT_SECRET","PAPERCLIP_SECRETS_MASTER_KEY"];
for (const k of keys) { const line = out.split("\n").find(l => l.startsWith(k + "=")); console.log(k.padEnd(30), line ? "ВИДЕН агенту: " + line.slice(k.length+1, k.length+13) + "…" : "скрыт"); }
