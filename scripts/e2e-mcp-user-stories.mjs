#!/usr/bin/env node
import { spawnPnpmSync } from "./lib/pnpm-invocation.mjs";

const args = process.argv.slice(2).filter((arg) => arg !== "--");
const includeGated = args.includes("--include-gated");
const passthrough = args.filter((arg) => arg !== "--include-gated");

const grep = includeGated ? "@mcp-us" : "@mcp-runnable";
// `pnpm exec` instead of `npx`: npx is npx.cmd on Windows, which needs a shell.
const result = spawnPnpmSync(
  [
    "exec",
    "playwright",
    "test",
    "--config",
    "tests/e2e/playwright.config.ts",
    "tests/e2e/mcp-user-stories.spec.ts",
    "--grep",
    grep,
    ...passthrough,
  ],
  { stdio: "inherit" },
);

if (result.error) console.error(result.error);
process.exitCode = result.status ?? 1;
