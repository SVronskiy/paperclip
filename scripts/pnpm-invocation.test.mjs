import assert from "node:assert/strict";
import test from "node:test";

import { resolvePnpmInvocation, spawnPnpmSync } from "./lib/pnpm-invocation.mjs";

test("a JavaScript pnpm entry point runs through this Node, never a shell", () => {
  assert.deepEqual(resolvePnpmInvocation({ npm_execpath: "/corepack/pnpm/9.15.4/bin/pnpm.cjs" }, "/usr/bin/node"), {
    command: "/usr/bin/node",
    argsPrefix: ["/corepack/pnpm/9.15.4/bin/pnpm.cjs"],
  });
  assert.deepEqual(resolvePnpmInvocation({ npm_execpath: "C:\\pnpm\\bin\\pnpm.cjs" }, "node.exe"), {
    command: "node.exe",
    argsPrefix: ["C:\\pnpm\\bin\\pnpm.cjs"],
  });
});

test("a native pnpm executable runs directly", () => {
  assert.deepEqual(resolvePnpmInvocation({ npm_execpath: "C:\\pnpm\\pnpm.exe" }, "node.exe"), {
    command: "C:\\pnpm\\pnpm.exe",
    argsPrefix: [],
  });
});

test("outside a pnpm script, pnpm on PATH is used", () => {
  assert.deepEqual(resolvePnpmInvocation({}, "/usr/bin/node"), { command: "pnpm", argsPrefix: [] });
  assert.deepEqual(resolvePnpmInvocation({ npm_execpath: "/usr/lib/node_modules/npm/bin/npm-cli.js" }, "/usr/bin/node"), {
    command: "pnpm",
    argsPrefix: [],
  });
});

test("shell metacharacters in an argument stay a single literal argument", () => {
  // Pass a fake pnpm entry (a script that prints its argv) through the resolver.
  const result = spawnPnpmSync(["--filter", "a&calc|b^c"], {
    env: { ...process.env, npm_execpath: new URL("./fixtures/fake-pnpm.cjs", import.meta.url).pathname },
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), ["--filter", "a&calc|b^c"]);
});
