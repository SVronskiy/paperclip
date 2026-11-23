import assert from "node:assert/strict";
import test from "node:test";

import { ALLOW_MARKER, findViolations, runCheck } from "./check-security-baseline.mjs";

const rules = (text, file = "server/src/x.ts") => findViolations(text, file).map((violation) => violation.rule);

test("flags Math.random but not secure alternatives or comments", () => {
  assert.deepEqual(rules("const id = Math.random().toString(36);"), ["random"]);
  assert.deepEqual(rules("const f = (random = Math.random) => random();"), ["random"]);
  assert.deepEqual(rules("// never use Math.random here"), []);
  assert.deepEqual(rules("const id = secureRandom().toString(36);"), []);
});

test("flags MD5 and SHA-1 hashing, including SQL md5 in server code", () => {
  assert.deepEqual(rules('createHash("md5")'), ["weak-hash"]);
  assert.deepEqual(rules("createHash('sha1')"), ["weak-hash"]);
  assert.deepEqual(rules('createHash("sha256")'), []);
  assert.deepEqual(rules("sql`md5(${value})`", "server/src/services/a.ts"), ["weak-hash"]);
  assert.deepEqual(rules("sql`md5(${value})`", "scripts/a.ts"), []);
});

test("flags shell spawning on any platform condition", () => {
  assert.deepEqual(rules('spawn("pnpm", args, { shell: true })'), ["shell"]);
  assert.deepEqual(rules('spawn("pnpm", args, { shell: process.platform === "win32" })'), ["shell"]);
  assert.deepEqual(rules('spawn("pnpm", args, { shell: false })'), []);
});

test("flags built-in telemetry collector addresses", () => {
  assert.deepEqual(rules('const url = "https://telemetry.paperclip.ing/ingest";'), ["telemetry"]);
  assert.deepEqual(rules('const url = "https://x.execute-api.us-east-1.amazonaws.com/ingest";'), ["telemetry"]);
});

test("an allow marker on the same or a previous line permits a protocol-mandated use", () => {
  assert.deepEqual(rules(`createHash("sha1") // ${ALLOW_MARKER} RFC 6455`), []);
  assert.deepEqual(rules(`// ${ALLOW_MARKER} RFC 6455\ncreateHash("sha1")`), []);
  assert.deepEqual(rules(`// ${ALLOW_MARKER} RFC 6455\n// second comment line\ncreateHash("sha1")`), []);
  assert.deepEqual(rules(`// ${ALLOW_MARKER} RFC 6455\n\n\ncreateHash("sha1")`), ["weak-hash"]);
});

test("the repository has no violations", () => {
  assert.deepEqual(runCheck(), []);
});
