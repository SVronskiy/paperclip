import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { checkVex, lockedVersions } from "./check-vex.mjs";

const entry = (refs) => ({ vulnerabilities: [{ id: "CVE-1", analysis: { state: "not_affected", justification: "code_not_present", detail: "x" }, affects: refs.map((ref) => ({ ref })) }] });

test("a locked version missing from affects is reported", () => {
  const locked = new Set(["pkg:npm/%40grpc/grpc-js@1.14.5", "pkg:npm/%40grpc/grpc-js@1.14.9", "pkg:npm/other@1.0.0"]);
  assert.deepEqual(checkVex(entry(["pkg:npm/%40grpc/grpc-js@1.14.5"]), locked), ["CVE-1: locked pkg:npm/%40grpc/grpc-js@1.14.9 is not in affects"]);
  assert.deepEqual(checkVex(entry(["pkg:npm/%40grpc/grpc-js@1.14.5", "pkg:npm/%40grpc/grpc-js@1.14.9"]), locked), []);
});

test("an entry without analysis is reported", () => {
  assert.equal(checkVex({ vulnerabilities: [{ id: "CVE-2", affects: [] }] }, new Set()).length, 1);
});

test("the repository VEX covers every locked hyper and grpc-js version", () => {
  const vex = JSON.parse(readFileSync(new URL("../security/vex.cdx.json", import.meta.url), "utf8"));
  const locked = lockedVersions();
  assert.ok([...locked].some((p) => p.startsWith("pkg:cargo/hyper@")));
  assert.ok([...locked].some((p) => p.startsWith("pkg:npm/%40grpc/grpc-js@")));
  assert.deepEqual(checkVex(vex, locked), []);
});
