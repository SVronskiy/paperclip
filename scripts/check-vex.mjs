#!/usr/bin/env node
// Checks that security/vex.cdx.json covers every locked version of the components it
// lists, so a dependency bump cannot silently re-open a finding that was analysed.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export function lockedVersions(repoRoot = root) {
  const files = execFileSync("git", ["ls-files", "*pnpm-lock.yaml", "*Cargo.lock"], { cwd: repoRoot, encoding: "utf8" })
    .split("\n").filter(Boolean);
  const purls = new Set();
  for (const file of files) {
    const text = readFileSync(path.join(repoRoot, file), "utf8");
    if (file.endsWith("Cargo.lock")) {
      for (const m of text.matchAll(/\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"/g)) purls.add(`pkg:cargo/${m[1]}@${m[2]}`);
    } else {
      for (const m of text.matchAll(/^ {2}'?(@?[^@'\s]+)@(\d+\.\d+\.\d+[^'():\s]*)'?:/gm)) {
        purls.add(`pkg:npm/${m[1].replace(/^@/, "%40")}@${m[2]}`);
      }
    }
  }
  return purls;
}

export function checkVex(vex, locked) {
  const problems = [];
  for (const vuln of vex.vulnerabilities ?? []) {
    if (vuln.analysis?.state !== "not_affected" || !vuln.analysis?.justification || !vuln.analysis?.detail) {
      problems.push(`${vuln.id}: needs state not_affected, a justification and a detail`);
    }
    const covered = new Set((vuln.affects ?? []).map((a) => a.ref));
    const names = new Set([...covered].map((ref) => ref.replace(/@[^@]+$/, "")));
    for (const purl of locked) {
      if (names.has(purl.replace(/@[^@]+$/, "")) && !covered.has(purl)) problems.push(`${vuln.id}: locked ${purl} is not in affects`);
    }
  }
  return problems;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const vex = JSON.parse(readFileSync(path.join(root, "security/vex.cdx.json"), "utf8"));
  const problems = checkVex(vex, lockedVersions());
  if (problems.length) {
    console.error(problems.join("\n"));
    process.exit(1);
  }
  console.log(`vex: ok (${vex.vulnerabilities.length} analysed findings)`);
}
