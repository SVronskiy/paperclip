#!/usr/bin/env node
// Security baseline check for product code. It fails when code adds back a
// pattern that the information-security review rejected:
//
//   random      Math.random() (use secureRandom / crypto from @paperclipai/shared/secure-random or node:crypto)
//   weak-hash   createHash("md5" | "sha1") and SQL md5() (use SHA-256)
//   shell       spawn/exec with `shell: true` or a platform-dependent shell flag (use scripts/lib/pnpm-invocation.mjs or an argument array)
//   telemetry   a built-in telemetry collector address
//
// A line that is required by an external protocol can opt out with a comment on
// the same or the previous line: `security-baseline-allow: <reason>`.
//
// Usage: node scripts/check-security-baseline.mjs [--json]

import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const ALLOW_MARKER = "security-baseline-allow:";

const PRODUCT_ROOTS = ["server/src", "cli/src", "ui/src", "packages", "scripts", "server/scripts"];
// `provider-assets` holds vendored third-party CLI bundles, not Paperclip source.
const SKIP_DIRS = new Set(["node_modules", "dist", ".git", ".turbo", "coverage", "__snapshots__", "migrations", "storybook-static", "provider-assets"]);
const SOURCE_EXTENSIONS = new Set([".ts", ".tsx", ".mjs", ".cjs", ".js", ".mts"]);
const TEST_FILE = /(^|\/)(__tests__|tests?|e2e|fixtures?|__mocks__)(\/|$)|\.(test|spec|stories|live\.test)\.[cm]?[jt]sx?$|\.test\.mjs$/;
// This script and its test describe the patterns, so they are not scanned.
const SELF = /(^|\/)check-security-baseline(\.test)?\.mjs$/;

const RULES = [
  {
    id: "random",
    pattern: /\bMath\.random\b/,
    message: "Math.random is predictable; use secureRandom() from @paperclipai/shared/secure-random or node:crypto",
  },
  {
    id: "weak-hash",
    pattern: /createHash\(\s*["'`](?:md5|sha1)["'`]/i,
    message: "MD5/SHA-1 is not allowed; use SHA-256 (protocol-mandated uses need a security-baseline-allow comment)",
  },
  {
    id: "weak-hash",
    pattern: /\bmd5\s*\(/i,
    message: "SQL md5() is not allowed; use encode(sha256(convert_to(..., 'UTF8')), 'hex')",
    onlyIn: /^(server\/src|packages\/db\/src)\//,
  },
  {
    id: "shell",
    pattern: /\bshell\s*:\s*(?:true\b|process\.platform|isWindows|isWin\b|platform\s*===)/,
    message: "spawning through a shell is not allowed; use an argument array without a shell (scripts/lib/pnpm-invocation.mjs runs pnpm)",
  },
  {
    id: "telemetry",
    pattern: /telemetry\.paperclip\.ing|execute-api\.us-east-1\.amazonaws\.com/,
    message: "built-in telemetry collector addresses are not allowed; telemetry must be opt-in with an operator-supplied endpoint",
  },
];

function isCommentOnly(line) {
  const trimmed = line.trim();
  return trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*") || trimmed.startsWith("#");
}

/** Returns the violations in `text` as `{ rule, line, message, source }`. */
export function findViolations(text, relativePath = "file.ts") {
  const lines = text.split("\n");
  const violations = [];
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (isCommentOnly(line)) continue;
    const allowed = line.includes(ALLOW_MARKER) || (index > 0 && lines[index - 1].includes(ALLOW_MARKER))
      || (index > 1 && lines[index - 2].includes(ALLOW_MARKER));
    if (allowed) continue;
    for (const rule of RULES) {
      if (rule.onlyIn && !rule.onlyIn.test(relativePath)) continue;
      if (rule.pattern.test(line)) {
        violations.push({ rule: rule.id, line: index + 1, message: rule.message, source: line.trim().slice(0, 160) });
      }
    }
  }
  return violations;
}

export function collectProductFiles(root) {
  const files = [];
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name) || entry.name.startsWith(".")) continue;
        walk(path.join(directory, entry.name));
      } else if (entry.isFile() && SOURCE_EXTENSIONS.has(path.extname(entry.name))) {
        const relative = path.relative(root, path.join(directory, entry.name)).split(path.sep).join("/");
        if (TEST_FILE.test(relative) || SELF.test(relative)) continue;
        files.push(relative);
      }
    }
  };
  for (const productRoot of PRODUCT_ROOTS) {
    const absolute = path.join(root, productRoot);
    try {
      if (statSync(absolute).isDirectory()) walk(absolute);
    } catch {
      // Optional root.
    }
  }
  return [...new Set(files)].sort();
}

export function runCheck({ root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..") } = {}) {
  const results = [];
  for (const file of collectProductFiles(root)) {
    // Benchmarks and fixtures generate synthetic data; they are not shipped.
    if (/(^|\/)benchmark-[^/]*\.[cm]?[jt]s$/.test(file)) continue;
    for (const violation of findViolations(readFileSync(path.join(root, file), "utf8"), file)) {
      results.push({ file, ...violation });
    }
  }
  return results;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const results = runCheck();
  if (process.argv.includes("--json")) {
    console.log(JSON.stringify({ ok: results.length === 0, violations: results }, null, 2));
  } else if (results.length === 0) {
    console.log("security baseline: ok");
  } else {
    for (const result of results) console.error(`${result.file}:${result.line} [${result.rule}] ${result.message}\n    ${result.source}`);
    console.error(`\nsecurity baseline: ${results.length} violation(s)`);
  }
  process.exitCode = results.length === 0 ? 0 : 1;
}
