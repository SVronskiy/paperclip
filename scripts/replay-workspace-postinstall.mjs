#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { discoverWorkspacePackagePaths } from "./ensure-workspace-package-links.mjs";
import { spawn } from "node:child_process";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function readPostinstall(dirPath) {
  const manifestPath = path.join(dirPath, "package.json");
  if (!existsSync(manifestPath)) return null;
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const script = manifest.scripts?.postinstall;
  return typeof script === "string" && script.trim().length > 0 ? script.trim() : null;
}

export function findWorkspacePostinstallScripts(rootDir = repoRoot) {
  const workspacePaths = discoverWorkspacePackagePaths(rootDir);
  const canonicalRoot = path.resolve(rootDir);
  const workspaceHooks = [];
  const seenDirs = new Set([canonicalRoot]);

  for (const dirPath of Array.from(workspacePaths.values()).sort()) {
    const resolved = path.resolve(dirPath);
    if (seenDirs.has(resolved)) continue;
    seenDirs.add(resolved);
    const script = readPostinstall(resolved);
    if (script) {
      workspaceHooks.push({
        dir: resolved,
        relDir: path.relative(canonicalRoot, resolved).split(path.sep).join("/"),
        script,
      });
    }
  }

  const rootScript = readPostinstall(canonicalRoot);
  return {
    workspaceHooks,
    rootHook: rootScript ? { dir: canonicalRoot, relDir: ".", script: rootScript } : null,
  };
}

/**
 * Splits a lifecycle script into an argument array without a shell. Single and
 * double quotes group words (inside double quotes a backslash escapes only
 * $ ` " \\ and newline, as in POSIX sh). Any shell syntax outside quotes (pipes, `&&`, `;`, redirects,
 * `$` expansion, backticks, globs, subshells) is refused, so a hook can only be
 * one plain command.
 */
export function parseLifecycleCommand(script) {
  const argv = [];
  let current = "";
  let quote = null;
  let started = false;
  for (let i = 0; i < script.length; i += 1) {
    const ch = script[i];
    if (quote === "'") {
      if (ch === "'") quote = null; else current += ch;
      continue;
    }
    if (quote === '"') {
      if (ch === '"') quote = null;
      // POSIX: inside double quotes a backslash escapes only $ ` " \\ and newline.
      else if (ch === "\\" && i + 1 < script.length && "$`\"\\\n".includes(script[i + 1])) current += script[++i];
      else current += ch;
      continue;
    }
    if (ch === "'" || ch === '"') { quote = ch; started = true; continue; }
    if (/\s/.test(ch)) {
      if (started) { argv.push(current); current = ""; started = false; }
      continue;
    }
    if (/[|&;<>$`()*?\\{}\[\]!~#]/.test(ch)) throw new Error(`unsupported shell syntax ${JSON.stringify(ch)} in ${JSON.stringify(script)}`);
    current += ch;
    started = true;
  }
  if (quote) throw new Error(`unterminated quote in ${JSON.stringify(script)}`);
  if (started) argv.push(current);
  if (argv.length === 0) throw new Error("empty postinstall script");
  return argv;
}

function runHook(hook, rootDir, env = process.env) {
  const binDirs = [
    path.join(hook.dir, "node_modules", ".bin"),
    path.join(rootDir, "node_modules", ".bin"),
  ];
  const mergedPath = [...binDirs, env.PATH ?? ""].filter(Boolean).join(path.delimiter);
  return new Promise((resolve, reject) => {
    let argv;
    try {
      argv = parseLifecycleCommand(hook.script);
    } catch (error) {
      reject(new Error(`postinstall in ${hook.relDir}: ${error.message}`));
      return;
    }
    const [command, ...args] = argv;
    // No shell: the hook is split into an argument array and `node` is this Node.
    const child = spawn(command === "node" ? process.execPath : command, args, {
      cwd: hook.dir,
      env: { ...env, PATH: mergedPath },
      shell: false,
      stdio: "inherit",
    });
    child.once("error", (error) => {
      reject(new Error(`postinstall in ${hook.relDir} failed to start: ${error.message}`));
    });
    child.once("close", (code, signal) => {
      if (code === 0) resolve();
      else reject(new Error(`postinstall in ${hook.relDir} exited with ${signal ?? code}`));
    });
  });
}

export async function replayWorkspacePostinstalls(rootDir = repoRoot, env = process.env) {
  const canonicalRoot = path.resolve(rootDir);
  const { workspaceHooks, rootHook } = findWorkspacePostinstallScripts(canonicalRoot);
  // Mirror `pnpm -r --if-present run postinstall && pnpm run postinstall`:
  // run independent workspace hooks in parallel first, then the root hook.
  await Promise.all(workspaceHooks.map((hook) => runHook(hook, canonicalRoot, env)));
  if (rootHook) {
    await runHook(rootHook, canonicalRoot, env);
  }
  return {
    workspaceCount: workspaceHooks.length,
    ranRoot: Boolean(rootHook),
  };
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : null;
if (invokedPath && invokedPath === fileURLToPath(import.meta.url)) {
  await replayWorkspacePostinstalls();
}
