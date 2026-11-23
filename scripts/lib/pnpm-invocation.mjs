// Runs pnpm without a shell, on every platform.
//
// A bare `pnpm` on Windows is `pnpm.cmd`, and Node.js refuses to spawn a .cmd file
// without a shell. Spawning through a shell would hand the arguments to `cmd`,
// which treats `&`, `|` and `^` as syntax, so these helpers never do that. Inside
// a pnpm script, pnpm sets `npm_execpath` to its own entry point: a JavaScript
// file (run through this Node) or a native executable (run directly). Outside a
// pnpm script, `pnpm` on PATH is the only option, which works where pnpm is a
// native executable (the standalone install, Linux and macOS).
import { spawn, spawnSync } from "node:child_process";

export function resolvePnpmInvocation(env = process.env, nodeExecPath = process.execPath) {
  const npmExecPath = env.npm_execpath?.trim();
  if (npmExecPath && npmExecPath.toLowerCase().includes("pnpm")) {
    if (/\.(cjs|mjs|js)$/i.test(npmExecPath)) {
      return { command: nodeExecPath, argsPrefix: [npmExecPath] };
    }
    return { command: npmExecPath, argsPrefix: [] };
  }
  return { command: "pnpm", argsPrefix: [] };
}

/** `spawn` for pnpm, with no shell. */
export function spawnPnpm(args, options = {}) {
  const { command, argsPrefix } = resolvePnpmInvocation(options.env ?? process.env);
  return spawn(command, [...argsPrefix, ...args], { ...options, shell: false });
}

/** `spawnSync` for pnpm, with no shell. */
export function spawnPnpmSync(args, options = {}) {
  const { command, argsPrefix } = resolvePnpmInvocation(options.env ?? process.env);
  return spawnSync(command, [...argsPrefix, ...args], { ...options, shell: false });
}
