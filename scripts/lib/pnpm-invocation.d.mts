import type { ChildProcess, SpawnOptions, SpawnSyncOptions, SpawnSyncReturns } from "node:child_process";

export function resolvePnpmInvocation(
  env?: NodeJS.ProcessEnv,
  nodeExecPath?: string,
): { command: string; argsPrefix: string[] };

export function spawnPnpm(args: readonly string[], options?: SpawnOptions): ChildProcess;

export function spawnPnpmSync(
  args: readonly string[],
  options?: SpawnSyncOptions,
): SpawnSyncReturns<string | Buffer>;
