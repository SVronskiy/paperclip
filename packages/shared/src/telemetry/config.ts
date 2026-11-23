import type { TelemetryBackoffConfig, TelemetryConfig } from "./types.js";

const CI_ENV_VARS = ["CI", "CONTINUOUS_INTEGRATION", "BUILD_NUMBER", "GITHUB_ACTIONS", "GITLAB_CI"];

/**
 * Single source of truth for telemetry soft caps + backoff. Kept as config
 * *defaults* (not hardcoded flush logic) so later work reads config, not
 * literals. Exported so the `client.ts` consumer resolves the same values.
 */
export const TELEMETRY_DEFAULTS: {
  readonly maxEventsPerBatch: number;
  readonly maxBodyBytes: number;
  readonly maxPendingRetryBatches: number;
  readonly backoff: Readonly<TelemetryBackoffConfig>;
} = Object.freeze({
  maxEventsPerBatch: 50,
  maxBodyBytes: 512 * 1024, // 524288
  maxPendingRetryBatches: 20,
  backoff: Object.freeze({
    baseDelayMs: 1_000,
    maxDelayMs: 30_000,
    maxAttempts: 5,
    jitterRatio: 0.25,
  }),
});

/** Caller-supplied overrides for the additive caps + backoff surface. */
export type TelemetryConfigOverrides = Partial<
  Pick<
    TelemetryConfig,
    "enabled" | "maxEventsPerBatch" | "maxBodyBytes" | "maxPendingRetryBatches" | "backoff"
  >
>;

/**
 * Fully-resolved caps + backoff — every field is present (defaults applied), so
 * `client.ts` can consume them without re-defaulting. `TelemetryConfig`'s own
 * cap fields stay optional (additive wire surface); this is the resolved view.
 */
export interface ResolvedTelemetryCaps {
  maxEventsPerBatch: number;
  maxBodyBytes: number;
  maxPendingRetryBatches: number;
  backoff: TelemetryBackoffConfig;
}

/**
 * Resolves soft caps + backoff, applying `TELEMETRY_DEFAULTS` for any field the
 * caller did not override. One source of truth for both the config surface and
 * the `client.ts` consumer.
 */
export function resolveCaps(overrides?: TelemetryConfigOverrides): ResolvedTelemetryCaps {
  return {
    maxEventsPerBatch: overrides?.maxEventsPerBatch ?? TELEMETRY_DEFAULTS.maxEventsPerBatch,
    maxBodyBytes: overrides?.maxBodyBytes ?? TELEMETRY_DEFAULTS.maxBodyBytes,
    maxPendingRetryBatches:
      overrides?.maxPendingRetryBatches ?? TELEMETRY_DEFAULTS.maxPendingRetryBatches,
    backoff: { ...TELEMETRY_DEFAULTS.backoff, ...overrides?.backoff },
  };
}

/** Accepts the usual spellings of an enabled flag: 1, true, yes, on (case-insensitive). */
function isTruthyFlag(value: string | undefined): boolean {
  const normalized = value?.trim().toLowerCase();
  return normalized === "1" || normalized === "true" || normalized === "yes" || normalized === "on";
}

function isCI(): boolean {
  return CI_ENV_VARS.some((key) => isTruthyFlag(process.env[key]));
}

/**
 * Telemetry is opt-in. It stays off unless the operator turns it on with
 * `PAPERCLIP_TELEMETRY_ENABLED` or `telemetry.enabled: true` in the config
 * file, and any opt-out signal (`PAPERCLIP_TELEMETRY_DISABLED`, `DO_NOT_TRACK`,
 * CI, `telemetry.enabled: false`) wins over an opt-in. There is no built-in
 * collector address: events are sent only to `PAPERCLIP_TELEMETRY_ENDPOINT`
 * (or to a custom transport) and are dropped when neither is configured.
 */
export function resolveTelemetryConfig(
  fileConfig?: { enabled?: boolean } & TelemetryConfigOverrides,
): TelemetryConfig {
  const caps = resolveCaps(fileConfig);

  if (isTruthyFlag(process.env.PAPERCLIP_TELEMETRY_DISABLED)) {
    return { enabled: false, ...caps };
  }
  if (isTruthyFlag(process.env.DO_NOT_TRACK)) {
    return { enabled: false, ...caps };
  }
  if (isCI()) {
    return { enabled: false, ...caps };
  }
  if (fileConfig?.enabled === false) {
    return { enabled: false, ...caps };
  }

  const optedIn = isTruthyFlag(process.env.PAPERCLIP_TELEMETRY_ENABLED) || fileConfig?.enabled === true;
  if (!optedIn) {
    return { enabled: false, ...caps };
  }

  const endpoint = process.env.PAPERCLIP_TELEMETRY_ENDPOINT || undefined;
  return { enabled: true, endpoint, ...caps };
}
