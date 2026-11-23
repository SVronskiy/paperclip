
import { resolveTelemetryConfig } from "file:///Users/mac/repos/paperclip/packages/shared/src/telemetry/config.ts";
const keys = ["PAPERCLIP_TELEMETRY_ENABLED","PAPERCLIP_TELEMETRY_DISABLED","DO_NOT_TRACK","CI","GITHUB_ACTIONS"];
const reset = () => { for (const k of keys) delete process.env[k]; };
const out: Record<string, unknown> = {};
reset(); out.defaultOff = resolveTelemetryConfig().enabled === false;
reset(); out.fileDefaultOff = resolveTelemetryConfig({}).enabled === false;
reset(); process.env.PAPERCLIP_TELEMETRY_ENABLED = "1"; out.envOptIn = resolveTelemetryConfig().enabled === true;
const optOut: Record<string, boolean> = {};
for (const key of ["PAPERCLIP_TELEMETRY_DISABLED", "DO_NOT_TRACK"]) {
  for (const value of ["1", "true", "TRUE", "yes", "on"]) {
    reset(); process.env.PAPERCLIP_TELEMETRY_ENABLED = "1"; process.env[key] = value;
    optOut[key + "=" + value] = resolveTelemetryConfig({ enabled: true }).enabled === false;
  }
}
out.optOut = optOut;
reset(); process.env.PAPERCLIP_TELEMETRY_ENABLED = "1"; out.fileDisabledWins = resolveTelemetryConfig({ enabled: false }).enabled === false;
reset(); process.env.PAPERCLIP_TELEMETRY_ENABLED = "1"; process.env.CI = "true"; out.ciWins = resolveTelemetryConfig().enabled === false;
console.log(JSON.stringify(out));
