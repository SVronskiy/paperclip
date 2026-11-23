
import { TelemetryClient, resolveTelemetryConfig } from "file:///Users/mac/repos/paperclip/packages/shared/src/telemetry/index.ts";
const calls: string[] = [];
(globalThis as any).fetch = async (url: string) => { calls.push(String(url)); return { ok: true, status: 200 }; };
const state = () => ({ installId: "i", salt: "s", createdAt: "2026-01-01T00:00:00Z", firstSeenVersion: "0" });
const result: Record<string, unknown> = {};
// Opted in but no endpoint configured: the client must drop events, not send them anywhere.
delete process.env.PAPERCLIP_TELEMETRY_ENDPOINT;
process.env.PAPERCLIP_TELEMETRY_ENABLED = "1";
const optedIn = resolveTelemetryConfig({ enabled: true });
const client = new TelemetryClient({ ...optedIn, endpoint: undefined }, state, "0.0.0");
client.track("install.started", {} as never);
await client.flush(); client.stop();
result.optedInWithoutEndpoint = calls.length;
// DO_NOT_TRACK=true: telemetry must be disabled, so no client is created at all.
process.env.DO_NOT_TRACK = "true";
result.doNotTrackEnabled = resolveTelemetryConfig({ enabled: true }).enabled;
console.log(JSON.stringify(result));
