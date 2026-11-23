import { describe, expect, it } from "vitest";
import { gatewayTransportAllowed, isNonPublicHost } from "./plaintext-ws.js";

const ok = (u: string, env: NodeJS.ProcessEnv = {}) => gatewayTransportAllowed(new URL(u), env);

describe("gatewayTransportAllowed", () => {
  it("always allows wss", () => expect(ok("wss://gateway.example.com")).toBe(true));
  it.each(["ws://127.0.0.1:1", "ws://localhost", "ws://[::1]:9", "ws://10.1.2.3", "ws://172.20.0.1", "ws://192.168.1.5",
    "ws://100.100.1.1", "ws://169.254.1.1", "ws://box.ts.net", "ws://nas.local", "ws://[fd12::1]"])("allows plaintext %s", (u) =>
    expect(ok(u)).toBe(true));
  it.each(["ws://gateway.example.com", "ws://8.8.8.8", "ws://172.32.0.1", "ws://100.128.0.1", "ws://evil.local.example.com"])(
    "rejects plaintext %s", (u) => expect(ok(u)).toBe(false));
  it("honours the override", () => expect(ok("ws://gateway.example.com", { PAPERCLIP_ALLOW_INSECURE_GATEWAY_WS: "1" })).toBe(true));
  it("rejects other schemes", () => expect(ok("http://127.0.0.1")).toBe(false));
  it("isNonPublicHost ignores empty", () => expect(isNonPublicHost("")).toBe(false));
});
