import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { emailWebhookRoutes } from "../routes/email.js";

describe("AgentMail webhook route", () => {
  it("passes only the three signature headers to the service", async () => {
    const webhook = vi.fn(async () => undefined);
    const app = express();
    app.use(express.raw({ type: "*/*" }));
    app.use(emailWebhookRoutes({ webhook } as never));
    const res = await request(app)
      .post("/api/chat-webhooks/agentmail/pub-1")
      .set("content-type", "application/json")
      .set("svix-id", "msg_1")
      .set("svix-timestamp", "1700000000")
      .set("svix-signature", "v1,abc")
      .set("x-extra", "ignored")
      .set("__proto__", "x")
      .send('{"ok":true}');
    expect(res.status).toBe(204);
    const [, body, headers] = webhook.mock.calls[0] as unknown as [string, Buffer, Record<string, string>];
    expect(body.toString()).toBe('{"ok":true}');
    expect({ ...headers }).toEqual({ "svix-id": "msg_1", "svix-timestamp": "1700000000", "svix-signature": "v1,abc" });
    expect(Object.getPrototypeOf(headers)).toBeNull();
  });
});
