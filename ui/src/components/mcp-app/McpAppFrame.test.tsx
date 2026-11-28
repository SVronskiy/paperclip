// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { describe, expect, it, vi } from "vitest";
import { McpAppFrame } from "./McpAppFrame";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

function frame(container: HTMLElement) {
  const iframe = container.querySelector("iframe");
  if (!iframe) throw new Error("no iframe");
  return iframe;
}

function fromView(iframe: HTMLIFrameElement, data: unknown) {
  window.dispatchEvent(new MessageEvent("message", { data, source: iframe.contentWindow }));
}

describe("McpAppFrame", () => {
  it("ignores a navigated frame's messages and remounts the original view", async () => {
    const callTool = vi.fn(async () => ({ content: [] }));
    const container = document.createElement("div");
    document.body.appendChild(container);
    const root = createRoot(container);
    await act(async () => {
      root.render(
        <McpAppFrame
          title="Circleback: Display meetings"
          viewId="view-1"
          toolName="DisplayMeetings"
          resource={{ uri: "ui://circleback/meetings", html: "<p>cards</p>", csp: {}, permissions: {}, prefersBorder: true }}
          toolInput={{}}
          toolResult={{ content: [] }}
          callTool={callTool}
        />,
      );
    });
    const original = frame(container);
    // The view's own document loads first (jsdom fires this for srcdoc).
    let loaded = original.contentDocument?.readyState === "complete";
    original.addEventListener("load", () => { loaded = true; });
    for (let i = 0; i < 100 && !loaded; i += 1) {
      await act(async () => { await new Promise((resolve) => setTimeout(resolve, 10)); });
    }
    expect(loaded).toBe(true);

    // The view's own document works.
    await act(async () => {
      fromView(original, { jsonrpc: "2.0", id: 1, method: "ui/initialize", params: {} });
      fromView(original, { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "RefreshMeetingCards", arguments: {} } });
      await new Promise((resolve) => setTimeout(resolve, 0));
    });
    expect(callTool).toHaveBeenCalledTimes(1);

    // The frame loads another document: its channel is dropped.
    await act(async () => {
      original.dispatchEvent(new Event("load"));
      fromView(original, { jsonrpc: "2.0", id: 3, method: "ui/initialize", params: {} });
      fromView(original, { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "DeleteTag", arguments: {} } });
      await new Promise((resolve) => setTimeout(resolve, 0));
    });
    expect(callTool).toHaveBeenCalledTimes(1);
    // A fresh iframe with the original view replaces it.
    const remounted = frame(container);
    expect(remounted).not.toBe(original);
    expect(remounted.getAttribute("srcdoc")).toContain("<p>cards</p>");
    await act(async () => root.unmount());
    container.remove();
  });

  it("keeps the view's host when a refetch hands over equal data, and remounts for a new document", async () => {
    const callTool = vi.fn(async () => ({ content: [] }));
    const container = document.createElement("div");
    document.body.appendChild(container);
    const root = createRoot(container);
    const props = (html: string) => ({
      title: "Circleback: Display meetings",
      viewId: "view-1",
      toolName: "DisplayMeetings",
      // New object identities on every render, as a refetch produces.
      resource: { uri: "ui://circleback/meetings", html, csp: {}, permissions: {}, prefersBorder: true },
      toolInput: { meetingIds: ["m1"] },
      toolResult: { content: [{ type: "text", text: "ok" }] },
      callTool,
    });
    await act(async () => root.render(<McpAppFrame {...props("<p>cards</p>")} />));
    const original = frame(container);
    await act(async () => {
      fromView(original, { jsonrpc: "2.0", id: 1, method: "ui/initialize", params: {} });
      await new Promise((resolve) => setTimeout(resolve, 0));
    });

    await act(async () => root.render(<McpAppFrame {...props("<p>cards</p>")} />));
    expect(frame(container)).toBe(original);
    await act(async () => {
      fromView(original, { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "RefreshMeetingCards", arguments: {} } });
      await new Promise((resolve) => setTimeout(resolve, 0));
    });
    // The same host still knows the view finished ui/initialize.
    expect(callTool).toHaveBeenCalledTimes(1);

    await act(async () => root.render(<McpAppFrame {...props("<p>new cards</p>")} />));
    expect(frame(container)).not.toBe(original);
    expect(frame(container).getAttribute("srcdoc")).toContain("new cards");
    expect(frame(container).getAttribute("sandbox")).toBe("allow-scripts");
    await act(async () => root.unmount());
    container.remove();
  });
  it("answers the view only through the guard's port, never with a wildcard postMessage", async () => {
    const callTool = vi.fn(async () => ({ content: [] }));
    const container = document.createElement("div");
    document.body.appendChild(container);
    const root = createRoot(container);
    await act(async () => root.render(
      <McpAppFrame
        title="View"
        viewId="view-1"
        toolName="DisplayMeetings"
        resource={{ uri: "ui://circleback/meetings", html: "<p>cards</p>", csp: {}, permissions: {}, prefersBorder: true }}
        toolInput={{}}
        toolResult={{ content: [] }}
        callTool={callTool}
      />,
    ));
    const iframe = frame(container);
    expect(iframe.getAttribute("srcdoc")).toContain(JSON.stringify(window.location.origin));
    const direct = vi.spyOn(iframe.contentWindow!, "postMessage");
    const received: unknown[] = [];
    const channel = new MessageChannel();
    channel.port1.onmessage = (event) => received.push(event.data);
    await act(async () => {
      // A request that arrives before the port is answered once the port arrives.
      fromView(iframe, { jsonrpc: "2.0", id: 1, method: "ui/initialize", params: {} });
      window.dispatchEvent(new MessageEvent("message", {
        data: { jsonrpc: "2.0", method: "paperclip/host-channel" }, source: iframe.contentWindow, ports: [channel.port2],
      }));
      // A second offer (the view's own code) is ignored.
      const rogue = new MessageChannel();
      rogue.port1.onmessage = () => received.push("rogue");
      window.dispatchEvent(new MessageEvent("message", {
        data: { jsonrpc: "2.0", method: "paperclip/host-channel" }, source: iframe.contentWindow, ports: [rogue.port2],
      }));
      for (let i = 0; i < 50 && received.length === 0; i += 1) await new Promise((resolve) => setTimeout(resolve, 5));
    });
    expect(direct).not.toHaveBeenCalled();
    expect(received).not.toContain("rogue");
    expect(received[0]).toMatchObject({ jsonrpc: "2.0", id: 1 });
    channel.port1.close();
    await act(async () => root.unmount());
    container.remove();
  });
});
