
import { safeRedirect } from "file:///Users/mac/repos/paperclip/server/src/routes/safe-redirect.ts";
const payloads = ["//evil.example", "https://evil.example", "/\\evil.example", "\\\\evil.example", "javascript:alert(1)", "data:text/html,x", "/a\nb", "evil.example"];
const leaked: string[] = [];
for (const payload of payloads) {
  let target = "";
  safeRedirect({ redirect: (_s: number, t: string) => { target = t; } } as never, 303, payload);
  if (target !== "/") leaked.push(payload);
}
console.log(JSON.stringify({ leaked }));
