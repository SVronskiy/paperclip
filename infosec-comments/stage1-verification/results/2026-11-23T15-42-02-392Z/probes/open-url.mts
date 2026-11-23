
import { resolveOpenUrlCommand, normalizeUrlToOpen } from "file:///Users/mac/repos/paperclip/cli/src/client/board-auth.ts";
const good = resolveOpenUrlCommand("https://paperclip.example.test/cli-auth/abc?x=1&y=2", "win32");
const attacks = ["calc.exe", "https://example.test/a b", "javascript:alert(1)", "file:///C:/Windows/System32/calc.exe", "https://u:p@example.test/", "https://example.test/\nx"];
console.log(JSON.stringify({ good, rejected: attacks.map((u) => normalizeUrlToOpen(u) === null) }));
