# Stage 1 verification report

- Commit: `1a80e2963df4a27e64e7230c84e154364b490541`
- Generated: 2026-11-28T06:08:25.796Z
- Result: 8 passed, 0 failed, 0 open, 0 skipped, 0 informational

> This report describes vulnerabilities. Keep it out of public places.

| Stream | Check | Status | Detail |
|---|---|---|---|
| E1-12 | MCP Apps: no wildcard postMessage target; host talks to the view only through the guard's port | PASS |  Test Files 2 passed (2) / Tests 22 passed (22) |
| E1-12 | Request paths echoed into HTML (Vite render, OAuth interstitial) are same-origin paths only | PASS |  Test Files 2 passed (2) / Tests 17 passed (17) |
| E1-12 | Agent instruction routes refuse traversal paths before any file service runs | PASS |  Test Files 1 passed (1) / Tests 32 passed (32) |
| E1-12 | Summary slot routes parse scope and slot against fixed enums; webhook headers are read by literal name | PASS |  Test Files 2 passed (2) / Tests 15 passed (15) |
| E1-12 | VEX records the hyper and grpc-js false matches and covers every locked version | PASS | vex: ok (2 analysed findings); ℹ pass 3 ℹ fail 0 |
| E1-10 | @grpc/grpc-js is at or above 1.14.5 (the version that fixes the Trivy finding) | PASS | pnpm-lock.yaml: 1.14.5, 1.14.5 |
| E1-10 | hyper in the Rust runner lockfile: false CPE match, recorded in security/vex.cdx.json | PASS | hyper 1.11.1: CVE-2024-23741 is Vercel's Hyper terminal; VEX not_affected/code_not_present |
| E1-10 | Dependency changes in this branch respect the reviewed-lockfile gate | PASS | pnpm-lock.yaml is unchanged from master, so the reviewed-lock gate is untouched |
