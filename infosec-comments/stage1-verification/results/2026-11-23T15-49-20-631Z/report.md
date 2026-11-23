# Stage 1 verification report

- Commit: `79f1ee623e0d83f944cec8e2ce0b2b646700e1c0`
- Generated: 2026-11-23T15:53:57.131Z
- Result: 35 passed, 0 failed, 1 open, 1 skipped, 2 informational

> This report describes vulnerabilities. Keep it out of public places.

| Stream | Check | Status | Detail |
|---|---|---|---|
| E1-0 | The repository is the stage 1 branch with its dependencies installed | info | branch pilot/hardening at 79f1ee623 |
| E1-1 | No built-in telemetry collector address in product code | PASS | no telemetry.paperclip.ing or execute-api.us-east-1 address |
| E1-1 | Telemetry is opt-in and every opt-out spelling wins | PASS | default off; opt-in works; 1/true/yes/on opt-outs win |
| E1-1 | A client with default settings, and one with DO_NOT_TRACK=true, make no network request | PASS | 0 requests without an operator endpoint; DO_NOT_TRACK=true disables telemetry |
| E1-1 | Feedback trace export is disabled without an explicit backend URL | PASS | no client is created without PAPERCLIP_FEEDBACK_EXPORT_BACKEND_URL |
| E1-1 | Telemetry and feedback unit tests pass | PASS |  Test Files 3 passed (3) / Tests 18 passed (18) /  Test Files 7 passed (7) / Tests 51 passed (51) |
| E1-2 | No spawn with a shell (shell: true or a platform-dependent shell flag) in product code and scripts | PASS | no shell spawning found |
| E1-2 | The pnpm launcher passes shell metacharacters as one literal argument | PASS | ℹ pass 4 ℹ fail 0 |
| E1-2 | The CLI opens approval URLs on Windows without cmd and rejects command-injection URLs | PASS | rundll32 url.dll,FileProtocolHandler; 6 unsafe URL forms rejected |
| E1-2 | CLI board-auth tests pass | PASS |  Test Files 1 passed (1) / Tests 23 passed (23) |
| E1-3 | Every stage of the smoke Dockerfiles sets a non-root USER | PASS | both smoke Dockerfiles run unprivileged in every stage |
| E1-3 | Trivy reports no DS002 (root user) finding for the two smoke Dockerfiles | PASS | no DS002 |
| E1-3 | The openclaw smoke image builds and runs as a non-root user | PASS | runs as uid 1000 |
| E1-4 | docker-compose.yml publishes no database port and has no default database password | PASS | no published port; POSTGRES_PASSWORD is required |
| E1-4 | docker compose refuses to render without POSTGRES_PASSWORD and renders without ports with it | PASS | ℹ pass 3 ℹ fail 0 |
| E1-4 | No default database password in .env.example, docs and CLI help | PASS | none found |
| E1-4 | PAPERCLIP_REQUIRE_EXTERNAL_DATABASE makes startup refuse the embedded development database | PASS |  Test Files 1 passed (1) / Tests 7 passed (7) |
| E1-5 | The Go agent shim rejects unsafe commands (go test) | PASS | ok  	github.com/paperclipai/paperclip/tools/agent-shim	(cached) |
| E1-4 | The embedded database uses a random per-instance password (no fixed paperclip/paperclip in product code) | PASS |  Test Files 1 passed (1) / Tests 4 passed (4) |
| E1-4 | The real server starts on a fresh and on a legacy embedded database, serves the API, and moves the legacy password | PASS | ok: fresh start reaches /api/health (status ok); ok: database password is random and stored with mode 0600 (mode 600, 48 chars); ok: an API route backed by the database answers (GET /api/companies -> 200); ok: the old fixed password is rejected (connect as paperclip/paperclip); ok: the stored password is accepted; ok: a legacy cluster (old password, no password file) starts; ok: the legacy cluster is moved to a random password; ok: the upgraded password works and the old one no longer does; ok: a restart reuses the stored password |
| E1-5 | Security baseline: no Math.random, MD5/SHA-1 (outside documented protocol uses), shell spawning or built-in telemetry address | PASS | security baseline: ok |
| E1-5 | The baseline check has tests and they pass | PASS | ℹ pass 6 ℹ fail 0 |
| E1-6 | secure-random helpers never use Math.random and stay in range | PASS |  Test Files 1 passed (1) / Tests 7 passed (7) |
| E1-6 | UI tests that depended on Math.random pass with crypto-backed randomness | PASS |  Test Files 3 passed (3) / Tests 40 passed (40) |
| E1-6 | Server retry/backoff tests that depended on Math.random pass | PASS |  Test Files 2 passed (2) / Tests 6 passed (6) |
| E1-7 | Hash replacements: ETag, redaction version and attention content use SHA-256 | PASS | MD5 replaced by SHA-256 in the three server places |
| E1-7 | Remaining SHA-1/MD5 uses are exactly the documented protocol exceptions | info | 1 protocol-mandated use(s): WebSocket accept x2, UUIDv5 x1, S3 Content-MD5 benchmark fake x1. A security-service exception request is still needed. |
| E1-8 | Redirect, OAuth-return and registration tests pass | PASS |  Test Files 3 passed (3) / Tests 56 passed (56) /  Test Files 1 passed (1) / Tests 16 passed (16) |
| E1-8 | Open-redirect payloads never reach res.redirect | PASS | 8 payloads all replaced by the fallback |
| E1-8 | res.redirect appears only inside safe-redirect.ts across server routes and app.ts | PASS | every redirect goes through safeRedirect or redirectToValidatedLocation |
| E1-8 | redirectToValidatedLocation blocks javascript:, data:, //host, plain http and credentials | PASS |  Test Files 1 passed (1) / Tests 29 passed (29) |
| E1-11 | Every AES-GCM decryption fixes the authentication tag length | PASS | 12 files, all GCM decipher calls pin authTagLength |
| E1-11 | Plaintext ws:// is refused toward public hosts and still works on loopback, private and tailnet hosts | PASS |  Test Files 1 passed (1) / Tests 20 passed (20) |
| E1-11 | Gateway adapter, announcements and secret-encryption suites still pass | PASS |  Test Files 6 passed (6) / Tests 140 passed (140) |
| E1-9 | Plugin UI static route denies hidden files and keeps dot-directory installs working | PASS |  Test Files 1 passed (1) / Tests 8 passed (8) |
| E1-10 | @grpc/grpc-js is at or above 1.14.5 (the version that fixes the Trivy finding) | PASS | pnpm-lock.yaml: 1.14.5, 1.14.5 |
| E1-10 | hyper in the Rust runner lockfile (Dependency-Track critical finding) | OPEN | hyper 1.11.1 is still locked. CVE-2024-23741 describes the Hyper terminal for macOS, not the Rust crate, so this looks like a false match by CPE; confirm with the secure-development team and record the analysis in Dependency-Track. The SBOM for it is infosec-comments/reports/stage1/sbom-cyclonedx.json. |
| E1-10 | Dependency changes in this branch respect the reviewed-lockfile gate | PASS | pnpm-lock.yaml is unchanged from master, so the reviewed-lock gate is untouched |
| E1-11 | Horusec re-run: weak random and MD5 findings are gone | skip | use --with-scanners |
