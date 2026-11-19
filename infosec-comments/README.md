# Замечания ИБ к пилоту Paperclip

Материалы по замечаниям информационной безопасности перед пилотом Paperclip (AI-PDLC, изолированный контур).

- [SECURITY-REMEDIATION-PLAN.md](SECURITY-REMEDIATION-PLAN.md) — план устранения замечаний команды безопасности ПО (БПО), команды безопасной разработки (БР) и собственной проверки (Opus).
- `reports/` — сырые отчёты проверок, на которые ссылается план.

Проверки выполнены 2026-11-19 по ревизии `master` @ `3dffb2c9d`.

> Отчёты содержат сведения об уязвимостях. По внутренним требованиям информация о выявленных уязвимостях конфиденциальна: не публикуйте ветку и папку во внешних репозиториях.

## Отчёты

Контрольные суммы всех файлов в `reports/` — в `reports/SHA256SUMS`. Проверка:

```bash
cd infosec-comments/reports && shasum -a 256 -c SHA256SUMS
```

| Файл | Инструмент | Что внутри |
|---|---|---|
| `reports/pnpm-audit-prod.json` | `pnpm audit --prod --json` (pnpm 9.15.4) | Уязвимости production-зависимостей: 1 Critical, 43 High, 52 Moderate, 16 Low |
| `reports/pnpm-audit-all.json` | `pnpm audit --json` | То же с dev-зависимостями: 2 Critical, 48 High |
| `reports/trivy-fs.json` | Trivy 0.66.0, `fs --scanners vuln,secret,misconfig` | Уязвимости зависимостей (2 Critical, 50 High), секреты (3, тестовые фикстуры), мисконфигурации Dockerfile и IaC |
| `reports/gitleaks.json` | gitleaks 8.28.0, `dir` | 309 срабатываний; реальных секретов нет (тестовые ключи, хеши в `doc/`) |
| `reports/semgrep.json` | Semgrep 1.140.0: `p/javascript`, `p/typescript`, `p/nodejsscan`, `p/expressjs`, `p/react` | 416 находок в prod-коде `server`, `cli`, `ui`, `adapter-utils`, `adapters`, `shared`, `db`; 553 файла пропущено по тайм-ауту |

## Предварительное динамическое тестирование (`reports/dast/`)

Сервер запускался из исходников в режиме `authenticated/private` на `127.0.0.1:3197` со встроенной БД. Телеметрия была направлена на локальный перехватчик, наружу ничего не отправлялось.

| Файл | Назначение |
|---|---|
| `capture.mjs` | Локальный перехватчик HTTP на `127.0.0.1:18999` для телеметрии (D-1) |
| `captured.jsonl` | Перехваченное событие `server.started`, отправленное при `DO_NOT_TRACK=true` |
| `env-leak.mts` | Запуск `runChildProcess` с `/usr/bin/env`: какие секреты сервера видит процесс агента (D-2) |
| `pg.mjs` | Вход во встроенный Postgres с `paperclip/paperclip` (D-3) |
| `routes.txt` | Список GET/POST-маршрутов, извлечённых из `server/src/routes` и `server/src/app.ts` |
| `unauth-sweep.txt` | Коды ответов на GET-маршруты без авторизации (D-4, D-5) |

Повтор проверки env-leak (из корня репозитория, после `pnpm install`):

```bash
BETTER_AUTH_SECRET=canary DATABASE_URL=postgres://u:canary@db/p server/node_modules/.bin/tsx infosec-comments/reports/dast/env-leak.mts
```

После исправления Opus-1 обе переменные должны показываться как «скрыт».
