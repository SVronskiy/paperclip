# План устранения замечаний ИБ перед пилотом Paperclip (AI-PDLC, изолированный контур)

- Ревизия кода: `master` @ `3dffb2c9d` (2026-11-18).
- Цель пилота (по письму): развернуть Paperclip в изолированном контуре, настроить ограничения, доступы и логирование, прогнать сквозной сценарий AI-PDLC на тестовых данных без доступа к продуктивным системам. Пилот не означает выбор Paperclip целевым решением.
- Нормативная база: внутренние требования к разработке безопасного ПО (далее — **РБПО**). Ссылки вида «РБПО 3» указывают раздел требований.
- Группы замечаний:
  - **БПО** — замечания команды безопасности ПО;
  - **БР** — замечания команды безопасной разработки (Semgrep, Horusec, Dependency-Track; 159 находок в выгрузке, 158 в письме);
  - **Opus** — замечания по результатам собственной проверки (Claude Opus 5.5): ручной разбор кода, Trivy, gitleaks, Semgrep, `pnpm audit`, предварительное динамическое тестирование.

Все замечания БПО и БР принимаются к обязательному триажу и закрытию: исправлением, доказанным ложноположительным срабатыванием либо согласованным службой ИБ исключением. Если код где-то уже частично соответствует требованию, это отмечено как «текущее состояние», но не снимает обязанность представить доказательство.

**Сроки устранения (РБПО, «Сроки устранения дефектов»):** Critical — 3 дня, High — 10 дней (оба блокируют допуск), Medium — 1 месяц, Low — тех. долг.

**Работы разделены на два этапа** (подробно — раздел «Этапы работ» после сводки):

- **Этап 1 — срочные исправления исходного кода по замечаниям ИБ из письма начала ноября.** В этап входят:
  - замечания БПО, которые требуют изменения кода: телеметрия, Windows shell, smoke-образы от root, Postgres и пароли по умолчанию;
  - все находки из отчёта БР;
  - всё, что те же сканеры (Semgrep с наборами правил БР, Horusec, Dependency-Track) выдают на текущей ревизии.

  Результат этапа передаётся в ИБ на повторную проверку.
- **Этап 2 — все остальные замечания плана и допуск к пилоту.** Сюда входят меры развёртывания по БПО-2, БПО-3 и остатку БПО-5 и БПО-6, все замечания Opus, зависимости из `pnpm audit` и Trivy, контур, Gates A–D (раздел 8).

> **Отчёт БР получен.** Приложение к письму — выгрузка из DefectDojo трёх сканеров: Semgrep (28 находок), Horusec (128) и Dependency-Track (3). Всего 159 активных находок: 1 Critical, 154 High, 4 Medium. В письме указано 158 и 153 High — расхождение в одну High-находку нужно сверить с БР. Сканирование выполнено 3–5 ноября 2026, то есть по более ранней ревизии, чем `3dffb2c9d`. Разбор каждой находки — в [br-findings-registry.csv](br-findings-registry.csv), сводка — в разделе 3.6.

### Решение о допуске

На текущей ревизии — **NO-GO**. Закрытие этапа 1 снимает замечания письма ИБ, но само по себе допуска к пилоту не даёт: подтверждённые динамически Opus-1 (секреты сервера в окружении агента) и Opus-2 (агент без изоляции) закрываются на этапе 2. Минимальные условия перехода к пилоту:

1. Закрыты подтверждённые пути компрометации: утечка окружения серверного процесса агенту, локальное исполнение агента без изоляции, Critical-зависимости, внешняя телеметрия и общие ключи.
2. Выбран и проверен единственный способ исполнения агентов. Для пилота — Kubernetes sandbox provider (или эквивалентный удалённый runtime) с отдельным pod на запуск; локальные адаптеры на pod сервера запрещены.
3. Получен и разобран отчёт БР: для каждой Critical/High находки есть исправление с тестом либо подписанное службой ИБ исключение с компенсирующей мерой и сроком.
4. Собран и отсканирован именно тот digest образа, который будет развёрнут; конфигурация контура прошла проверку как код.
5. Выполнены критерии приёмки раздела 8.3 и подписан протокол допуска владельцами сервиса, платформы и службы ИБ.

Статус находки ведётся как `Подтверждена / Не подтверждена / Ложноположительная / Принятый риск / Исправлена`. Число срабатываний сканера не равно числу эксплуатируемых уязвимостей; снижение уровня допускается только с зафиксированным обоснованием и подтверждением БР и службы ИБ.

---

## 0. Сводка

| ID | Группа | Кратко | Уровень | Блокирует пилот | Этап |
|---|---|---|---|---|---|
| БПО-1 | БПО | Телеметрия на `telemetry.paperclip.ing` и AWS API Gateway; отключение работает не во всех режимах (подтверждено динамически) | High | Да | 1 |
| БПО-2 | БПО | Смена ключей при развёртывании | High | Да | 2 |
| БПО-3 | БПО | Агент по умолчанию имеет доступ ко всем секретам (подтверждено динамически) | High | Да | 2 |
| БПО-4 | БПО | Windows: команды через shell в runner-скриптах | Medium | Да (исправить или запретить Windows) | 1 |
| БПО-5 | БПО | Docker-образы, работающие от root | High | Да | 1 (smoke-образы) / 2 (prod-образ) |
| БПО-6 | БПО | Postgres опубликован в compose, пароль `paperclip` по умолчанию (подтверждено динамически) | High | Да | 1 (compose, пароли) / 2 (роли, TLS) |
| БР-1 | БР | RCE: небезопасный вызов системных команд | Critical/High | Да | 1 |
| БР-2 | БР | Криптографически нестойкий ГСЧ (`Math.random`, 49 файлов prod-кода); заменяется полностью | High | Да | 1 |
| БР-3 | БР | Устаревшие MD5/SHA1; заменяются на SHA-256, кроме обязательных по протоколу (WebSocket, UUIDv5, S3 `Content-MD5`, Git) — по ним исключение службы ИБ | High | Да | 1 |
| БР-4 | БР | Open Redirect | High | Да | 1 |
| БР-5 | БР | Полный реестр находок БР: 159 (1 Critical, 154 High, 4 Medium), сводка в разделе 3.6 | по отчёту | Critical, High — да | 1 |
| БР-6 | БР | Windows: URL открывается через `cmd /c start` в CLI (`board-auth.ts`) — инъекция команд через `&`/`|` | High | Да (исправить или запретить Windows) |
| Opus-1 | Opus | Секреты сервера (`BETTER_AUTH_SECRET`, `DATABASE_URL`, ключи облаков и LLM) наследуются процессами агентов (подтверждено динамически) | Critical | Да | 2 |
| Opus-2 | Opus | Агенты не изолированы от сервера: тот же UID, песочница выключена, `--dangerously-skip-permissions` по умолчанию | High | Да | 2 |
| Opus-3 | Opus | Встроенный Postgres: `paperclip/paperclip`, роль **superuser** (подтверждено динамически) | High | Да | 1 (пароль по умолчанию) / 2 (superuser) |
| Opus-4 | Opus | Выгрузка feedback-трейсов на `telemetry.paperclip.ing` мимо флагов телеметрии | High | Да | 1 (тот же адрес, что БПО-1) |
| Opus-5 | Opus | Один ключ `BETTER_AUTH_SECRET` для нескольких целей | High | Да | 2 |
| Opus-6 | Opus | Уязвимые сторонние компоненты: `pnpm audit` — 1 Critical / 43 High в prod-зависимостях; Trivy — 2 Critical / 50 High | Critical | Да | 2 |
| Opus-7 | Opus | Открытая саморегистрация и слабая парольная политика (`12345678`, `password` принимаются) | High | Да | 2 |
| Opus-8 | Opus | Нет заголовков безопасности (HSTS, frame-ancestors/X-Frame-Options, CSP для UI); `X-Powered-By` раскрывает Express | Medium | Да | 2 |
| Opus-9 | Opus | Управление сессиями: 7 дней без ограничения неактивности, нет лимита одновременных сессий, cookie без `Secure` при HTTP | Medium | Да | 2 |
| Opus-10 | Opus | Валидация входных данных: невалидный id в пути даёт 500; поиск ресурса до проверки авторизации | Medium | Нет | 2 |
| Opus-11 | Opus | Публичные `/api/openapi.json` и `/api/health` (коммит, режим, состояние бэкапов) | Low | Нет | 2 |
| Opus-12 | Opus | Prod-образ: `curl`, `wget`, Tailscale (средство удалённого доступа), нет HEALTHCHECK, небезопасные env по умолчанию | Medium | Да | 2 |
| Opus-13 | Opus | Телеметрия и egress самих агентских CLI (Claude Code, Codex и др.) | High | Да | 2 |
| Opus-14 | Opus | Режим `local_trusted` отключает аутентификацию; запуск на не-loopback адресе уже запрещён в коде | Low | Нет (запрет конфигурацией и тест) | 2 |
| Opus-15 | Opus | В CI нет SAST, SCA, поиска секретов, сканирования образов | Medium | Нет | 2 |
| Opus-16 | Opus | AES-GCM без фиксированной длины тега (8 мест, включая хранилище секретов) | High | Да | 2 |
| Opus-17 | Opus | Сравнение токенов и кодов через `===` (атака по времени), 39 мест | Medium | Нет | 2 |
| Opus-18 | Opus | `CORS: *` для UI плагинов, `postMessage("*")`, `Content-Type` из внешнего фида, `sendFile` | Medium | Нет | 2 |
| Opus-19 | Opus | 173 SAST-срабатывания `regex_dos`, требующие проверки достижимости и входных ограничений | Medium | Нет | 2 |

---

## Этапы работ

### Этап 1. Срочные исправления кода по замечаниям ИБ (на повторную проверку)

**Состав.** Ровно то, что ИБ выдала в письме начала ноября, с поправкой на то, что те же инструменты выдают сейчас:

- замечания БПО, требующие изменений в исходном коде и файлах развёртывания в репозитории;
- 159 находок отчёта БР;
- новые срабатывания тех же сканеров на ревизии `3dffb2c9d` (повторный прогон 2026-11-23, см. ниже).

Меры, которые выполняются при развёртывании, а не в коде (смена ключей, ограничение подключений агента, контур), относятся к этапу 2.

**Срок.** По РБПО: Critical — 3 дня, High — 10 дней от подтверждения находки. Этап 1 укладывается в 10 рабочих дней.

**Результат.** Ветка `pilot/hardening` с исправлениями, реестр этапа 1 со статусом каждой строки, повторные отчёты тех же сканеров и SBOM коммита для Dependency-Track. Всё это передаётся в ИБ на повторную проверку.

#### Повторный прогон теми же инструментами (2026-11-23, ревизия `3dffb2c9d`)

| Инструмент | Конфигурация | Находки БР воспроизводятся | Новые срабатывания тех же правил | Новые типы срабатываний |
|---|---|---|---|---|
| Horusec 2.8.0 | движок Horusec без Docker; область отчёта БР (`server`, `ui`, `cli`, `packages`), без тестов, без категории Leaks, уровни Medium и выше | 126 из 128 (2 уже устранены) | 251 | 277 |
| Semgrep 1.140.0 | наборы `semgrep-rules` (JavaScript, TypeScript, Python, Go, bash, Dockerfile) и `ajinabraham/njsscan` с той же структурой `RULESETS`, что в отчёте БР; только уровень ERROR (High); без тестов и документации; 264 правила, 8285 файлов, 393 файла с ошибками разбора или тайм-аутом | 28 из 28 | 6 | 274 |
| Dependency-Track | локально не запускался; SBOM текущей ревизии (CycloneDX, Trivy) — [reports/stage1/sbom-cyclonedx.json](reports/stage1/sbom-cyclonedx.json) | все 3 компонента в тех же версиях | — | загрузить SBOM в Dependency-Track БР |

Число срабатываний на текущей ревизии заметно больше, чем в отчёте БР. Причин может быть две: БР выгружала только активные находки после своего разбора, или у неё была другая версия правил. Это нужно уточнить у БР до начала этапа. Все срабатывания внесены в реестр [stage1-registry.csv](stage1-registry.csv). У каждой строки указаны поток, происхождение (находка БР, новое срабатывание правила из отчёта БР или новый тип срабатывания) и действие. Сырые отчёты лежат в [reports/stage1/](reports/stage1/).

#### Потоки этапа 1

| Поток | Замечание | Что сделать в коде | Находок в реестре | Проверка для ИБ |
|---|---|---|---|---|
| Э1-1 | БПО-1, Opus-4 (тот же адрес `telemetry.paperclip.ing`) | Удалить `DEFAULT_ENDPOINTS` и `DEFAULT_FEEDBACK_EXPORT_BACKEND_URL`. Телеметрия только opt-in. Флаги отключения принимают `1/true/yes`. Feedback-трейсы выключены без явного URL (БПО-1 п. 1–2, Opus-4) | — | Юнит-тесты: без настроек `fetch` не вызывается. Строк `telemetry.paperclip.ing` и `execute-api.us-east-1` в prod-коде нет. Повтор D-1 с перехватчиком — 0 запросов |
| Э1-2 | БПО-4, БР-6 | Убрать `shell: true` на Windows в runner/dev/CI-скриптах (`cross-spawn`). В `board-auth.ts` открывать URL без `cmd` и проверять схему | Semgrep `spawn-shell-true`: 7 БР + 5 новых; Horusec 1 БР (`board-auth.ts`) | Semgrep `spawn-shell-true` = 0; тест с URL `…&calc` |
| Э1-3 | БПО-5 (smoke-образы) | `USER` с непривилегированным UID в `docker/openclaw-smoke/Dockerfile` и `docker/runner-image/Dockerfile.smoke`. В README образов пометка «не образец для prod» | — | Trivy misconfig DS002 по этим Dockerfile = 0 |
| Э1-4 | БПО-6, Opus-3 (пароль) | В `docker/docker-compose.yml` убрать `ports: 5432:5432`, пароль задавать только через обязательную переменную (`${POSTGRES_PASSWORD:?}`) или `_FILE`. Убрать `paperclip:paperclip` из `.env.example`, документации, CLI и скриптов (сейчас около 40 файлов). Встроенная БД получает случайный пароль при инициализации | — | `docker compose config` без опубликованного порта БД; `git grep 'paperclip:paperclip@'` вне тестов = 0; тест инициализации встроенной БД |
| Э1-5 | БР-1 | Запуск ОС-команд: явный `shell:false`, команды — константы или allowlist, проверка аргументов. Отладочные Python-скрипты раннера — не включать в поставку. Go-шим — allowlist команд | Horusec: 63 БР + 85 новых; Semgrep: 7 БР (Python 6, Go 1) | Повторный Horusec/Semgrep; юнит-тесты отказа на недопустимые аргументы |
| Э1-6 | БР-2 | Заменить `Math.random` на `crypto` во всех местах, которые показывает сканер. Общий модуль `secure-random` | Horusec: 35 БР (1 устранена) + 40 новых | Horusec «Weak Random» = 0 |
| Э1-7 | БР-3 | MD5/SHA1 → SHA-256. Для `Sec-WebSocket-Accept` и UUIDv5 — заявка на исключение по протоколу | Horusec: 5 БР + 10 новых | Horusec MD5/SHA1 = 0 или только исключения |
| Э1-8 | БР-4 | Проверка цели редиректа: только относительный путь или зарегистрированный `redirect_uri`. Ограничить динамическую регистрацию OAuth-клиентов (`public-mcp`, `muse`) allowlist-ом `redirect_uri` | Horusec: 18 БР + 4 новых; Semgrep: 10 БР | Тесты на `//evil.com`, `https://evil.com`, `/\evil.com`, `%2F%2Fevil.com`, `javascript:` |
| Э1-9 | БР-5 (прочие правила отчёта) | Экранирование вывода, `dotfiles: "deny"`, экранирование RegExp, проверка `origin` в обработчиках `message`, `Object.create(null)`, параметризованный SQL, без стека в ответе, проверка пути файла | Horusec: 6 БР + 112 новых (в основном «Origins should be verified» на `addEventListener`); Semgrep: 4 БР + 1 новое (`tainted-sql-string`) | Повторный прогон; тесты на каждое исправление |
| Э1-10 | БР-5 (Dependency-Track) | Обновить `hyper` (Rust, `Cargo.lock` раннера) и `@grpc/grpc-js` (`server/package.json`, lockfile плагина Daytona) до актуальных версий. Загрузить SBOM этапа 1 в Dependency-Track и вместе с БР зафиксировать там анализ совпадения CVE по CPE | 3 | Повторный анализ SBOM в Dependency-Track |
| Э1-11 | Новые типы срабатываний Horusec 2.8.0 и Semgrep | Разобрать вместе с БР до передачи. Подтверждённое исправить, остальное — с обоснованием в DefectDojo. Основная масса: «Alert statements should not be used» (270) — срабатывания на слово `prompt(` в серверном коде. Есть также «No use eval» (Critical, 1) — регулярное выражение для поиска `eval` в тексте навыков. Semgrep: `node_secret`/`node_api_key`/`node_password` (178), `useless-ternary` (30), `detect-insecure-websocket` (17), `eval_nodejs` (12), `gcm-no-tag-length` (10, совпадает с Opus-16), Dockerfile `missing-user` (3, совпадает с БПО-5) и др. | Horusec 277; Semgrep 274 | Решение по каждой строке согласовано с БР |

**Пакет на повторную проверку ИБ:**

1. Коммит ветки `pilot/hardening` и его хеш.
2. Повторные отчёты Semgrep и Horusec той же конфигурации, SBOM коммита. Хеши отчётов указаны в `SHA256SUMS`.
3. Реестр этапа 1. В каждой строке один из статусов:
   - `Исправлено` — с коммитом и тестом;
   - `Ложноположительная` — с обоснованием, согласованным с БР;
   - `Исключение по протоколу` — со ссылкой на заявку.

   Открытых Critical и High быть не должно.
4. Результаты проверок из колонки «Проверка для ИБ», `pnpm verify` и зелёный CI на этом коммите.

**Не входит в этап 1 (переходит в этап 2):**

- БПО-2 — смена ключей при развёртывании;
- БПО-3 — минимальные подключения агента; кодовая часть — Opus-1;
- контур egress из БПО-1 п. 3–4;
- hardening prod-образа из БПО-5;
- роли и TLS PostgreSQL из БПО-6;
- места `Math.random` и MD5/SHA1 из перечней БР-2 и БР-3, которые сканеры не показывают;
- все замечания Opus, кроме Opus-4 и пароля по умолчанию из Opus-3.

### Этап 2. Остальные замечания и допуск к пилоту

**Состав.** Всё, что не закрыто на этапе 1:

- БПО-2, БПО-3; остаток БПО-1 (контур egress), БПО-5 (prod-образ, `runAsNonRoot`), БПО-6 (роли, TLS, аудит);
- остаток БР-2 и БР-3 — полная замена по перечням и запрет линтером;
- Opus-1 … Opus-19, в первую очередь подтверждённые динамически Opus-1 (Critical), Opus-2 и Opus-6 (Critical-зависимости `proxy-addr`, `shell-quote`);
- результаты собственного Semgrep (раздел 5), `pnpm audit` и Trivy;
- финальный DAST/пентест.

**Порядок.** По разделу 8: Gate A → Gate B → Gate C → Gate D. Строки B5 и A1–A2, относящиеся к находкам сканеров БР, к началу этапа 2 уже закрыты этапом 1.

**Результат.** Протокол допуска к пилоту (раздел 8.3).

---

## 1. Проведённые проверки и их результаты

| Проверка | Инструмент | Область | Результат |
|---|---|---|---|
| Ручной разбор кода | — | `server/`, `packages/adapter-utils`, `packages/adapters`, `packages/shared`, `cli/`, Docker | Находки БПО, БР, Opus ниже |
| SCA (зависимости) | `pnpm audit` (повторный запуск; первый упал по таймауту сети) | весь workspace | prod: **1 Critical, 43 High**, 52 Moderate, 16 Low из 1390 пакетов; все: 2 Critical, 48 High |
| SCA + секреты + мисконфигурации | Trivy 0.66.0 (`fs --scanners vuln,secret,misconfig`) | весь репозиторий | **2 Critical** (`proxy-addr`, `shell-quote`), 50 High, 62 Medium; 3 «секрета» — тестовые фикстуры; мисконфигурации: DS002 (root) ×4 Dockerfile, нет HEALTHCHECK ×16, замечания к AWS-шаблонам |
| Поиск секретов | gitleaks 8.28.0 | рабочее дерево | 309 срабатываний, реальных секретов не найдено: тестовые ключи, хеши в `doc/`, примеры заголовков |
| SAST | Semgrep 1.140.0 (`p/javascript`, `p/typescript`, `p/nodejsscan`, `p/expressjs`, `p/react`) | prod-код без тестов, ~1,35 млн строк | 416 находок (166 ERROR, 250 WARNING), см. раздел 5 |
| Предварительный DAST | curl-скрипты, перехватчик на 127.0.0.1 | сервер в режиме `authenticated` на 127.0.0.1 | см. раздел 4 |

---

## 2. Замечания команды безопасности ПО (БПО)

### БПО-1. Телеметрия на внешние адреса

**Текущее состояние.**

- Адреса жёстко заданы в [packages/shared/src/telemetry/client.ts:14](../packages/shared/src/telemetry/client.ts:14): `https://telemetry.paperclip.ing/ingest` и `https://rusqrrg391.execute-api.us-east-1.amazonaws.com/ingest`.
- Причины, по которым штатное отключение работает не во всех режимах ([packages/shared/src/telemetry/config.ts:66](../packages/shared/src/telemetry/config.ts:66)):
  - `PAPERCLIP_TELEMETRY_DISABLED` и `DO_NOT_TRACK` срабатывают только при значении ровно `"1"`;
  - `CI` — только при `"true"` или `"1"`;
  - на сервере телеметрия включена по умолчанию ([server/src/config.ts:445](../server/src/config.ts:445));
  - CLI игнорирует `telemetry.enabled: false`, если не прочитал конфиг ([cli/src/telemetry.ts:27](../cli/src/telemetry.ts:27));
  - выгрузка feedback-трейсов не зависит от флагов (Opus-4).
- **Динамическая проверка:** сервер запущен с `DO_NOT_TRACK=true`, эндпоинт подменён на локальный перехватчик. Через минуту после старта пришло событие `server.started` с `installId` и версией. Значит, отключение не сработало.

**Устранение.**

1. Патч (ветка `pilot/hardening`): удалить `DEFAULT_ENDPOINTS` и `DEFAULT_FEEDBACK_EXPORT_BACKEND_URL`; телеметрия только opt-in (`PAPERCLIP_TELEMETRY_ENABLED=1`); флаги отключения принимают `1/true/yes`; дефолт `telemetryEnabled=false`.
2. Тесты: при пустом окружении `fetch` не вызывается; CI-проверка, что строк `telemetry.paperclip.ing` и `execute-api.us-east-1` нет в prod-коде.
3. Контур: egress deny-by-default, DNS-sinkhole для `telemetry.paperclip.ing`, `*.execute-api.*.amazonaws.com`, `*.posthog.com`, `*.sentry.io`.
4. Приёмка: повторить динамическую проверку с перехватчиком (0 запросов) и 24 часа захвата трафика на egress.

### БПО-2. Смена ключей при развёртывании

**Текущее состояние.**

| Секрет | Назначение | Где задаётся |
|---|---|---|
| `BETTER_AUTH_SECRET` | сессии; запасной ключ для JWT агентов, runtime-токенов, login-handoff, sandbox-proof | env |
| `PAPERCLIP_AGENT_JWT_SECRET` | JWT агентов ([server/src/agent-auth-jwt.ts:41](../server/src/agent-auth-jwt.ts:41)) | env, необязателен |
| `PAPERCLIP_TOOL_ACTION_SIGNING_SECRET` | подпись approval-действий | env, в compose пустой по умолчанию |
| `PAPERCLIP_SECRETS_MASTER_KEY` / `_FILE` | шифрование хранилища секретов | env или автосоздаваемый файл |
| Пароль Postgres | БД | `paperclip` (БПО-6, Opus-3) |
| Ключи LLM, GitHub App, OAuth-клиенты | внешние сервисы | env / хранилище секретов |

**Устранение.**

1. Отдельные значения (`openssl rand -hex 32`) для каждого секрета из таблицы. Это также закрывает Opus-5. Требование «не использует один и тот же криптографический ключ для разных целей» сформулировано в РБПО в разделе мобильных приложений («Требования к криптографии») и принимается для пилота как обязательное.
2. Хранение — корпоративное хранилище (Vault), доставка в контейнер через `*_FILE` или secretKeyRef (РБПО, Kubernetes 3.1–3.2).
3. Мастер-ключ хранить вне тома с данными; резервная копия — отдельно от бэкапа БД.
4. Пилотные ключи LLM: с лимитом бюджета и IP-allowlist, отозвать после пилота.
5. Патч: отказ старта в `authenticated`, если секрет короче 32 байт, равен `paperclip-dev-secret` или совпадает с другим секретом.
6. Регламент ротации и её последствий.

### БПО-3. Агент по умолчанию имеет доступ ко всем секретам

**Текущее состояние.** Формулировка «агент имеет доступ ко всем секретам» требует уточнения. API секретов требует run-bound токен агента и approval на привязку ([server/src/routes/secrets.ts](../server/src/routes/secrets.ts)); произвольное чтение всех записей хранилища через API не подтверждено. Подтверждён другой критичный путь: локальный процесс агента наследует секреты серверного процесса через окружение (Opus-1), работает под тем же UID и может читать каталог инстанса с мастер-ключом, а `DATABASE_URL` ведёт к БД с правами суперпользователя (Opus-2, Opus-3). Этого достаточно для компрометации секретов без обхода API.

**Устранение.**

1. Закрыть Opus-1, Opus-2, Opus-3.
2. В хранилище пилота — только тестовые секреты; каждому агенту минимальный набор; новые привязки — через approval.
3. Коннекторы — только необходимые, с тестовыми аккаунтами и минимальными скоупами; GitHub — fine-grained токен или App только на тестовый репозиторий.
4. Журнал операций с секретами (`secret_access_events`, activity log) — в SIEM (РБПО 4; Kubernetes 5.2).

### БПО-4. Windows: команды через shell в runner-скриптах

**Текущее состояние.** `shell: process.platform === "win32"`: [scripts/dev-runner.ts:383](../scripts/dev-runner.ts:383), `:723`, `scripts/dev-runner.mjs:261,374,474`, `scripts/ci-typecheck-lane.mjs:87`, `scripts/typecheck-test-programs.mjs:92,122`, `scripts/typecheck-low-memory.mjs:23`, `scripts/e2e-mcp-user-stories.mjs:21`, `packages/paperclip-runner/scripts/build-runner-binary.mjs:41`.

**Устранение (РБПО 3, инъекции команд ОС).**

1. Убрать `shell: true` во всех местах: запускать `pnpm.cmd`/`node.exe` напрямую через `cross-spawn` (корректно экранирует аргументы на Windows) с `shell:false`.
2. ESLint-правило: запрет `shell: true` и `exec`/`execSync` со строкой во всём репозитории (кроме явно согласованного allowlist).
3. До исправления — не использовать Windows-хосты в пилоте и не передавать в скрипты непроверенные аргументы.

### БПО-5. Docker-образы от root

**Текущее состояние.** Trivy DS002 «Image user should not be root»: [docker/openclaw-smoke/Dockerfile](../docker/openclaw-smoke/Dockerfile), [docker/runner-image/Dockerfile.smoke](../docker/runner-image/Dockerfile.smoke), `.github/docker-context-checks.Dockerfile`, `packages/plugins/sandbox-providers/cloudflare/bridge-template/Dockerfile`. Основной [Dockerfile](../Dockerfile) не задаёт `USER`: entrypoint стартует от root только для переназначения UID/GID и прав на volume, затем запускает приложение через `gosu node` ([scripts/docker-entrypoint.sh](../scripts/docker-entrypoint.sh)). Это уменьшает риск, но не удовлетворяет политике `runAsNonRoot` и требует лишних capabilities на старте.

**Устранение.**

1. Не исправлять служебные smoke/build-образы механически, если они не попадают в runtime пилота; явно исключить их из перечня разрешённых образов. Для каждого runtime-образа задать `USER` (непривилегированный UID).
2. Основной образ в пилоте запускать с `runAsNonRoot: true`, фиксированными `runAsUser/runAsGroup`; права на volume готовить непривилегированным init-контейнером/CSI. После проверки удалить из пилотного образа root-ветку entrypoint и ненужные `gosu/usermod`.
3. Запуск: `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, без `privileged` и host mounts, `readOnlyRootFilesystem: true` + отдельные writable mounts, seccomp/AppArmor (РБПО 14; Kubernetes 8.1–8.13).
4. Smoke-образы как образец для prod не использовать.
5. CI: hadolint или Trivy misconfig как блокирующая проверка (РБПО, Kubernetes 9.17–9.18).

### БПО-6. Postgres в compose, пароль `paperclip`

**Текущее состояние.** [docker/docker-compose.yml](../docker/docker-compose.yml): `ports: "5432:5432"`, `POSTGRES_PASSWORD: paperclip`; то же в [.env.example](../.env.example) и [docs/deploy/database.md](../docs/deploy/database.md). РБПО 1 запрещает пароли по умолчанию.

**Устранение.**

1. Убрать публикацию порта БД; доступ только из сети приложения.
2. Пароль — через `POSTGRES_PASSWORD_FILE` и секрет; убрать `paperclip:paperclip` из примеров, заменив на плейсхолдер.
3. Отдельные роли: владелец схемы (миграции) и прикладной пользователь без DDL и без superuser.
4. Требования РБПО к PostgreSQL: явный `listen_addresses`, TLS, ролевая модель, аудит входов и DDL (`pgaudit`).
5. В пилоте не использовать встроенную БД (Opus-3).

---

## 3. Замечания команды безопасной разработки (БР)

### БР-1. RCE: небезопасный вызов системных команд

**Текущее состояние.**

- Агенты запускаются через `spawn(..., { shell:false })` с массивом аргументов ([packages/adapter-utils/src/server-utils.ts:4880](../packages/adapter-utils/src/server-utils.ts:4880)).
- Вызовы через shell есть в скриптах (БПО-4).
- Trivy нашёл **Critical CVE-2026-102422 в `shell-quote@1.10.0`**: выполнение произвольных команд через некорректную обработку перевода строки (lockfile плагина `packages/plugins/sandbox-providers/daytona`).
- Агенты по замыслу продукта исполняют команды, сгенерированные LLM, и по умолчанию работают с `dangerouslySkipPermissions: true` ([packages/adapters/claude-local/src/index.ts:73](../packages/adapters/claude-local/src/index.ts:73)). Prompt injection = выполнение кода; вместе с Opus-1 — компрометация сервера.

**Устранение (РБПО 3, инъекции команд ОС).**

1. Разобрать каждую находку класса «Command Injection» из отчёта БР по шаблону раздела 7; исправить в сроки РБПО.
2. Для обычных служебных команд — `spawn`/`execFile` с массивом аргументов и `shell:false`; строковые `exec`/`execSync` запретить вне точечного allowlist. Не требовать allowlist всех аргументов, сгенерированных LLM: исполнение произвольных агентских команд является функцией продукта, а его границей безопасности должна быть изоляция runtime. Реальные command-injection findings подтверждать отдельным taint-flow от недоверенного ввода до shell-интерпретации.
3. Обновить `shell-quote` до ≥1.11.0 (`pnpm.overrides`); Daytona-плагин в пилоте не использовать.
4. Изолировать исполнение агентов (Opus-2): отдельные контейнеры `docker/agent-runtime/*`, `filesystemScope: "workspace"`, `networkScope: "allowlist"`, без доступа к БД и сети сервера.
5. Approval-гейты на опасные действия: push, внешние коннекторы, привязка секретов.
6. Добавить Semgrep-правила на command injection в CI (Opus-15).

### БР-2. Криптографически нестойкий ГСЧ

Требование. Формулировка «все случайные числа генерируются при помощи генератора случайных чисел надлежащего качества» содержится в РБПО в разделе «Требования к безопасности мобильных приложений» → «Требования к криптографии». В общих требованиях к РБПО отдельного пункта о ГСЧ нет. Для пилота это требование принимается как обязательное и для серверного и веб-кода: так совпадают позиции с командой БР и не нужно доказывать исключения по каждому месту.

**Текущее состояние.** `Math.random` встречается в 49 файлах prod-кода. Это смешанные случаи: токены и непредсказуемые имена, идентификаторы, временные файлы, retry jitter, sampling, декоративная UI-анимация. Токены входа и board-claim уже используют `crypto.randomBytes` ([server/src/board-claim.ts:28](../server/src/board-claim.ts:28)); сессии выдаёт better-auth.

**Устранение.**

1. Заменить **все** `Math.random` в prod-коде на криптостойкий ГСЧ, независимо от назначения:
   - идентификаторы и токены → `crypto.randomUUID()` / `crypto.randomBytes()`;
   - числа в диапазоне, jitter, sampling → `crypto.randomInt()` или обёртка над `crypto.getRandomValues()`;
   - браузер → `crypto.getRandomValues()`; удалить небезопасный фолбэк в [ui/src/lib/uuid.ts:8](../ui/src/lib/uuid.ts:8).

   В реестре каждое место всё равно помечается как `security-sensitive` или `non-security`: это определяет приоритет и срок. Security-sensitive места (токены, коды, nonce, непредсказуемые имена файлов и объектов, публичные идентификаторы) исправляются первыми, в сроки High. Остальные — в той же ветке, без отдельного согласования исключений. Там, где тестам нужна детерминированность, источник случайности передаётся параметром (по умолчанию — криптостойкий), как уже сделано в `TelemetryClient`.

   Перечень мест:

   | Область | Файлы (строки) |
   |---|---|
   | server | `server/src/telemetry.ts:83`, `server/src/storage/local-disk-provider.ts:51`, `server/src/storage/s3-multipart.ts:200,286`, `server/src/services/heartbeat/retries.ts:299,436,461`, `server/src/services/heartbeat/agent-directory-busy.ts:40`, `server/src/services/accounting-transaction.ts:62`, `server/src/services/browser-use.ts:1521`, `server/src/services/chat-channels/github/retry.ts:9`, `server/src/services/company-import-transfers.ts:77`, `server/src/services/plugin-worker-manager.ts:3340`, `server/src/services/recovery/assigned-work-sweep.ts:745`, `server/src/services/reusable-sandbox-resume-replacement.ts:55`, `server/src/realtime/runner-prp-outbound.ts:338` |
   | packages | `packages/shared/src/telemetry/client.ts:144,146`, `packages/db/src/backup-lib.ts:202`, `packages/paperclip-runner/src/live/runnerd-codex-transport.ts:9325`, адаптеры `claude-local` (`acp.ts:779,1011`, `test.ts:96`), `codex-local` (`acp.ts:695`, `test.ts:309`), `cursor-local/test.ts:99`, `gemini-local/test.ts:87`, `grok-local/test.ts:124`, `kimi-local/test.ts:136`, `opencode-local` (`models.ts:176`, `test.ts:82`), `pi-local` (`models.ts:114`, `test.ts:95`), плагины `cloudflare/bridge-template/src/exec.ts:26`, `modal/src/plugin.ts:614` |
   | cli | `cli/src/install-store.ts:60,153,281`, `cli/src/commands/service.ts:65` |
   | ui | `ui/src/lib/uuid.ts:8`, `lib/cross-tab-poll.ts:57,103,498`, `lib/polling.ts:104,132`, `lib/optimistic-issue-comments.ts:39`, `lib/browser-tracing/controller.ts:75`, `hooks/useDocumentAnnotationMutations.ts:121`, `components/IssueChatThread.tsx:5256`, `components/task-chat/TaskChatComposer.tsx:777`, `components/task-chat/RunnerGoalWidget.tsx:31`, `context/ToastContext.tsx:85`, `plugins/launchers.tsx:710`, `pages/tools/profiles/WizardToolsStep.tsx:313`, `components/NewProjectDialog.tsx:30`, а также декоративные анимации (`AsciiArtAnimation.tsx`, `SleepingZs.tsx`, `PrimaryAgentPresentation.tsx`) |

2. Общий модуль `secure-random` в `packages/shared` (`randomId()`, `randomInt()`, `jitter()`, `sample()`) и ESLint `no-restricted-properties` на `Math.random` во всём prod-коде. Исключения — только тестовые файлы.
3. Сессии (РБПО 2): проверить настройку better-auth и закрыть Opus-9 — смена идентификатора при входе, тайм-аут неактивности, лимит одновременных сессий.
4. Тесты: для security-sensitive мест — проверка, что значения берутся из `crypto`; в CI — поиск `Math.random` по prod-коду = 0.

### БР-3. Устаревшие алгоритмы хеширования MD5/SHA1

Требование. В общих требованиях РБПО (раздел 1) — хеширование паролей надёжными алгоритмами с уникальной солью. Запрет «общепризнанно устаревших криптографических протоколов и алгоритмов» сформулирован в разделе «Требования к безопасности мобильных приложений» → «Требования к криптографии». Для пилота он принимается как обязательный и для серверного кода.

**Текущее состояние.** Ниже — полный перечень MD5/SHA1 в prod-коде и скриптах. В реестре каждое место классифицируется по назначению: защитное применение, некриптографический отпечаток или алгоритм, обязательный по внешнему протоколу. Классификация определяет приоритет, но не освобождает от замены: заменяется всё, кроме алгоритмов, зашитых в протокол или стандарт.

| Место | Алгоритм | Назначение | Устранение |
|---|---|---|---|
| [server/src/routes/plugin-ui-static.ts:176](../server/src/routes/plugin-ui-static.ts:176) | MD5 | ETag | SHA-256 |
| [server/src/services/routines.ts:543](../server/src/services/routines.ts:543) | SHA1 | детерминированный id (UUIDv5) | SHA1 задан стандартом UUIDv5 (RFC 9562 §5.5); значение — идентификатор, не секрет. Перейти на стандартную библиотеку `uuid` (`v5`) вместо ручной реализации и включить в заявку на исключение в службу ИБ. Собственную схему UUIDv8 не изобретать: при смене алгоритма поменяются уже сохранённые id |
| [server/src/services/run-secret-redaction.ts:30](../server/src/services/run-secret-redaction.ts:30) | SQL `md5()` | отпечаток реестра редактирования секретов | `encode(sha256(...::bytea),'hex')` |
| `server/src/services/attention.ts:1769,1839,1976` | SQL `md5()` | отпечаток изменения контента | `sha256()` |
| `packages/plugins/plugin-llm-wiki/src/wiki/core.ts:495` | MD5 | стабильный id | SHA-256 |
| `packages/paperclip-runner/scripts/contracts/contract-fingerprints.mjs:143` | SHA1 | ключ кэша | SHA-256 |
| `packages/paperclip-runner/src/cli/codex-app-server-unix-proxy.ts:39`, `packages/paperclip-runner/src/control-plane/durable-prp-control-plane.ts:3214` | SHA1 | `Sec-WebSocket-Accept` | перейти на библиотеку `ws` (рукописный handshake убрать); по алгоритму, зашитому в протокол RFC 6455, оформить согласованное со службой ИБ исключение |
| `server/src/storage/s3-provider.ts`, `server/src/storage/s3-multipart.ts` | MD5 | заголовок `Content-MD5` протокола S3, контроль целостности передачи | Не заменять произвольно на SHA-256; проверить поддержку checksum SHA-256 конкретным S3 и оформить протокольное исключение, если `Content-MD5` обязателен |
| `scripts/benchmark-*.ts` (8 файлов) | SQL `md5()` | генерация тестовых данных | `sha256()` или `gen_random_uuid()` для единообразия |

Пароли хеширует better-auth (scrypt с солью) — требование РБПО 1 о соли и надёжном алгоритме выполняется; зафиксировать это в документации.

**Устранение.**

1. Заменить на SHA-256 все MD5/SHA1 из таблицы, кроме протокольных. Первыми — места, где значение участвует в решении безопасности (`run-secret-redaction.ts`). Для отпечатков, сохранённых в БД (`attention.ts`, `run-secret-redaction.ts`), — миграция с пересчётом или сравнение по новому полю, чтобы не вызвать ложных «изменений».
2. ESLint/Semgrep-правило: запрет `createHash('md5'|'sha1')` и SQL `md5(` в prod-коде; allowlist только для протокольных мест из п. 3, с владельцем и ссылкой на исключение.
3. Одна заявка в службу ИБ на исключение для алгоритмов, обязательных по внешнему протоколу или стандарту: SHA1 в `Sec-WebSocket-Accept` (RFC 6455), SHA1 в UUIDv5 (RFC 9562), MD5 в `Content-MD5` S3 (если используемое S3-хранилище не поддерживает `x-amz-checksum-sha256`; если поддерживает — перейти на SHA-256), SHA1 в идентификаторах Git. В заявке — доказательство, что алгоритм не является границей доверия.

### БР-4. Open Redirect

**Текущее состояние.** Динамически: better-auth отклоняет внешний `callbackURL` (`INVALID_CALLBACK_URL`). Возможные векторы, требующие централизованной защиты: `res.redirect` в [server/src/app.ts:710-718](../server/src/app.ts:710) (GitHub-callback), [server/src/routes/tool-access.ts](../server/src/routes/tool-access.ts) (OAuth-recovery), [server/src/routes/chat-channels.ts](../server/src/routes/chat-channels.ts) (Slack return path), [server/src/routes/public-mcp.ts:78](../server/src/routes/public-mcp.ts:78), [server/src/routes/muse.ts:57](../server/src/routes/muse.ts:57), [server/src/routes/slack-tools.ts:59](../server/src/routes/slack-tools.ts:59), [server/src/routes/smoke-lab.ts:84](../server/src/routes/smoke-lab.ts:84); в UI — `window.location.assign(redirectUrl)` в [ui/src/pages/McpConnect.tsx:91,95](../ui/src/pages/McpConnect.tsx:91).

**Устранение.**

1. Проверять redirect на границе, где формируется URL: внутренние return path — только нормализованный относительный путь; OAuth/MCP callback — только заранее зарегистрированный `redirect_uri` клиента. Общий helper допустим для внутренних путей, но blanket-запрет `res.redirect` не должен ломать протокольные OAuth-редиректы на зарегистрированные внешние origin.
2. UI: перед `location.assign` проверять, что URL того же origin или из allowlist.
3. Тесты на `//evil.com`, `https://evil.com`, `/\evil.com`, `%2F%2Fevil.com`, `javascript:`.
4. Smoke-lab в пилоте не включать.

### БР-5. Реестр находок БР

1. Реестр заведён: [br-findings-registry.csv](br-findings-registry.csv) — 159 строк, по каждой: инструмент, уровень, CWE, правило, место в отчёте и в текущей ревизии, пункт плана, оценка эксплуатируемости, действие, статус. Все находки — в статусе «Принята к исправлению».
2. Critical — исправить за 3 дня, High — за 10 дней (РБПО); Medium — за месяц.
3. Исправления делаются по группам (раздел 3.6), для каждой группы — тест.
4. Повторное сканирование ветки `pilot/hardening` той же конфигурацией DefectDojo (Semgrep, Horusec, Dependency-Track), отчёт о дельте.

### БР-6 (High). Windows: открытие URL через `cmd`

**Текущее состояние.** [cli/src/client/board-auth.ts:195](../cli/src/client/board-auth.ts:195) на Windows открывает ссылку командой `cmd /c start "" <url>`. `cmd` интерпретирует `&`, `|`, `^` в строке: URL с такими символами выполнит произвольную команду на машине пользователя CLI. Найдено по находке Horusec «Using Shell Interpreter» (раздел 3.6).

**Устранение.** Открывать URL без интерпретатора команд (`rundll32 url.dll,FileProtocolHandler <url>` или `explorer.exe <url>`), предварительно проверять, что схема `https:` (или `http:` для loopback), и отклонять URL с управляющими символами. Тест с URL, содержащим `&calc`. До исправления — не использовать CLI на Windows в пилоте.

### 3.6. Сводка реестра находок БР

Исходные данные: выгрузка DefectDojo от 3–5 ноября 2026; сопоставление с ревизией `3dffb2c9d`. 154 находки на месте (94 — на той же строке, 60 — со сдвигом строки), 2 уже устранены в текущей ревизии (Math.random удалён из `environment-runtime.ts`, файл `codex-runtime-adapter.ts` удалён), 3 — зависимости. Часть мест отмечена обоими SAST-инструментами одновременно (особенно Open Redirect), поэтому число уникальных мест меньше числа находок.

| Группа | Находок | Уровень | Инструмент | Пункт плана | Оценка и действие |
|---|---|---|---|---|---|
| Запуск ОС-команд | 65 | High | Horusec 64, Semgrep 1 | БР-1 | Почти все — `execFile`/`spawn` с массивом аргументов без shell. Действие: явный `shell:false`, команды — константы или allowlist, запрет строковых `exec` линтером. Особые места: `board-auth.ts` (подтверждено → БР-6); `workspace-runtime.ts` выполняет команды workspace через `/bin/sh -c` по замыслу, агентам изменение команд запрещено (`assertNoAgentHostWorkspaceCommandMutation`), в пилоте — только администратор; `tool-gateway.ts` — команда stdio-шаблона MCP от администратора; `tools/agent-shim/main.go` — exec бинаря адаптера, ввести allowlist |
| Нестойкий ГСЧ | 35 | High | Horusec | БР-2 | Все места входят в перечень БР-2, кроме одного уже устранённого. Полная замена на `crypto` |
| Open Redirect | 28 | High | Semgrep 10, Horusec 18 | БР-4 | OAuth `authorize` (`public-mcp`, `muse`) сверяет `redirect_uri` с зарегистрированным клиентом, но динамическая регистрация клиентов принимает любой `redirect_uri` — в пилоте ограничить allowlist-ом или отключить. Остальные — внутренние return path: нормализация и тесты |
| Запуск через shell (Windows) | 7 | High | Semgrep | БПО-4 | Подтверждено: `shell: true` на Windows в dev/CI-скриптах. Перейти на `cross-spawn` |
| Python subprocess | 6 | High | Semgrep | БР-1 | `packages/paperclip-runner/scripts/probe-copilot-acp.py` — скрипт отладки, аргументы списком без shell. Валидация аргументов, исключить из поставки |
| Устаревшие хеши | 5 | High | Horusec | БР-3 | SHA1 в WebSocket-handshake (2) и UUIDv5 (1) — исключение по протоколу; MD5 в ETag и id wiki (2) — замена на SHA-256 |
| Вывод данных из запроса | 2 | High | Horusec | Opus-18 | `tool-access.ts` (interstitial OAuth) экранирует `&`, `"`, `<` — дополнительно экранировать `>` и `'`; `app.ts` — HTML Vite только в dev-режиме, в prod не включать |
| Выдача скрытых файлов | 1 | High | Horusec | Opus-18 | `plugin-ui-static.ts`: `sendFile(..., { dotfiles: "allow" })` — перейти на `deny`; выход из каталога уже закрыт `realpath` |
| Инъекция в RegExp | 1 | High | Semgrep | Opus-19 | `kubernetes/src/image-allowlist.ts` строит RegExp из allowlist — экранировать спецсимволы |
| Междоменные сообщения | 1 | High | Horusec | Opus-18 | `vite-issue-detail-preload.ts` слушает собственное DOM-событие, а не `message`; подтвердить и пометить |
| Инъекция свойств | 1 | High | Semgrep | Opus-10 | `email.ts`: ключи заголовков — фиксированный список `svix-*`; использовать `Object.create(null)` |
| SQL-инъекция | 1 | High | Semgrep | Opus-10 | `environments.ts`: строка — текст ошибки, в SQL не попадает; подтвердить тестом |
| Инъекция в рендер HTML (wkhtmltoimage) | 1 | High | Semgrep | Opus-10 | `summary-slots.ts`: wkhtmltoimage в проекте не используется; подтвердить отсутствие зависимости |
| Раскрытие ошибок | 1 | Medium | Horusec | Opus-10 | Демо-сервер сценариев раннера; не отдавать стек, исключить из поставки |
| Чтение файла по пути из запроса | 1 | Medium | Horusec | Opus-10 | `agents.ts`: путь проверяется `assertInstructionPathSafe`; добавить тесты на обход |
| Сторонние компоненты | 3 | Critical 1, Medium 2 | Dependency-Track | Opus-6 | `hyper 1.11.1` (Rust) — CVE-2024-23741 относится к терминалу Hyper для macOS, совпадение по CPE подтвердить с БР; `@grpc/grpc-js` 1.14.4/1.14.5 — CVE-2023-32732 описана для gRPC core, но Trivy показывает по пакету другую High CVE-2026-101916 — обновить в любом случае |

**Чего нет в отчёте БР, но есть в плане.** Утечка секретов сервера в окружение агента (Opus-1), отсутствие изоляции агентов (Opus-2), пароль и superuser встроенной БД (Opus-3), телеметрия (БПО-1, Opus-4), AES-GCM без длины тега (Opus-16), ReDoS (Opus-19), а также Critical-зависимости из `pnpm audit` и Trivy (`proxy-addr`, `shell-quote`). Dependency-Track нашёл 3 уязвимых компонента против 44 Critical/High у `pnpm audit` — стоит сверить с БР, какой SBOM загружался в Dependency-Track.
---

## 4. Предварительное динамическое тестирование

**Условия.** Сервер запущен из исходников (`server/src/index.ts`) в режиме `authenticated/private` на `127.0.0.1:3197`, встроенная БД, UI не раздавался. Телеметрия направлена на локальный перехватчик, наружу ничего не уходило. Длительность — около 1,5 часа, включая установку зависимостей и запуск.

> По РБПО 12 динамический анализ должны проводить специалисты заказчика или привлечённая организация. Этот прогон — предварительный, для подготовки исправлений; финальный пентест проводит служба ИБ или подрядчик (Gate C, раздел 8.3).

| # | Проверка | Результат | Замечание |
|---|---|---|---|
| D-1 | Телеметрия при `DO_NOT_TRACK=true` | Событие `server.started` (installId, версия) отправлено | БПО-1 |
| D-2 | Окружение процесса агента (`runChildProcess` → `/usr/bin/env`) | Видны `BETTER_AUTH_SECRET`, `DATABASE_URL`, `ANTHROPIC_API_KEY`, `AWS_SECRET_ACCESS_KEY`; скрыты только `PAPERCLIP_*` | Opus-1 |
| D-3 | Вход во встроенный Postgres `paperclip/paperclip` | Успешно, роль **superuser**, доступны таблицы секретов | Opus-3 |
| D-4 | 759 маршрутов, GET без авторизации | 191×401, 138×403, ~120×404; данные не отдаются. Открыты `/api/openapi.json` и `/api/health` | Opus-11 |
| D-5 | Невалидный id в пути без авторизации | 500 и запрос в БД до проверки прав (`/api/approvals`, `/goals`, `/projects`, `/execution-workspaces`); «Agent not found» до 401 | Opus-10 |
| D-6 | Регистрация | Открыта; пароли `12345678`, `password` приняты | Opus-7 |
| D-7 | Перебор паролей | После 2 неверных попыток — 429 (rate limit есть) | Соответствует; лимиты сделать настраиваемыми |
| D-8 | Cookie сессии | `HttpOnly; SameSite=Lax; Max-Age=604800`; без `Secure` (HTTP) | Opus-9 |
| D-9 | Заголовки | Нет HSTS, X-Frame-Options/frame-ancestors, CSP на API; есть `X-Powered-By: Express` | Opus-8 |
| D-10 | HTTP-методы | TRACE → 404, CONNECT отклонён; OPTIONS → 200 | Ограничить методы по РБПО 6 |
| D-11 | Ошибка разбора JSON | `{"error":"Invalid JSON body"}`, без стека | Соответствует РБПО 4 |
| D-12 | Open Redirect через `callbackURL` | Отклонено (`INVALID_CALLBACK_URL`) | БР-4 (централизовать) |

**Не покрыто** (войдёт в финальный пентест): UI (XSS, clickjacking), авторизация между компаниями с двумя аккаунтами (IDOR), загрузка файлов, WebSocket/realtime, OAuth-коннекторы, фаззинг API, побег агента из песочницы в контейнере.

---

## 5. Результаты Semgrep

**Параметры.** Semgrep 1.140.0, наборы `p/javascript`, `p/typescript`, `p/nodejsscan`, `p/expressjs`, `p/react`. Область: `server/src`, `cli/src`, `ui/src`, `packages/adapter-utils/src`, `packages/adapters`, `packages/shared/src`, `packages/db/src` (около 1,35 млн строк, без тестов и сторибуков). Просканировано 5105 файлов; 553 пропущены по тайм-ауту или ошибке разбора — в CI повторить без лимитов. Первый запуск с дополнительными наборами (`p/secrets`, `p/dockerfile`) остановлен через 70 минут: их покрыли gitleaks и Trivy.

**Итог: 416 находок.** Все принимаются к разбору по шаблону раздела 7.

| Правило | Кол-во | Где | Оценка и действие |
|---|---|---|---|
| `regex_dos` (ReDoS) | 173 | server 118, ui 27, adapters 13, shared 8, adapter-utils 4, db 3 | Принять: регулярные выражения на пользовательских данных и выводе LLM переписать или ограничить длину входа; для сложных — `re2` → Opus-19 |
| `node_secret` / `node_password` / `node_api_key` (жёстко заданные секреты) | 89 | server 59, cli 14, ui 7 и др. | Разобрать по одному; по выборке это имена переменных и константы-метки, но каждая строка подлежит проверке; реальные значения — вынести в хранилище секретов (РБПО 1) |
| `node_insecure_random_generator` | 52 | все области | → БР-2 |
| `node_timing_attack` | 39 | ui 25, server 12, cli 2 | Сравнение секретов через `===`; подтверждено в [server/src/board-claim.ts:38-39](../server/src/board-claim.ts:38) (токен и код board-claim) → Opus-17 |
| `node_username` | 27 | db, adapter-utils | Тестовые учётки встроенной БД → Opus-3 |
| `express_open_redirect` | 7 | `chat-channels.ts:267,310`, `muse.ts:54,57`, `public-mcp.ts:78`, `slack-tools.ts:50`, `smoke-lab.ts:74` | → БР-4 |
| `gcm-no-tag-length` | 7 (+2 вне правила) | 6 из 7 мест подтверждены (`tool-content-guards.ts` проверяет длину вручную); ручной поиск нашёл ещё 2: `native-runtime/native-provider-artifacts.ts:652`, `native-runtime/native-harness-backup-storage.ts:401` | Итого 8 мест → Opus-16 |
| `eval_nodejs` | 7 | `db/client.ts`, `run-intake-stall-watch.ts` и др. | Срабатывание на `setTimeout(() => …)` со стрелочной функцией; исправление не требуется, пометить в отчёте с обоснованием |
| `node_logic_bypass` | 4 | `costs.ts:196`, `routines.ts:407` и др. | Проверка прав по полю из тела запроса; покрыть тестами авторизации |
| `express_xss` / `direct-response-write` | 4 | `announcements.ts:28-37`, `plugin-ui-static.ts:383` | `Content-Type` берётся из внешнего фида анонсов — SVG/HTML даст stored XSS; ввести allowlist типов изображений → Opus-18 |
| `tainted-sql-string` | 2 | `environments.ts:898,1404` | Срабатывание на текст ошибки, не на SQL; пометить с обоснованием |
| `express_cors` | 1 | `plugin-ui-static.ts:490` — `Access-Control-Allow-Origin: *` | → Opus-18 |
| `express-res-sendfile` | 1 | `plugin-ui-static.ts:496` | Проверить нормализацию пути (path traversal) → Opus-18 |
| `wildcard-postmessage-configuration` | 1 | `ui/src/components/mcp-app/McpAppFrame.tsx:113` — `postMessage(msg, "*")` | → Opus-18 |
| `node_md5` | 1 | `plugin-ui-static.ts:175` | → БР-3 |
| `generic_error_disclosure` | 1 | `packages/db/src/test-postgres-owner.ts:48` | Тестовый хелпер; исключить из prod-сборки |

Распределение по уровням (166 ERROR / 250 WARNING) близко по структуре к отчёту БР: большинство High там, вероятно, — ReDoS, «жёстко заданные секреты», ГСЧ и сравнения по времени. Сопоставить при получении отчёта.

---

## 6. Замечания Opus

### Opus-1 (Critical). Секреты сервера в окружении агентов

**Суть.** `sanitizeInheritedPaperclipEnv` ([packages/adapter-utils/src/server-utils.ts:3617](../packages/adapter-utils/src/server-utils.ts:3617)) удаляет только `PAPERCLIP_*`. Адаптеры дополнительно собирают `{ ...process.env, ...env }` (`claude-local/execute.ts:324,507,783`, `codex-local/execute.ts:742,1108` и др.). Подтверждено динамически (D-2). `BETTER_AUTH_SECRET` используется как fallback для agent JWT и других подписей, поэтому его чтение позволяет подделывать соответствующие служебные токены; возможность подделать пользовательскую DB-backed сессию отдельно не доказана. Через `DATABASE_URL` агент может читать и изменять данные всех компаний в пределах прав роли БД.

**Устранение.**

1. Allowlist наследуемых переменных (`PATH`, отдельные agent `HOME`/`TMPDIR`, `LANG`, `LC_*`, `TZ`, утверждённые proxy/CA settings) вместо denylist; остальное агент получает только из привязанных секретов. Применять фильтр централизованно **после окончательного объединения** base env, `process.env`, adapter config и run secrets, иначе адаптер может повторно добавить удалённые значения.
2. Жёсткий запрет передачи `BETTER_AUTH_SECRET`, `DATABASE_URL`, `*_MASTER_KEY*`, `AWS_SECRET_ACCESS_KEY`, `*_SECRET`.
3. Убрать фолбэк JWT и runtime-токенов на `BETTER_AUTH_SECRET` (Opus-5).
4. Регрессионные тесты — повтор D-2 и canary-тест каждого поддерживаемого execute/test/model/probe spawn-пути Claude, Codex, Gemini, Kimi, OpenCode и выбранного пилотного runtime.

### Opus-2 (High). Агенты не изолированы от сервера

**Суть.**

- Локальные адаптеры работают под тем же пользователем ОС, что и сервер, с доступом к каталогу инстанса и мастер-ключу.
- Песочница bwrap ([packages/adapter-utils/src/local-process-sandbox.ts](../packages/adapter-utils/src/local-process-sandbox.ts)) включается вручную, только на Linux и только в `claude-local` и `codex-local`.
- `dangerouslySkipPermissions` по умолчанию `true`.

**Устранение.**

1. Исполнение агентов — в отдельных контейнерах `docker/agent-runtime/*` (UID 1000) или через remote execution target; без тома `/paperclip`.
2. NetworkPolicy: агент видит только API Paperclip, LLM-прокси, тестовый Git; нет доступа к БД и к метаданным облака.
3. Патч: песочница по умолчанию; отказ запуска локального агента без песочницы в `authenticated`.
4. Allowlist инструментов вместо `skip-permissions` для ролей без shell.
5. Пентест «от имени агента» в приёмке.

### Opus-3 (High). Встроенный Postgres: пароль по умолчанию и superuser

**Суть.** [server/src/index.ts:735,741](../server/src/index.ts:735), [cli/src/commands/auth-bootstrap-ceo.ts:27](../cli/src/commands/auth-bootstrap-ceo.ts:27). Подтверждено динамически (D-3). Нарушает РБПО 1 (пароли по умолчанию) и требования к PostgreSQL (наименьшие привилегии).

**Устранение.** В пилоте — только внешний Postgres. Патч: случайный пароль при инициализации (файл `0600`), отдельная непривилегированная роль приложения.

### Opus-4 (High). Выгрузка feedback-трейсов мимо флагов телеметрии

**Суть.** [server/src/services/feedback-share-client.ts:7](../server/src/services/feedback-share-client.ts:7): по умолчанию трейсы прогонов агентов уходят на `telemetry.paperclip.ing/feedback-traces`; клиент создаётся всегда ([server/src/index.ts:952](../server/src/index.ts:952)).

**Устранение.** Удалить дефолтный URL; без `PAPERCLIP_FEEDBACK_EXPORT_BACKEND_URL` функция выключена и скрыта в UI; тест.

### Opus-5 (High). Один ключ для нескольких целей

**Суть.** `BETTER_AUTH_SECRET` — запасной ключ в `agent-auth-jwt.ts:41`, `runtime-tools-token.ts:19`, `auth/workspace-login-handoff.ts:218`, `services/sandbox-absence-proof.ts:89`. Нарушает требование РБПО «не использует один и тот же криптографический ключ для разных целей» (раздел мобильных приложений, принят для пилота как обязательный).

**Устранение.** Отдельные обязательные секреты, фолбэки удалить (БПО-2 п. 1, 5).

### Opus-6 (Critical). Уязвимые сторонние компоненты

**Суть.** `pnpm audit --prod`: 1 Critical, 43 High. Trivy: 2 Critical, 50 High. Основные:

| Пакет | Версия | Исправлено в | Уровень | Суть |
|---|---|---|---|---|
| `proxy-addr` | 2.0.7 | 2.0.8 | Critical | подмена IP через IPv4-mapped IPv6 (Express, актуально при `TRUST_PROXY`) |
| `shell-quote` | 1.10.0 | 1.11.0 | Critical | выполнение команд (lockfile Daytona-плагина) |
| `undici` | 5.29.0, 6.28.1, 7.30.0, 8.10.0 | 6.29.1 / 7.30.1 / 8.12.2 | High | обход проверки TLS-сертификата, отравление кэша, DoS |
| `fast-uri` | 3.1.2 | 3.1.9 | High | SSRF, подмена хоста |
| `follow-redirects` | 1.16.0 | 1.16.2 | High | утечка заголовков авторизации при редиректе |
| `@modelcontextprotocol/sdk` | 1.31.0 | 1.32.0 | High | привязка задач к сессии, DoS; Moderate — принятие токенов другого сервиса |
| `@azure/msal-node` | 5.6.0 | 7.1.0 | High | раскрытие параметров authorization code flow |
| `path-to-regexp` | 8.3.0 | 8.4.0 | High | ReDoS |
| `body-parser` | 2.2.2 | 2.4.0 | High | DoS |
| `multer` | 2.4.0 | 2.5.0 | High | DoS |
| `@fastify/busboy` | 2.1.1 | 3.2.1 | High | DoS |
| `js-yaml` | 4.3.1 | 4.3.2 | High | DoS |
| `sharp` | 0.35.4 | 0.35.5 | High | уязвимость в librsvg |
| `vite` | 6.4.3, 8.2.2 | 8.2.4 | High | dev-сервер (не в prod-рантайме) |
| `zod` | 3.25.76, 4.1.11, 4.4.3 | 4.6.6 | High | исчерпание памяти |
| `dompurify`, `hono`, `@hono/node-server`, `qs`, `@grpc/grpc-js` и др. | — | — | Moderate–High | см. отчёт `pnpm audit` |

**Устранение (РБПО 13).**

1. Для каждой advisory зафиксировать путь зависимости, наличие в финальном runtime-образе, достижимость уязвимого API и исправленную версию. Обновить прямые зависимости; `pnpm.overrides` использовать только после проверки совместимости и тестов.
2. Повторный `pnpm audit --prod`, Trivy fs и Trivy image по финальному digest: 0 достижимых Critical/High; остальные — только с согласованной службой ИБ оценкой влияния, компенсирующей мерой и сроком. Одного совпадения версии в lockfile недостаточно для объявления эксплуатируемости.
3. Сторонние компоненты — только из внутреннего хранилища (зеркало npm, реестр образов), с проверкой перед помещением; версии фиксированы (`pnpm-lock.yaml`, `--frozen-lockfile`, digest базовых образов).
4. SBOM (CycloneDX/Syft) для каждого образа.

### Opus-7 (High). Открытая регистрация и слабая парольная политика

**Суть.** D-6: регистрация открыта, `12345678` и `password` принимаются. В [server/src/auth/better-auth.ts](../server/src/auth/better-auth.ts) `requireEmailVerification: false`; регистрация закрывается только через `PAPERCLIP_AUTH_DISABLE_SIGN_UP`. РБПО 1 требует ограничений сложности, запрета повтора паролей и принудительной смены первоначального пароля.

**Устранение.**

1. В пилоте: `PAPERCLIP_AUTH_DISABLE_SIGN_UP=true`, локальные пользователи создаются администратором по утверждённому списку. Нативная корпоративная OIDC/SAML-аутентификация в проверенной ревизии не обнаружена. Reverse proxy с SSO сам по себе не создаёт Paperclip-сессию и не должен называться интеграцией SSO: либо реализовать и проверить нативный OIDC, либо оставить локальную аутентификацию Paperclip за access proxy как два независимых рубежа.
2. Патч: политика сложности по внутренним требованиям, история паролей, принудительная смена при первом входе, журналирование событий аутентификации (РБПО 4).
3. Двухфакторная аутентификация для администраторов.

### Opus-8 (Medium). Заголовки безопасности

**Суть.** D-9: глобального `helmet` или аналога нет, хотя отдельные чувствительные ответы уже выставляют CSP и `nosniff`. Отсутствие CSP на JSON API само по себе не уязвимость; CSP необходима для HTML/UI. HSTS имеет смысл только на фактической точке завершения TLS.

**Устранение.** На ingress включить HSTS; для UI/HTML — совместимую с plugin/MCP iframe моделью CSP и `frame-ancestors`; глобально `X-Content-Type-Options`, подходящий `Referrer-Policy`, `app.disable('x-powered-by')`. Подключать `helmet` поэтапно с browser-тестами, а не механически на все API-ответы. Неиспользуемые HTTP-методы ограничить на ingress (РБПО 6).

### Opus-9 (Medium). Управление сессиями

**Суть.** D-8 выполнялся по HTTP, где отсутствие `Secure` ожидаемо; это не доказывает поведение целевого HTTPS-развёртывания. Сессия 7 дней, отдельный тайм-аут неактивности и лимит одновременных сессий не настроены (РБПО 2).

**Устранение.** Только HTTPS (cookie `Secure` + HSTS); тайм-аут неактивности по регламенту; лимит одновременных сессий; проверка смены идентификатора сессии при входе; аннулирование при выходе — тест.

### Opus-10 (Medium). Валидация входных данных

**Суть.** D-5: невалидный UUID в пути даёт 500 (ошибка SQL в логе), поиск ресурса идёт до проверки прав.

**Устранение.** Единая валидация параметров (zod) до обращения к БД; проверка аутентификации до поиска ресурса; ответ 400/401 вместо 500; журналирование ошибок валидации (РБПО 3).

### Opus-11 (Low). Раскрытие информации

**Суть.** `/api/openapi.json` и `/api/health` (commit, режим, статус бэкапов) доступны без входа.

**Устранение.** Без аутентификации `/api/health` отдаёт только `{"status":"ok"}`; `openapi.json` — только после входа или отключить в prod.

### Opus-12 (Medium). Состав prod-образа

**Суть.**

- [Dockerfile](../Dockerfile) ставит `curl`, `wget` (РБПО, Kubernetes 9.8) и Tailscale — средство удалённого доступа (9.15).
- Нет HEALTHCHECK.
- Небезопасные env по умолчанию: `OPENCODE_ALLOW_ALL_MODELS=true`, `GEMINI_SANDBOX=false`.
- Базовые образы `node:24-trixie-slim` без digest в части stage.

**Устранение.** Собрать для пилота prod-образ без curl, wget и Tailscale; HEALTHCHECK; закрепить digest всех базовых образов; убрать небезопасные env; подписывать образ (cosign) и сканировать перед помещением в реестр (РБПО 14; Kubernetes 9.16–9.18).

### Opus-13 (High). Телеметрия и egress агентских CLI

**Суть.** Claude Code, Codex, OpenCode и Gemini CLI имеют собственную телеметрию и автообновление; патч Paperclip это не закрывает.

**Устранение.** Claude Code: `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`, `DISABLE_TELEMETRY=1`, `DISABLE_ERROR_REPORTING=1`, `DISABLE_AUTOUPDATER=1`; аналогичные настройки для остальных CLI; версии зафиксировать в образе. LLM-трафик — через корпоративный прокси (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`) с логированием и DLP.

### Opus-14 (Low). Режим `local_trusted`

**Суть.** [server/src/middleware/auth.ts:277](../server/src/middleware/auth.ts:277): вход не требуется. Это режим по умолчанию у `pnpm dev`. При этом startup уже запрещает `local_trusted` на non-loopback bind и с exposure, отличным от `private` ([server/src/index.ts](../server/src/index.ts)); требуемая защита в коде частично реализована.

**Устранение.** В пилоте строго `authenticated` + `private`, HTTPS, `PAPERCLIP_ALLOWED_HOSTNAMES`. Добавить deployment/policy-as-code тест, что manifest не может включить `local_trusted`; сохранить регрессионный тест существующего отказа старта на non-loopback. Новый патч поведения не требуется, если проверка подтверждает текущую защиту.

### Opus-15 (Medium). Проверки безопасности в CI

**Суть.** В `.github/workflows/` нет SAST, SCA, поиска секретов, сканирования образов (РБПО 10, 11, 13, 14).

**Устранение.** Добавить в CI форка блокирующие проверки: Semgrep (или корпоративный SAST), `pnpm audit --prod --audit-level=high`, Trivy fs + image, gitleaks (с baseline тестовых фикстур), hadolint; SBOM и подпись образа.

### Opus-16 (High). AES-GCM без фиксированной длины тега

**Суть.** Semgrep нашёл 7 мест, ручной поиск по `createDecipheriv` во всём prod-коде (12 файлов) — ещё 2. Итого 8 мест, где `createDecipheriv("aes-256-gcm", key, iv)` вызывается без `{ authTagLength: 16 }` и без проверки длины тега:

| Место | Что шифруется |
|---|---|
| [server/src/secrets/local-encrypted-provider.ts:240](../server/src/secrets/local-encrypted-provider.ts:240) | хранилище секретов |
| [server/src/storage/file-crypto-pool.ts:146](../server/src/storage/file-crypto-pool.ts:146) | файлы |
| [server/src/services/git-restore-point.ts:597](../server/src/services/git-restore-point.ts:597) | точки восстановления Git |
| [server/src/services/mcp-elicitation.ts:358](../server/src/services/mcp-elicitation.ts:358) | MCP elicitation |
| [server/src/services/mcp-tasks.ts:174](../server/src/services/mcp-tasks.ts:174) | идентификаторы MCP-задач |
| [server/src/services/provider-trace-object-store.ts:93](../server/src/services/provider-trace-object-store.ts:93) | трейсы провайдеров |
| [server/src/services/native-runtime/native-provider-artifacts.ts:652](../server/src/services/native-runtime/native-provider-artifacts.ts:652) | артефакты native provider |
| [server/src/services/native-runtime/native-harness-backup-storage.ts:401](../server/src/services/native-runtime/native-harness-backup-storage.ts:401) | резервные копии native harness |

Проверены и корректны: `tool-content-guards.ts` (длина тега проверяется вручную), `paperclip-cloud-connector.ts` (задан `authTagLength`), `packages/paperclip-runner/src/control-plane/durable-prp-control-plane.ts` (тег — всегда последние 16 байт). `remote-workspace-snapshot-storage.ts` использует AES-CTR без тега, но целостность проверяется по SHA-256, сохранённому в БД. Node.js без явной длины принимает укороченный тег, что снижает стойкость аутентификации шифротекста.

**Устранение.** Явно задать `authTagLength: 16` в `createCipheriv` и `createDecipheriv`; проверять `tag.length === 16` до расшифровки; добавить тест с укороченным тегом; Semgrep-правило в CI.

### Opus-17 (Medium). Сравнение секретов, уязвимое к атаке по времени

**Суть.** [server/src/board-claim.ts:38-39](../server/src/board-claim.ts:38) сравнивает длинные случайные token/code через `!==`; Semgrep нашёл ещё 38 кандидатов (включая UI, где constant-time сравнение не создаёт серверной защиты). Эксплуатируемость удалённой timing-атаки не подтверждена, но серверные MAC, подписи, reset/claim tokens и API keys должны сравниваться constant-time.

**Устранение.** Для секретов, токенов, кодов, подписей — `crypto.timingSafeEqual` на буферах одинаковой длины (общий helper в `packages/shared`); остальные срабатывания разобрать и пометить.

### Opus-18 (Medium). Междоменные взаимодействия и выдача контента

**Суть.**

- `Access-Control-Allow-Origin: *` для публичных статических файлов UI плагинов ([server/src/routes/plugin-ui-static.ts:490](../server/src/routes/plugin-ui-static.ts:490)); без credentialed response или чувствительных данных это не подтверждённая утечка, а требование проверить модель origin и способы загрузки плагинов.
- `postMessage(message, "*")` в iframe MCP-приложений ([ui/src/components/mcp-app/McpAppFrame.tsx:113](../ui/src/components/mcp-app/McpAppFrame.tsx:113)); iframe использует `srcDoc` с opaque origin, поэтому конкретный `targetOrigin` технически недоступен, а приём уже проверяет `event.source === iframe.contentWindow`. Это не подтверждённая уязвимость, а требование проверить capability/message schema и sandbox flags.
- `Content-Type` изображений анонсов берётся из внешнего фида ([server/src/routes/announcements.ts:32](../server/src/routes/announcements.ts:32)).
- `res.sendFile` в `plugin-ui-static.ts:496`.

**Устранение.**

1. CORS — сначала подтвердить, какие plugin assets должны загружаться cross-origin и содержат ли ответы чувствительные данные. Для credentialed/dynamic endpoints — только allowlist origin; `*` допустим для действительно публичных неизменяемых assets при отдельном обосновании.
2. Для `srcDoc`/opaque-origin оставить `targetOrigin="*"` только при строгой проверке `event.source`, schema сообщений, capability allowlist и sandbox iframe; добавить негативные browser-тесты. Если iframe переводится на отдельный origin, тогда использовать конкретный `targetOrigin` и проверять `event.origin`.
3. Анонсы: allowlist `image/png|jpeg|gif|webp` без SVG; в пилоте фид анонсов отключить (это ещё и внешний egress).
4. `sendFile`: существующая проверка `path.relative` уже отклоняет выход из каталога; добавить тесты на `../`, encoded traversal и symlink escape. Менять реализацию только если тест воспроизводит обход.

### Opus-19 (Medium). Регулярные выражения, уязвимые к ReDoS

**Суть.** 173 срабатывания `regex_dos` (раздел 5). Это кандидаты, а не 173 доказанные уязвимости: для эксплуатации выражение должно быть достижимо недоверенным входом достаточной длины и иметь сверхлинейное время. Подтверждённые случаи на пользовательском вводе, выводе LLM и логах команд могут блокировать event loop сервера (например [packages/adapter-utils/src/command-redaction.ts:46](../packages/adapter-utils/src/command-redaction.ts:46)).

**Устранение.** Разобрать все 173: переписать без катастрофического backtracking, ограничить длину входа перед сопоставлением, для выражений на недоверенных данных использовать `re2`; правило `regex_dos` в CI как блокирующее для новых нарушений.

---

## 7. Шаблон разбора находки (БР-5 и др.)

| Поле | Содержание |
|---|---|
| ID отчёта / правило | |
| Файл:строка | |
| Prod-код или test/script/eval | |
| Источник данных (user input / LLM / конфиг / константа) | |
| Уровень и срок по РБПО | |
| Исправление / PR / тест | |
| Статус (Открыто / Исправлено / Исключение службы ИБ) | |

---

## 8. План работ этапа 2 (Gates A–D)

Раздел описывает этап 2. Этап 1 («Этапы работ») — его предпосылка: находки сканеров БР к началу Gate A уже закрыты или переданы в ИБ на повторную проверку.

Срок считается от даты подтверждения находки, а не от даты этого документа. Для каждой строки назначается ФИО владельца и ссылка на неизменяемое доказательство (PR/commit, отчёт сканера, manifest/digest, протокол теста). Роли ниже: **DEV** — команда Paperclip/форка, **PLAT** — команда платформы, **БР** — безопасная разработка, **ИБ** — служба информационной безопасности, принимающая сторона.

### 8.1. Gate A — инвентаризация и минимизация области

| # | Работа | Владелец | Результат / критерий выхода |
|---|---|---|---|
| A1 | Реестр этапа 1 передан в ИБ; реестр 159 находок БР заведён ([br-findings-registry.csv](br-findings-registry.csv)); зафиксировать с БР ревизию, версии Semgrep/Horusec/Dependency-Track и наборы правил; сверить расхождение 159/158 | БР + DEV | Ревизия и конфигурация сканеров зафиксированы, расхождение объяснено |
| A2 | Дедупликация и совместный триаж: prod/runtime, достижимость, источник недоверенных данных, severity | DEV + БР | Каждая находка имеет статус, обоснование уровня, owner, deadline и тест/исключение |
| A3 | Зафиксировать пилотный BOM: commit, lockfile, Dockerfile, образы и их digest, Helm/Kustomize/NetworkPolicy; сохранить команды, версии scanner/ruleset и SHA-256 сырых отчётов (для отчётов предварительной проверки — `reports/SHA256SUMS`) | DEV + PLAT | Один воспроизводимый набор артефактов и evidence manifest; сканируется именно он |
| A4 | Зафиксировать сокращённую функциональную область | владелец пилота + служба ИБ | Linux/Kubernetes; один выбранный agent runtime; тестовый Git и LLM gateway; без Windows, smoke-lab, встроенной БД, Tailscale и неразрешённых плагинов/коннекторов |

### 8.2. Gate B — исправления и построение контура

| Поток | Работы | Владелец | Блокирует |
|---|---|---|---|
| B1. Изоляция агента | Allowlist окружения; отдельные ephemeral HOME/TMP; убрать фолбэки ключей; запрет локальных адаптеров на сервере; отдельный pod на запуск без server/DB volumes; `dangerouslySkipPermissions` допустим только внутри этого sandbox | DEV + PLAT | Opus-1/2/5, БПО-3, БР-1 |
| B2. Выбранный sandbox provider | Включить в область проверки только Kubernetes provider (или выбранный эквивалент), его supply chain и runtime images; проверить `runAsNonRoot`, read-only rootfs, drop ALL, seccomp, quotas, timeout, cleanup и отсутствие host mounts | DEV + БР + PLAT | Opus-2, БПО-5 |
| B3. Телеметрия и egress | Телеметрия/feedback opt-in без внешних defaults; prod-bundle тест; отключение телеметрии и auto-update CLI; L3/L4 egress default-deny с явными FQDN/IP/port назначениями через LLM proxy. DNS sinkhole — только дополнительная мера | DEV + PLAT | БПО-1, Opus-4/13 |
| B4. Ключи и данные | Уникальные ключи из Vault; внешний PostgreSQL с TLS и раздельными owner/runtime ролями; миграции отдельной job; тестовые данные; backup/restore и ротация | DEV + PLAT | БПО-2/6, Opus-3/5 |
| B5. Кодовые Critical/High | Находки сканеров БР закрыты на этапе 1. На этапе 2: оставшиеся по перечням БР-2/БР-3 места `Math.random` и MD5/SHA1 и запрет линтером; `authTagLength` в 8 местах AES-GCM; Critical/High из собственного Semgrep (раздел 5) | DEV | БР-2/3 (остаток), Opus-16 |
| B6. Зависимости и образ | Обновления по достижимости; frozen lockfile; внутренние зеркала; минимальный non-root образ без Tailscale и лишних CLI; SBOM, подпись и Trivy image по digest | DEV + PLAT | Opus-6/12, БПО-5 |
| B7. Human auth | Регистрация закрыта; утверждённый bootstrap пользователей; HTTPS; cookie/session policy. Нативный OIDC — отдельная работа; access proxy не подменяет Paperclip auth | DEV + PLAT | Opus-7/9/14 |
| B8. Defense in depth | Security headers; input validation; CORS/postMessage/content allowlists; только подтверждённые timing/ReDoS случаи; ограничение размера/времени обработки | DEV | Opus-8/10/11/17–19 |
| B9. Непрерывный контроль | Корпоративные SAST/SCA/secrets/IaC/image checks с baseline и блокировкой новых Critical/High; SBOM и provenance | DEV + БР | Opus-15 |
| B10. Аудит | Authentication, approvals, secret binding/access, agent lifecycle, connector calls, admin changes и LLM gateway — в SIEM; синхронизация времени, retention, alert rules | DEV + PLAT + служба ИБ | РБПО 4 |

### 8.3. Gate C — критерии приёмки

Допуск выдаётся по артефакту, а не по заявлению «исправлено»:

1. Реестр БР: 100% из 159 первичных ID разобраны; подтверждённых Critical/High со статусом `Открыто` нет. Исключение содержит владельца риска, компенсирующую меру, срок и подпись службы ИБ.
2. Регрессия D-1/D-2: при пустой конфигурации телеметрии нет сетевых вызовов; canary-значения `BETTER_AUTH_SECRET`, `DATABASE_URL`, master/cloud credentials отсутствуют в окружении и файловой системе agent pod.
3. Escape-тест: агент не читает server/Vault/DB/Kubernetes credentials, не обращается к metadata service, control-plane DB и произвольному Internet; после завершения pod и ephemeral secrets уничтожены.
4. SCA/image: в развёртываемом digest нет достижимых Critical/High; все недостижимые/неисправимые findings имеют согласованные исключения. SBOM и подпись соответствуют digest.
5. Конфигурация: policy-as-code подтверждает non-root, read-only rootfs, drop ALL, no privilege escalation/host mounts, resource limits, NetworkPolicy default-deny и разрешённые image digests.
6. AuthN/AuthZ: регистрация закрыта; HTTPS и Secure cookie; тесты двух пользователей и двух компаний не выявляют IDOR; проверены logout/revocation, session timeout и admin bootstrap.
7. AppSec: повторный SAST тем же ruleset без timeout/parse-пропусков в заявленной области (либо каждый пропуск отдельно закрыт другим анализом) и отдельный DAST/пентест силами службы ИБ; подтверждены command-injection, redirect, upload/path traversal, WebSocket, plugin UI и prompt-injection-to-shell сценарии.
8. Наблюдение egress не менее 24 часов на реалистичном сквозном прогоне: соединения только с утверждёнными назначениями; DNS, прокси и firewall логи приложены.
9. DR/операции: успешно проверены backup/restore, ротация каждого ключа, отзыв connector/LLM credentials и аварийная остановка всех agent pods.

### 8.4. Gate D — пилот и завершение

1. На время пилота — change freeze пилотного BOM; любое изменение commit, lockfile, image digest или политики инвалидирует затронутые доказательства Gate C.
2. Ежедневные alerts и еженедельный обзор журналов: действия агентов, approvals, секреты, egress, бюджет и нарушения sandbox.
3. Stop conditions: неожиданный egress, доступ агента вне workspace, утечка canary/секрета, неподписанный образ, отключение SIEM или обход approval — немедленная остановка пилота и ротация.
4. По окончании: отзыв ключей LLM и токенов коннекторов, ротация серверных секретов, уничтожение test data/volumes по акту, итоговый отчёт для целевой архитектуры AI-PDLC.

---

## 9. Ограничения проверки

- Повторный прогон этапа 1 (2026-11-23): Horusec запускался по каталогам (на всём репозитории сразу он падает с исчерпанием потоков), без тестов; Semgrep — по наборам правил для языков репозитория, без тестов и документации, 393 файла с ошибками разбора или тайм-аутом; Dependency-Track локально не запускался, вместо этого подготовлен SBOM. Конфигурацию сканеров (версии правил, фильтры, разбор в DefectDojo) нужно сверить с БР: на текущей ревизии сканеры выдают заметно больше срабатываний, чем 159 в отчёте.
- Отчёт БР разобран по выгрузке DefectDojo (HTML). Оценки эксплуатируемости в реестре — по чтению кода текущей ревизии, без динамической проверки каждой находки; исходные HTML-отчёты содержат внутренние адреса и в репозиторий не добавлены.
- Динамическое тестирование предварительное: сервер из исходников, без UI, без агентов с реальными LLM, без второй компании для проверки IDOR.
- Плагины (`packages/plugins/*`) системно не проверялись. При этом контейнерная изоляция пилота требует выбранного sandbox provider; поэтому только этот provider, его зависимости и runtime-образ необходимо добавить в область SAST/SCA/пентеста. Все остальные плагины в пилоте запрещены.
- Rust-часть раннера (`packages/paperclip-runner/runner`) и `packages/paperclip-runner/src` проверялись только Trivy и gitleaks; Semgrep по ним не запускался из-за объёма.
- Semgrep пропустил 553 файла по тайм-ауту или ошибке разбора; полный прогон — в CI без лимитов.
- Prod-образ Docker не собирался и Trivy по образу (`trivy image`) не запускался: сборка требует Rust-тулчейна и длительна; выполнить в Gate B6 (раздел 8.2) по финальному digest.
