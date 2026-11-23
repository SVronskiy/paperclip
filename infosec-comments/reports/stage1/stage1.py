"""Build the stage-1 registry: BR findings + what the same tools report on the current revision.

Usage: python3 -I stage1.py <br-tools dir> <rescan dir> <out csv>
"""
import collections
import csv
import json
import os
import re
import sys

BR, RS, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
old = {o["id"]: o for o in json.load(open(os.path.join(BR, "findings.json")))}
cmp_ = json.load(open(os.path.join(RS, "compare.json")))


def norm_rule(r):
    return re.sub(r"^\(\d+/\d+\) \* Possible Vulnerability Detected: ", "", r, flags=re.I).strip().lower()


br_rules = {norm_rule(o["title"].split(".")[-1] if o["tool"] == "Semgrep" else o["title"]) for o in old.values()}

# rule (lowercase) -> (stream, plan item, action)
S = {
    "using shell interpreter when executing os commands": ("Э1-5", "БР-1", "Явный shell:false; команда — константа или allowlist; аргументы проверяются; запрет строковых exec линтером"),
    "using command line arguments": ("Э1-5", "БР-1", "Проверка аргументов по allowlist перед запуском процесса; shell:false"),
    "dangerous-subprocess-use-audit": ("Э1-5", "БР-1", "Проверка аргументов; исключить отладочный скрипт из поставки"),
    "dangerous-subprocess-use-tainted-env-args": ("Э1-5", "БР-1", "Проверка аргументов; исключить отладочный скрипт из поставки"),
    "dangerous-syscall-exec": ("Э1-5", "БР-1", "Allowlist команд адаптеров, абсолютные пути"),
    "spawn-shell-true": ("Э1-2", "БПО-4", "Убрать shell:true, запуск через cross-spawn"),
    "no use weak random number generator": ("Э1-6", "БР-2", "Заменить Math.random на crypto (randomUUID / randomInt / getRandomValues)"),
    "no use md5 hashing": ("Э1-7", "БР-3", "Заменить на SHA-256 (для протокольных мест — исключение службы ИБ)"),
    "no use sah1 hashing": ("Э1-7", "БР-3", "SHA-256; для RFC 6455 / UUIDv5 — исключение службы ИБ, UUIDv5 через библиотеку uuid"),
    "redirect to unknown path": ("Э1-8", "БР-4", "Проверка цели редиректа: относительный путь или зарегистрированный redirect_uri; тесты"),
    "express_open_redirect": ("Э1-8", "БР-4", "Проверка цели редиректа: относительный путь или зарегистрированный redirect_uri; тесты"),
    "no render content from request": ("Э1-9", "БР-5", "Экранировать вывод (включая > и '); dev-HTML Vite не включать в prod; тест XSS"),
    "statically serving hidden files is security-sensitive": ("Э1-9", "БР-5", "dotfiles: 'deny'; тест"),
    "origins should be verified during cross-origin communications": ("Э1-9", "БР-5", "Для window message — проверка event.origin/event.source; прочие слушатели (DOM/AbortSignal) — пометить с обоснованием"),
    "stack trace exposure": ("Э1-9", "БР-5", "Не отдавать стек в ответе"),
    "no read file using data from request": ("Э1-9", "БР-5", "Проверка пути внутри разрешённого каталога; тесты на ../ и symlink"),
    "regex_injection_dos": ("Э1-9", "БР-5", "Экранировать спецсимволы при построении RegExp"),
    "remote-property-injection": ("Э1-9", "БР-5", "Фиксированный список ключей; Object.create(null)"),
    "tainted-sql-string": ("Э1-9", "БР-5", "Только параметризованные запросы; тест"),
    "express-wkhtmltoimage-injection": ("Э1-9", "БР-5", "Подтвердить отсутствие wkhtmltoimage; пометить"),
}
NEW_RULE = ("Э1-11", "БР-5", "Совместный триаж с БР до передачи: подтверждённое исправить, остальное — обоснование в DefectDojo")

rows = []
fixed = {"364636": "Устранено: Math.random удалён из environment-runtime.ts", "365590": "Устранено: файл codex-runtime-adapter.ts удалён"}
for x in cmp_["new"]:
    if not x["in_profile"]:
        continue
    r = x["rule"].lower()
    if x["br_id"]:
        origin = "Находка БР"
    elif r in br_rules:
        origin = "Новое срабатывание правила из отчёта БР"
    else:
        origin = "Новый тип срабатывания"
    stream, ref, act = S.get(r, NEW_RULE) if origin != "Новый тип срабатывания" else NEW_RULE
    if x["file"] == "cli/src/client/board-auth.ts" and "shell" in r:
        stream, ref, act = "Э1-2", "БР-6", "Открывать URL без cmd; проверка схемы; тест с &calc"
    if x["file"].startswith("server/src/routes/public-mcp") or x["file"].startswith("server/src/routes/muse"):
        if stream == "Э1-8":
            act += "; ограничить динамическую регистрацию клиентов allowlist-ом redirect_uri"
    rows.append({
        "Поток этапа 1": stream, "Пункт плана": ref, "Происхождение": origin, "ID БР": x["br_id"],
        "Инструмент": x["tool"], "Уровень": x["severity"], "Правило": x["rule"],
        "Файл": x["file"], "Строка": x["line"], "Фрагмент": x["code"][:160].replace("\n", " "),
        "Действие": act, "Статус": "Принята к исправлению",
    })
for i, note in fixed.items():
    o = old[i]
    rows.append({"Поток этапа 1": "Э1-6" if "Random" in o["title"] else "Э1-5", "Пункт плана": "БР-2" if "Random" in o["title"] else "БР-1",
                 "Происхождение": "Находка БР", "ID БР": i, "Инструмент": o["tool"], "Уровень": o["severity"],
                 "Правило": norm_rule(o["title"]), "Файл": o["file"], "Строка": "", "Фрагмент": o["code"][:160],
                 "Действие": note + "; закрыть после подтверждения БР", "Статус": "Устранено до этапа 1"})
dt = {"365906": ("hyper", "1.11.1", "Cargo.lock раннера"), "365904": ("@grpc/grpc-js", "1.14.4", "lockfile плагина Daytona"), "365905": ("@grpc/grpc-js", "1.14.5", "server/package.json")}
for i, (name, ver, where) in dt.items():
    o = old[i]
    rows.append({"Поток этапа 1": "Э1-10", "Пункт плана": "Opus-6", "Происхождение": "Находка БР", "ID БР": i,
                 "Инструмент": "DependencyTrack", "Уровень": o["severity"], "Правило": o["title"].split(" Affected By: ")[1],
                 "Файл": f"{name}@{ver} ({where})", "Строка": "", "Фрагмент": "",
                 "Действие": "Обновить компонент до актуальной версии; загрузить SBOM этапа 1 в Dependency-Track; результат анализа совпадения CVE зафиксировать в Dependency-Track вместе с БР",
                 "Статус": "Принята к исправлению"})
order = {f"Э1-{n}": n for n in range(1, 12)}
rows.sort(key=lambda r: (order[r["Поток этапа 1"]], r["Происхождение"] != "Находка БР", r["Файл"], int(r["Строка"] or 0)))
for n, r in enumerate(rows, 1):
    r["№"] = n
fields = ["№"] + [k for k in rows[0] if k != "№"]
with open(OUT, "w", encoding="utf-8-sig", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=fields)
    w.writeheader()
    w.writerows(rows)

c = collections.Counter((r["Поток этапа 1"], r["Происхождение"]) for r in rows)
for k, v in sorted(c.items(), key=lambda kv: (order[kv[0][0]], kv[0][1])):
    print(v, k)
print(len(rows), collections.Counter(r["Уровень"] for r in rows))
print(collections.Counter((r["Инструмент"], r["Происхождение"]) for r in rows))
