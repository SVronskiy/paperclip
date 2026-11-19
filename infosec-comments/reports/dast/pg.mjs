import { createRequire } from "node:module"; const require = createRequire(new URL("../../../packages/db/package.json", import.meta.url));
const postgres = require("postgres");
const sql = postgres("postgres://paperclip:paperclip@127.0.0.1:54329/paperclip", { max: 1, connect_timeout: 5 });
try {
  const [u] = await sql`select current_user, (select rolsuper from pg_roles where rolname=current_user) as superuser`;
  const t = await sql`select table_name from information_schema.tables where table_schema='public' and table_name ilike '%secret%' order by 1`;
  const [c] = await sql`select count(*)::int n from company_secrets`.catch(()=>[{n:"n/a"}]);
  console.log("ПОДКЛЮЧЕНИЕ С ПАРОЛЕМ ПО УМОЛЧАНИЮ: успешно; user:", u.current_user, "superuser:", u.superuser);
  console.log("таблицы секретов:", t.map(r=>r.table_name).join(", "), "| строк company_secrets:", c.n);
} catch (e) { console.log("не удалось:", e.message); } finally { await sql.end(); }
