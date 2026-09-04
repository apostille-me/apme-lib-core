-- Provisioning the isolated admin database on Supabase.
--
-- Run in the SQL editor of a DEDICATED Supabase project — never the project
-- that serves customers. Supabase's own `postgres` role carries CREATEROLE and
-- CREATEDB, so the admin runtime refuses to use it: it provisions, and a
-- separate runtime role connects.
--
-- Connection string shape the runtime will accept:
--   Direct:  postgresql://admin_api_runtime:<pw>@db.<ref>.supabase.co:5432
--              /admin_control?sslmode=verify-full
--   Pooler:  postgresql://postgres.<ref>:<pw>@aws-0-<region>.pooler.supabase.com:5432
--              /postgres?sslmode=verify-full
--
-- IMPORTANT: port 6543 (Supavisor transaction pooling) is REFUSED by the
-- runtime. Transaction pooling does not carry session state between
-- statements, and the admin contexts prove read-only versus writable with a
-- session-scoped `SHOW transaction_read_only`. Use 5432 (session pooling) or a
-- direct connection.

\set ON_ERROR_STOP on

-- 1. Runtime roles.
CREATE ROLE admin_api_runtime LOGIN PASSWORD :'admin_api_password';
CREATE ROLE admin_web_runtime LOGIN PASSWORD :'admin_web_password';

ALTER ROLE admin_api_runtime NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE admin_web_runtime NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE admin_web_runtime SET default_transaction_read_only = on;

-- Supabase ships anon/authenticated/service_role for PostgREST. The admin plane
-- does not go through PostgREST and these roles must never reach admin tables.
REVOKE ALL ON SCHEMA public FROM anon, authenticated;

-- 2. No schema creation. Supabase grants CREATE on public to postgres and, on
--    older projects, to PUBLIC — both must go for the runtime check to pass.
REVOKE ALL    ON DATABASE postgres FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM admin_api_runtime, admin_web_runtime;

GRANT CONNECT ON DATABASE postgres TO admin_api_runtime, admin_web_runtime;
GRANT USAGE   ON SCHEMA public     TO admin_api_runtime, admin_web_runtime;

-- The admin runtime must not reach Supabase's own auth schema. Identity comes
-- from the shared-auth admin instance, not from Supabase Auth.
REVOKE ALL ON SCHEMA auth    FROM admin_api_runtime, admin_web_runtime;
REVOKE ALL ON SCHEMA storage FROM admin_api_runtime, admin_web_runtime;

-- 3. Table privileges. Apply AFTER admin-db-contract.sql.
GRANT SELECT                 ON admin_principals      TO admin_api_runtime, admin_web_runtime;
GRANT SELECT, INSERT, UPDATE ON admin_action_requests TO admin_api_runtime;
GRANT SELECT                 ON admin_action_requests TO admin_web_runtime;
GRANT SELECT, INSERT, UPDATE ON admin_action_outbox   TO admin_api_runtime;

-- 4. Row Level Security.
--    The admin tables are reached only by these two roles over a private
--    network, so RLS is defence in depth rather than the primary control. Enable
--    it and FORCE it, so a future grant to another role cannot quietly read the
--    tables. Neither runtime role has BYPASSRLS (asserted at startup).
ALTER TABLE admin_principals      ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_action_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_action_outbox   ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_principals      FORCE  ROW LEVEL SECURITY;
ALTER TABLE admin_action_requests FORCE  ROW LEVEL SECURITY;
ALTER TABLE admin_action_outbox   FORCE  ROW LEVEL SECURITY;

CREATE POLICY admin_runtime_read_principals ON admin_principals
    FOR SELECT TO admin_api_runtime, admin_web_runtime USING (true);
CREATE POLICY admin_runtime_read_requests ON admin_action_requests
    FOR SELECT TO admin_api_runtime, admin_web_runtime USING (true);
CREATE POLICY admin_api_write_requests ON admin_action_requests
    FOR INSERT TO admin_api_runtime WITH CHECK (true);
CREATE POLICY admin_api_update_requests ON admin_action_requests
    FOR UPDATE TO admin_api_runtime USING (true) WITH CHECK (true);
CREATE POLICY admin_api_read_outbox ON admin_action_outbox
    FOR SELECT TO admin_api_runtime USING (true);
CREATE POLICY admin_api_write_outbox ON admin_action_outbox
    FOR INSERT TO admin_api_runtime WITH CHECK (true);
CREATE POLICY admin_api_update_outbox ON admin_action_outbox
    FOR UPDATE TO admin_api_runtime USING (true) WITH CHECK (true);

-- No DELETE policy exists on any table, so nothing in the runtime path can
-- remove admin history even if a DELETE grant were added by mistake.

-- 5. Supabase-specific operational notes.
--    * Turn OFF the Data API (PostgREST) for this project, or at minimum
--      exclude the admin tables from exposed schemas. The admin plane is not
--      reachable over HTTP from Supabase.
--    * Restrict network access to the admin VPC egress addresses under
--      Database Settings, and keep "Enforce SSL on incoming connections" on.
--    * Do not enable Supabase Auth on this project; identity belongs to the
--      shared-auth admin instance.
