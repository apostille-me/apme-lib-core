-- Provisioning the isolated admin database on Neon.
--
-- Run as the project owner (usually `neondb_owner`) against a DEDICATED Neon
-- project or database — never alongside customer data.
--
-- Why a new role at all: the admin runtime refuses to start unless
-- `current_user` is a plain role with none of SUPERUSER, CREATEROLE, CREATEDB,
-- REPLICATION or BYPASSRLS, and with no CREATE privilege on the database or on
-- any non-system schema. Neon's default `neondb_owner` fails that check — it
-- owns the database and can create schemas — so it provisions, and a separate
-- runtime role connects.
--
-- Connection string shape the runtime will accept:
--   postgresql://admin_api_runtime:<pw>@ep-<id>.<region>.aws.neon.tech
--     /admin_control?sslmode=verify-full
-- Neon requires TLS; `verify-full` is mandatory here and Neon presents a
-- publicly trusted certificate, so no custom CA is needed. If your driver does
-- not send SNI, append `&options=endpoint%3Dep-<id>` — the runtime checks that
-- it names the same endpoint as the hostname, because a mismatch silently
-- routes to a different compute.

\set ON_ERROR_STOP on

-- 1. Runtime roles. Passwords come from your secret store, not from here.
CREATE ROLE admin_api_runtime LOGIN PASSWORD :'admin_api_password';
CREATE ROLE admin_web_runtime LOGIN PASSWORD :'admin_web_password';

-- Neon grants every new role membership in neon_superuser by default on some
-- project templates. Remove it: it carries CREATEROLE.
REVOKE neon_superuser FROM admin_api_runtime, admin_web_runtime;

ALTER ROLE admin_api_runtime NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE admin_web_runtime NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

-- The web tier is read-only at the database, not merely by convention. The
-- runtime proves this by checking `SHOW transaction_read_only` after connecting.
ALTER ROLE admin_web_runtime SET default_transaction_read_only = on;

-- 2. No schema creation anywhere. The runtime-role check fails if either role
--    can create objects, which is what keeps migrations exclusively in
--    declarative-migrations.
REVOKE ALL ON DATABASE admin_control FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM admin_api_runtime, admin_web_runtime;

GRANT CONNECT ON DATABASE admin_control TO admin_api_runtime, admin_web_runtime;
GRANT USAGE ON SCHEMA public TO admin_api_runtime, admin_web_runtime;

-- 3. Table privileges. Apply AFTER admin-db-contract.sql has created the tables.
GRANT SELECT                 ON admin_principals      TO admin_api_runtime, admin_web_runtime;
GRANT SELECT, INSERT, UPDATE ON admin_action_requests TO admin_api_runtime;
GRANT SELECT                 ON admin_action_requests TO admin_web_runtime;
GRANT SELECT, INSERT, UPDATE ON admin_action_outbox   TO admin_api_runtime;

-- Deliberately absent: DELETE anywhere, and any grant on the outbox to the web
-- tier. Admin history is append-only; nothing in the runtime path can rewrite it.

-- 4. Neon-specific operational notes.
--    * Put the admin database in its own Neon PROJECT, not just its own branch.
--      Branches share compute and a project-wide connection allowlist, so a
--      branch is not an isolation boundary for an admin plane.
--    * Disable "allow connections from anywhere" and restrict the project's IP
--      allowlist to the admin VPC egress addresses. The in-process CIDR gate
--      guards inbound; this guards the database side.
--    * Scale-to-zero adds cold-start latency to the readiness probe. Either
--      disable suspend on this project or raise the probe's failureThreshold.
