# admin-orm

Product-owned, named ORM operations for the isolated admin database.

The admin API and admin console depend on this crate from their product's ORM
repository. `AdminReadContext` and `AdminWriteContext` keep the SeaORM
connection private, so a caller cannot bypass the reviewed operations with
ad-hoc SQL, and each proves at connect time that the credential it was given is
actually read-only or actually writable — rather than trusting configuration.

## What is checked before a connection is used

* The URL's scheme, host, role, database and `sslmode=verify-full` all match
  the reviewed identity passed in `AdminDatabaseConfig`.
* The provider-specific endpoint rules hold (see below).
* `current_user` and `current_database()` are what was expected, and the role
  holds none of SUPERUSER, CREATEROLE, CREATEDB, REPLICATION or BYPASSRLS, and
  has no CREATE privilege on the database or on any non-system schema. This is
  what keeps DDL exclusively in `declarative-migrations`.
* `SHOW transaction_read_only` agrees with the context being constructed.

## Providers

`AdminDatabaseProvider` selects the endpoint rules. The default managed
Postgres roles on Neon and Supabase both **fail** the runtime-role check above,
so each needs a dedicated role — see `docs/admin-db-provisioning-*.sql`.

| Provider | Host rule | Notes |
|---|---|---|
| `rds` | exact hostname | the original shape; no suffix constraint |
| `neon` | must end `.neon.tech`, first label is the `ep-…` endpoint | if `options=endpoint%3D…` is present it must name the same endpoint as the host, since a mismatch silently routes to a different compute |
| `supabase` | must end `.supabase.co` / `.supabase.com` | role may be `postgres.<project-ref>`; **port 6543 is refused** because transaction pooling does not carry the session state the read-only/writable proof depends on |

Set it with `ADMIN_DATABASE_PROVIDER` (`rds` \| `neon` \| `supabase`). An
unknown value is a startup error rather than a silent default — defaulting to
the strictest provider would still be the wrong one, and defaulting to the
loosest would be a security regression.

## Schema

`docs/admin-db-contract.sql` is the declarative contract. Nothing here executes
DDL; migrations belong to `declarative-migrations` running as the dedicated
admin owner, which is a different role from either runtime role.
