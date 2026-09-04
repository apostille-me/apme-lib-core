-- Declarative contract only. The server never executes DDL at startup.
-- Apply through declarative-migrations with the dedicated admin RDS owner.

CREATE TABLE admin_principals (
    shared_auth_subject text PRIMARY KEY,
    status text NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
    permissions text[] NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (cardinality(permissions) <= 64)
);

CREATE TABLE admin_action_requests (
    operation_id uuid PRIMARY KEY,
    idempotency_key text NOT NULL UNIQUE,
    actor_subject text NOT NULL REFERENCES admin_principals(shared_auth_subject),
    actor_session_id text NOT NULL,
    resource text NOT NULL,
    action text NOT NULL,
    reason text NOT NULL,
    status text NOT NULL DEFAULT 'accepted'
        CHECK (status IN ('accepted', 'running', 'succeeded', 'failed', 'rejected')),
    requested_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    CHECK (length(idempotency_key) BETWEEN 8 AND 128),
    CHECK (length(reason) BETWEEN 8 AND 500)
);

CREATE TABLE admin_action_outbox (
    operation_id uuid PRIMARY KEY REFERENCES admin_action_requests(operation_id),
    event_kind text NOT NULL CHECK (event_kind = 'admin.action.requested'),
    delivery_status text NOT NULL DEFAULT 'pending'
        CHECK (delivery_status IN ('pending', 'delivering', 'delivered', 'failed')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 100),
    available_at timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz,
    last_error_code text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX admin_action_outbox_pending_idx
    ON admin_action_outbox (available_at, operation_id)
    WHERE delivery_status IN ('pending', 'failed');

-- Runtime roles are separate from the migration owner. The API runtime receives
-- only SELECT on admin_principals and SELECT/INSERT/UPDATE on action requests.
-- It receives SELECT/INSERT/UPDATE on the outbox but no CREATE privilege on the
-- database or any non-system schema. Runtime roles are never superusers and do
-- not receive CREATEROLE, CREATEDB, REPLICATION, or BYPASSRLS. Public/customer
-- service principals receive no CONNECT grant to this database.
