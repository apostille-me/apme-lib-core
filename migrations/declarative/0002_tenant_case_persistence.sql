do $$
begin
    perform pg_advisory_xact_lock(3457001);
end;
$$;

create table if not exists apme_tenants (
    id uuid primary key,
    organization_id uuid not null,
    display_name text not null check (length(display_name) between 1 and 160),
    created_at timestamptz not null default now()
);

create table if not exists apme_tenant_memberships (
    tenant_id uuid not null references apme_tenants(id),
    shared_user_id text not null check (length(shared_user_id) between 1 and 160),
    role text not null check (role in ('viewer', 'agent', 'administrator')),
    active boolean not null default true,
    created_at timestamptz not null default now(),
    primary key (tenant_id, shared_user_id)
);

create table if not exists apme_cases (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references apme_tenants(id),
    version bigint not null default 1 check (version > 0),
    title text not null check (length(title) between 1 and 256),
    summary text not null default '' check (length(summary) <= 4000),
    client_reference text not null check (length(client_reference) between 1 and 200),
    destination_country text not null check (length(destination_country) between 1 and 120),
    document_type text not null check (length(document_type) between 1 and 160),
    next_action_due_at timestamptz,
    status text not null default 'intake'
        check (status in ('intake','collecting_documents','review','submitted','completed','closed')),
    retention_class text not null
        check (retention_class in ('standard','extended','legal_hold_eligible')),
    retain_until timestamptz not null,
    legal_hold boolean not null default false,
    tombstoned_at timestamptz,
    encrypted_object_reference text,
    ciphertext_sha256 text,
    object_key_version integer,
    created_at timestamptz not null,
    updated_at timestamptz not null,
    unique (id, tenant_id),
    check (
        (encrypted_object_reference is null and ciphertext_sha256 is null and object_key_version is null)
        or (
            encrypted_object_reference is not null
            and encrypted_object_reference not like '%://%'
            and ciphertext_sha256 ~ '^[0-9a-f]{64}$'
            and object_key_version > 0
        )
    )
);

create index if not exists apme_cases_tenant_created_idx
    on apme_cases(tenant_id, created_at desc, id) where tombstoned_at is null;

create table if not exists apme_case_appointments (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references apme_tenants(id),
    case_id uuid not null,
    appointment_kind text not null check (length(appointment_kind) between 1 and 120),
    scheduled_at timestamptz not null,
    created_at timestamptz not null default now(),
    foreign key (case_id, tenant_id) references apme_cases(id, tenant_id)
);

create table if not exists apme_case_deadlines (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references apme_tenants(id),
    case_id uuid not null,
    deadline_kind text not null check (length(deadline_kind) between 1 and 120),
    due_at timestamptz not null,
    completed_at timestamptz,
    created_at timestamptz not null default now(),
    foreign key (case_id, tenant_id) references apme_cases(id, tenant_id)
);

create table if not exists apme_case_events (
    event_id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references apme_tenants(id),
    case_id uuid not null,
    case_version bigint not null check (case_version > 0),
    event_type text not null,
    actor_shared_user_id text not null,
    occurred_at timestamptz not null,
    payload jsonb not null,
    previous_hash bytea,
    event_hash bytea not null check (octet_length(event_hash) = 32),
    unique (case_id, case_version),
    foreign key (case_id, tenant_id) references apme_cases(id, tenant_id)
);

create table if not exists apme_case_create_commands (
    tenant_id uuid not null references apme_tenants(id),
    idempotency_key text not null check (length(idempotency_key) between 1 and 200),
    request_hash bytea not null check (octet_length(request_hash) = 32),
    case_id uuid not null,
    created_at timestamptz not null,
    primary key (tenant_id, idempotency_key),
    foreign key (case_id, tenant_id) references apme_cases(id, tenant_id)
);

create table if not exists apme_case_transition_commands (
    tenant_id uuid not null references apme_tenants(id),
    idempotency_key text not null check (length(idempotency_key) between 1 and 200),
    request_hash bytea not null check (octet_length(request_hash) = 32),
    case_id uuid not null,
    resulting_version bigint not null,
    created_at timestamptz not null,
    primary key (tenant_id, idempotency_key),
    foreign key (case_id, tenant_id) references apme_cases(id, tenant_id)
);

create table if not exists apme_case_object_commands (
    tenant_id uuid not null references apme_tenants(id),
    idempotency_key text not null check (length(idempotency_key) between 1 and 200),
    request_hash bytea not null check (octet_length(request_hash) = 32),
    case_id uuid not null,
    resulting_version bigint not null,
    created_at timestamptz not null,
    primary key (tenant_id, idempotency_key),
    foreign key (case_id, tenant_id) references apme_cases(id, tenant_id)
);

create table if not exists apme_tenant_audit_heads (
    tenant_id uuid primary key references apme_tenants(id),
    sequence bigint not null default 0,
    receipt_hash bytea
);

create table if not exists apme_audit_receipts (
    receipt_id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references apme_tenants(id),
    sequence bigint not null,
    action text not null
        check (action in ('create','transition','key_rotation','access','export','deletion')),
    actor_shared_user_id text not null,
    resource_type text not null,
    resource_id uuid not null,
    occurred_at timestamptz not null,
    details jsonb not null default '{}'::jsonb,
    previous_hash bytea,
    receipt_hash bytea not null check (octet_length(receipt_hash) = 32),
    unique (tenant_id, sequence)
);

create or replace function apme_hash_case_event(
    p_previous bytea, p_tenant uuid, p_case uuid, p_version bigint,
    p_type text, p_actor text, p_at timestamptz, p_payload jsonb
)
returns bytea language sql immutable as $$
    select pg_catalog.sha256(pg_catalog.convert_to(
        coalesce(encode(p_previous, 'hex'), '') || '|' || p_tenant::text || '|' ||
        p_case::text || '|' || p_version::text || '|' || p_type || '|' || p_actor ||
        '|' || to_char(p_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') ||
        '|' || p_payload::text,
        'UTF8'
    ));
$$;

create or replace function apme_hash_audit_receipt(
    p_previous bytea, p_tenant uuid, p_sequence bigint, p_action text,
    p_actor text, p_resource_type text, p_resource_id uuid,
    p_at timestamptz, p_details jsonb
)
returns bytea language sql immutable as $$
    select pg_catalog.sha256(pg_catalog.convert_to(
        coalesce(encode(p_previous, 'hex'), '') || '|' || p_tenant::text || '|' ||
        p_sequence::text || '|' || p_action || '|' || p_actor || '|' ||
        p_resource_type || '|' || p_resource_id::text || '|' ||
        to_char(p_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') ||
        '|' || p_details::text,
        'UTF8'
    ));
$$;

create or replace function apme_append_audit(
    p_tenant uuid, p_action text, p_actor text, p_resource_type text,
    p_resource_id uuid, p_at timestamptz, p_details jsonb
)
returns uuid language plpgsql as $$
declare
    audit_head apme_tenant_audit_heads%rowtype;
    next_hash bytea;
    new_receipt uuid;
begin
    insert into apme_tenant_audit_heads(tenant_id) values (p_tenant)
    on conflict (tenant_id) do nothing;
    select * into audit_head from apme_tenant_audit_heads
     where tenant_id = p_tenant for update;
    next_hash := apme_hash_audit_receipt(
        audit_head.receipt_hash, p_tenant, audit_head.sequence + 1, p_action,
        p_actor, p_resource_type, p_resource_id, p_at, p_details
    );
    insert into apme_audit_receipts(
        tenant_id, sequence, action, actor_shared_user_id, resource_type,
        resource_id, occurred_at, details, previous_hash, receipt_hash
    ) values (
        p_tenant, audit_head.sequence + 1, p_action, p_actor, p_resource_type,
        p_resource_id, p_at, p_details, audit_head.receipt_hash, next_hash
    ) returning receipt_id into new_receipt;
    update apme_tenant_audit_heads
       set sequence = audit_head.sequence + 1, receipt_hash = next_hash
     where tenant_id = p_tenant;
    return new_receipt;
end;
$$;

create or replace function apme_create_case(
    p_tenant uuid, p_actor text, p_idempotency_key text, p_request_hash bytea,
    p_title text, p_summary text, p_client_reference text,
    p_destination_country text, p_document_type text,
    p_next_action_due_at timestamptz, p_retention_class text,
    p_retain_until timestamptz, p_object_reference text,
    p_ciphertext_sha256 text, p_key_version integer, p_now timestamptz
)
returns table(case_id uuid, case_version bigint, event_id uuid, event_hash bytea, replayed boolean)
language plpgsql as $$
declare
    existing_command apme_case_create_commands%rowtype;
    member_role text;
    new_case uuid;
    new_event uuid;
    new_hash bytea;
    event_payload jsonb;
begin
    select role into member_role from apme_tenant_memberships
     where tenant_id = p_tenant and shared_user_id = p_actor and active;
    if member_role is null or member_role not in ('agent','administrator') then
        raise exception 'APME_NOT_AUTHORIZED' using errcode = '42501';
    end if;
    perform pg_advisory_xact_lock(hashtextextended(p_tenant::text || ':' || p_idempotency_key, 3456));
    select * into existing_command from apme_case_create_commands
     where tenant_id = p_tenant and idempotency_key = p_idempotency_key;
    if found then
        if existing_command.request_hash <> p_request_hash then
            raise exception 'APME_IDEMPOTENCY_CONFLICT' using errcode = '23505';
        end if;
        return query select c.id, c.version, e.event_id, e.event_hash, true
          from apme_cases c join apme_case_events e
            on e.case_id = c.id and e.case_version = 1
         where c.id = existing_command.case_id;
        return;
    end if;

    insert into apme_cases(
        tenant_id, title, summary, client_reference, destination_country,
        document_type, next_action_due_at, retention_class, retain_until,
        encrypted_object_reference, ciphertext_sha256, object_key_version,
        created_at, updated_at
    ) values (
        p_tenant, p_title, p_summary, p_client_reference, p_destination_country,
        p_document_type, p_next_action_due_at, p_retention_class, p_retain_until,
        p_object_reference, p_ciphertext_sha256, p_key_version, p_now, p_now
    ) returning id into new_case;
    event_payload := jsonb_build_object('status','intake','version',1);
    new_hash := apme_hash_case_event(null, p_tenant, new_case, 1, 'case.created', p_actor, p_now, event_payload);
    insert into apme_case_events(
        tenant_id, case_id, case_version, event_type, actor_shared_user_id,
        occurred_at, payload, previous_hash, event_hash
    ) values (p_tenant, new_case, 1, 'case.created', p_actor, p_now, event_payload, null, new_hash)
    returning apme_case_events.event_id into new_event;
    insert into apme_case_create_commands values
        (p_tenant, p_idempotency_key, p_request_hash, new_case, p_now);
    perform apme_append_audit(p_tenant, 'create', p_actor, 'case', new_case, p_now, event_payload);
    return query select new_case, 1::bigint, new_event, new_hash, false;
end;
$$;

create or replace function apme_transition_case(
    p_tenant uuid, p_actor text, p_case uuid, p_expected_version bigint,
    p_to_status text, p_idempotency_key text, p_request_hash bytea, p_now timestamptz
)
returns table(case_id uuid, case_version bigint, event_id uuid, event_hash bytea, replayed boolean)
language plpgsql as $$
declare
    selected_case apme_cases%rowtype;
    existing_command apme_case_transition_commands%rowtype;
    member_role text;
    prior_hash bytea;
    next_hash bytea;
    next_event uuid;
    event_payload jsonb;
begin
    select role into member_role from apme_tenant_memberships
     where tenant_id = p_tenant and shared_user_id = p_actor and active;
    if member_role is null or member_role not in ('agent','administrator') then
        raise exception 'APME_NOT_AUTHORIZED' using errcode = '42501';
    end if;
    perform pg_advisory_xact_lock(hashtextextended(p_tenant::text || ':' || p_idempotency_key, 3456));
    select * into existing_command from apme_case_transition_commands
     where tenant_id = p_tenant and idempotency_key = p_idempotency_key;
    if found then
        if existing_command.request_hash <> p_request_hash or existing_command.case_id <> p_case then
            raise exception 'APME_IDEMPOTENCY_CONFLICT' using errcode = '23505';
        end if;
        return query select p_case, existing_command.resulting_version, e.event_id, e.event_hash, true
          from apme_case_events e where e.case_id = p_case
           and e.case_version = existing_command.resulting_version;
        return;
    end if;
    select * into selected_case from apme_cases
     where id = p_case and tenant_id = p_tenant and tombstoned_at is null for update;
    if not found then raise exception 'APME_CASE_NOT_FOUND' using errcode = 'P0002'; end if;
    if selected_case.version <> p_expected_version then
        raise exception 'APME_STALE_VERSION' using errcode = '40001';
    end if;
    if not (
        (selected_case.status = 'intake' and p_to_status in ('collecting_documents','closed')) or
        (selected_case.status = 'collecting_documents' and p_to_status in ('review','closed')) or
        (selected_case.status = 'review' and p_to_status in ('collecting_documents','submitted','closed')) or
        (selected_case.status = 'submitted' and p_to_status in ('completed','closed')) or
        (selected_case.status = 'completed' and p_to_status = 'closed')
    ) then raise exception 'APME_INVALID_TRANSITION' using errcode = '22023'; end if;
    select e.event_hash into prior_hash from apme_case_events e
     where e.case_id = p_case and e.case_version = selected_case.version;
    event_payload := jsonb_build_object('from', selected_case.status, 'to', p_to_status,
                                        'version', selected_case.version + 1);
    next_hash := apme_hash_case_event(prior_hash, p_tenant, p_case, selected_case.version + 1,
                                     'case.transitioned', p_actor, p_now, event_payload);
    update apme_cases set status = p_to_status, version = version + 1, updated_at = p_now
     where id = p_case;
    insert into apme_case_events(
        tenant_id, case_id, case_version, event_type, actor_shared_user_id,
        occurred_at, payload, previous_hash, event_hash
    ) values (p_tenant, p_case, selected_case.version + 1, 'case.transitioned',
              p_actor, p_now, event_payload, prior_hash, next_hash)
    returning apme_case_events.event_id into next_event;
    insert into apme_case_transition_commands values
        (p_tenant, p_idempotency_key, p_request_hash, p_case, selected_case.version + 1, p_now);
    perform apme_append_audit(p_tenant, 'transition', p_actor, 'case', p_case, p_now, event_payload);
    return query select p_case, selected_case.version + 1, next_event, next_hash, false;
end;
$$;

create or replace function apme_rotate_case_object(
    p_tenant uuid, p_actor text, p_case uuid, p_expected_version bigint,
    p_idempotency_key text, p_request_hash bytea, p_object_reference text,
    p_ciphertext_sha256 text, p_key_version integer, p_now timestamptz
)
returns table(case_id uuid, case_version bigint, event_id uuid, event_hash bytea, replayed boolean)
language plpgsql as $$
declare
    selected_case apme_cases%rowtype;
    existing_command apme_case_object_commands%rowtype;
    member_role text;
    prior_hash bytea;
    next_hash bytea;
    next_event uuid;
    event_payload jsonb;
begin
    select role into member_role from apme_tenant_memberships
     where tenant_id = p_tenant and shared_user_id = p_actor and active;
    if member_role is distinct from 'administrator' then
        raise exception 'APME_NOT_AUTHORIZED' using errcode = '42501';
    end if;
    perform pg_advisory_xact_lock(hashtextextended(p_tenant::text || ':' || p_idempotency_key, 3457));
    select * into existing_command from apme_case_object_commands
     where tenant_id = p_tenant and idempotency_key = p_idempotency_key;
    if found then
        if existing_command.request_hash <> p_request_hash or existing_command.case_id <> p_case then
            raise exception 'APME_IDEMPOTENCY_CONFLICT' using errcode = '23505';
        end if;
        return query select p_case, existing_command.resulting_version, e.event_id, e.event_hash, true
          from apme_case_events e where e.case_id = p_case
           and e.case_version = existing_command.resulting_version;
        return;
    end if;
    select * into selected_case from apme_cases
     where id = p_case and tenant_id = p_tenant and tombstoned_at is null for update;
    if not found then raise exception 'APME_CASE_NOT_FOUND' using errcode = 'P0002'; end if;
    if selected_case.version <> p_expected_version then
        raise exception 'APME_STALE_VERSION' using errcode = '40001';
    end if;
    if selected_case.encrypted_object_reference is null then
        raise exception 'APME_CASE_OBJECT_NOT_FOUND' using errcode = 'P0002';
    end if;
    if p_key_version <= selected_case.object_key_version then
        raise exception 'APME_KEY_VERSION_ROLLBACK' using errcode = '22023';
    end if;
    select e.event_hash into prior_hash from apme_case_events e
     where e.case_id = p_case and e.case_version = selected_case.version;
    event_payload := jsonb_build_object(
        'old_ciphertext_sha256', selected_case.ciphertext_sha256,
        'new_ciphertext_sha256', p_ciphertext_sha256,
        'old_key_version', selected_case.object_key_version,
        'new_key_version', p_key_version,
        'version', selected_case.version + 1
    );
    next_hash := apme_hash_case_event(prior_hash, p_tenant, p_case, selected_case.version + 1,
                                     'case.document_key_rotated', p_actor, p_now, event_payload);
    update apme_cases set encrypted_object_reference = p_object_reference,
        ciphertext_sha256 = p_ciphertext_sha256, object_key_version = p_key_version,
        version = version + 1, updated_at = p_now
     where id = p_case;
    insert into apme_case_events(
        tenant_id, case_id, case_version, event_type, actor_shared_user_id,
        occurred_at, payload, previous_hash, event_hash
    ) values (p_tenant, p_case, selected_case.version + 1, 'case.document_key_rotated',
              p_actor, p_now, event_payload, prior_hash, next_hash)
    returning apme_case_events.event_id into next_event;
    insert into apme_case_object_commands values
        (p_tenant, p_idempotency_key, p_request_hash, p_case, selected_case.version + 1, p_now);
    perform apme_append_audit(p_tenant, 'key_rotation', p_actor, 'case', p_case, p_now, event_payload);
    return query select p_case, selected_case.version + 1, next_event, next_hash, false;
end;
$$;

create or replace function apme_verify_case_audit(p_case uuid)
returns boolean language sql stable as $$
    with ordered as (
        select e.*,
               lag(event_hash) over (order by case_version) as expected_previous
          from apme_case_events e where case_id = p_case
    ), checked as (
        select *, event_hash = apme_hash_case_event(
            previous_hash, tenant_id, case_id, case_version, event_type,
            actor_shared_user_id, occurred_at, payload
        ) and previous_hash is not distinct from expected_previous as valid
        from ordered
    )
    select coalesce(bool_and(valid), false)
       and min(case_version) = 1
       and count(*) = max(case_version)
       and max(case_version) = (select version from apme_cases where id = p_case)
      from checked;
$$;

create or replace function apme_verify_tenant_audit(p_tenant uuid)
returns boolean language sql stable as $$
    with ordered as (
        select r.*,
               lag(receipt_hash) over (order by sequence) as expected_previous
          from apme_audit_receipts r where tenant_id = p_tenant
    ), checked as (
        select *, receipt_hash = apme_hash_audit_receipt(
            previous_hash, tenant_id, sequence, action, actor_shared_user_id,
            resource_type, resource_id, occurred_at, details
        ) and previous_hash is not distinct from expected_previous as valid
          from ordered
    )
    select coalesce(bool_and(valid), false)
       and min(sequence) = 1
       and count(*) = max(sequence)
       and max(sequence) = (
           select sequence from apme_tenant_audit_heads where tenant_id = p_tenant
       )
       and (select receipt_hash from checked order by sequence desc limit 1) = (
           select receipt_hash from apme_tenant_audit_heads where tenant_id = p_tenant
       )
      from checked;
$$;

create or replace function apme_apply_retention(p_now timestamptz, p_actor text)
returns bigint language plpgsql as $$
declare
    selected_case apme_cases%rowtype;
    prior_hash bytea;
    next_hash bytea;
    event_payload jsonb;
    affected bigint := 0;
begin
    for selected_case in select * from apme_cases
     where retain_until <= p_now and not legal_hold and tombstoned_at is null for update
    loop
        select event_hash into prior_hash from apme_case_events
         where case_id = selected_case.id and case_version = selected_case.version;
        event_payload := jsonb_build_object('retention_class', selected_case.retention_class,
                                            'version', selected_case.version + 1);
        next_hash := apme_hash_case_event(prior_hash, selected_case.tenant_id, selected_case.id,
            selected_case.version + 1, 'case.deleted', p_actor, p_now, event_payload);
        update apme_cases set title = '[tombstoned]', summary = '', client_reference = '[tombstoned]',
            destination_country = '[tombstoned]', document_type = '[tombstoned]',
            next_action_due_at = null, encrypted_object_reference = null,
            ciphertext_sha256 = null, object_key_version = null, status = 'closed',
            tombstoned_at = p_now, version = version + 1, updated_at = p_now
         where id = selected_case.id;
        insert into apme_case_events(tenant_id, case_id, case_version, event_type,
            actor_shared_user_id, occurred_at, payload, previous_hash, event_hash)
        values (selected_case.tenant_id, selected_case.id, selected_case.version + 1,
            'case.deleted', p_actor, p_now, event_payload, prior_hash, next_hash);
        perform apme_append_audit(selected_case.tenant_id, 'deletion', p_actor, 'case',
            selected_case.id, p_now, event_payload);
        affected := affected + 1;
    end loop;
    return affected;
end;
$$;
