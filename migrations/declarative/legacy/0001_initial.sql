    create extension if not exists pgcrypto;

    create table if not exists cases (
        id uuid primary key default gen_random_uuid(),
        title text not null check (length(title) between 1 and 256),
        summary text not null default '' check (length(summary) <= 4000),
        client_reference text not null,
destination_country text not null,
document_type text not null,
next_action_due_at timestamptz null,
        status text not null default 'intake',
        created_at timestamptz not null default now(),
        updated_at timestamptz not null default now()
    );

    create index if not exists cases_status_created_idx
      on cases(status, created_at desc, id);

    alter table cases enable row level security;

    -- Production must replace this deny-by-default baseline with explicit
    -- tenant-scoped policies tied to authenticated subjects.
    drop policy if exists deny_anon_cases on cases;
    create policy deny_anon_cases on cases
      for all to anon using (false) with check (false);
