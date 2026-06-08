-- Single-tenant activation fixture.
-- A personal notes app: every row is owned by one user. No cross-account table,
-- no custom domains, no Host based routing. The Lens 8 gate must stay shut.
create table if not exists public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  body text not null,
  created_at timestamptz not null default now()
);

alter table public.notes enable row level security;

create policy "notes are owner scoped"
  on public.notes for all
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);
