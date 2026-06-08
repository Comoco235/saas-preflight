-- Multi-tenant fixture schema. The agencies table, the agency_domains table, the
-- tenant_id column, and the subdomain column are all Lens 8 activation signals.
create table if not exists public.agencies (
  id uuid primary key default gen_random_uuid(),
  name text not null
);

create table if not exists public.agency_domains (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null,
  domain text not null unique,
  subdomain text,
  status text not null default 'pending'
);

create table if not exists public.reviews (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.agencies (id),
  body text not null
);

alter table public.agency_domains enable row level security;
alter table public.reviews enable row level security;
