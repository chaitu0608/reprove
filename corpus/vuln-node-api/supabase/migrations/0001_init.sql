-- Initial schema for Vibe Shop. Two classic mistakes in one file:
--   1. public.orders has RLS disabled entirely              → world-readable via anon key
--   2. public.profiles has a policy USING (true)            → RLS enabled but pointless

create table public.orders (
  id bigint primary key generated always as identity,
  user_id uuid references auth.users(id),
  item text not null,
  created_at timestamptz default now()
);
-- (nobody ever ran: alter table public.orders enable row level security)

create table public.profiles (
  id bigint primary key generated always as identity,
  user_id uuid references auth.users(id),
  display_name text,
  bio text
);

alter table public.profiles enable row level security;

create policy "profiles_select_all" on public.profiles
  for select using (true);

create policy "profiles_insert_any" on public.profiles
  for insert with check (true);
