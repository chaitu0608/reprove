-- Hardened schema: RLS enabled with owner-scoped policies on every table.

create table public.orders (
  id bigint primary key generated always as identity,
  user_id uuid references auth.users(id),
  item text not null,
  created_at timestamptz default now()
);

alter table public.orders enable row level security;

create policy "orders_select_own" on public.orders
  for select using (auth.uid() = user_id);
create policy "orders_insert_own" on public.orders
  for insert with check (auth.uid() = user_id);
create policy "orders_update_own" on public.orders
  for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "orders_delete_own" on public.orders
  for delete using (auth.uid() = user_id);

create table public.profiles (
  id bigint primary key generated always as identity,
  user_id uuid references auth.users(id),
  display_name text,
  bio text
);

alter table public.profiles enable row level security;

create policy "profiles_select_own" on public.profiles
  for select using (auth.uid() = user_id);
create policy "profiles_write_own" on public.profiles
  for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
