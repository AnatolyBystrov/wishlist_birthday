-- Вишлист Анатолия: база для Supabase.
-- Как запустить: Supabase → SQL Editor → New query → вставь весь файл → Run.
-- В самом конце выведется admin_key: это ключ от панели именинника. Никому его не показывай.
-- Скрипт можно запускать повторно: данные и ключ не пропадут.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.items (
  id uuid primary key default gen_random_uuid(),
  title text not null check (char_length(title) between 1 and 120),
  price text not null default '' check (char_length(price) <= 40),
  link text not null default '' check (char_length(link) <= 600),
  note text not null default '' check (char_length(note) <= 400),
  level int not null default 2 check (level between 1 and 3),
  created_at timestamptz not null default now()
);

-- One claim per gift: the primary key makes double booking impossible even if two guests tap at once.
create table if not exists public.claims (
  item_id uuid primary key references public.items(id) on delete cascade,
  guest_name text not null check (char_length(guest_name) between 1 and 40),
  token_hash text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.settings (
  id int primary key default 1 check (id = 1),
  birthday date
);
insert into public.settings (id) values (1) on conflict (id) do nothing;

-- The owner key lives in a schema the public API cannot reach.
create schema if not exists private;
revoke all on schema private from public, anon, authenticated;
create table if not exists private.admin (
  id int primary key default 1 check (id = 1),
  key text not null
);
insert into private.admin (id, key)
values (1, encode(extensions.gen_random_bytes(16), 'hex'))
on conflict (id) do nothing;

-- Row level security: guests may only read gifts and settings; every write goes through the functions below.
alter table public.items enable row level security;
alter table public.claims enable row level security;
alter table public.settings enable row level security;

drop policy if exists items_read on public.items;
create policy items_read on public.items for select to anon, authenticated using (true);
drop policy if exists settings_read on public.settings;
create policy settings_read on public.settings for select to anon, authenticated using (true);

revoke insert, update, delete, truncate on public.items, public.settings from anon, authenticated;
-- Explicit read grants, so the script works even when Supabase does not expose new tables automatically.
grant usage on schema public to anon, authenticated;
grant select on public.items, public.settings to anon, authenticated;
revoke all on public.claims from anon, authenticated;

-- Who took what, without the secret token.
create or replace view public.claims_public as
  select item_id, guest_name, created_at from public.claims;
revoke all on public.claims_public from anon, authenticated;
grant select on public.claims_public to anon, authenticated;

create or replace function public.claim_item(p_item uuid, p_name text, p_token text)
returns text language plpgsql security definer set search_path = public, extensions as $$
declare
  n text := btrim(coalesce(p_name, ''));
  h text;
begin
  if char_length(n) < 1 or char_length(n) > 40 then raise exception 'name must be 1-40 characters'; end if;
  if char_length(coalesce(p_token, '')) < 16 then raise exception 'bad token'; end if;
  if not exists (select 1 from items where id = p_item) then return 'missing'; end if;
  h := encode(digest(p_token, 'sha256'), 'hex');
  insert into claims (item_id, guest_name, token_hash) values (p_item, n, h)
  on conflict (item_id) do nothing;
  if found then return 'ok'; end if;
  if exists (select 1 from claims where item_id = p_item and token_hash = h) then return 'ok'; end if;
  return 'taken';
end $$;

create or replace function public.unclaim_item(p_item uuid, p_token text)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
begin
  delete from claims where item_id = p_item and token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex');
  return found;
end $$;

create or replace function public.my_claims(p_token text)
returns table (item_id uuid) language sql stable security definer set search_path = public, extensions as $$
  select c.item_id from claims c where c.token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex');
$$;

create or replace function public.admin_check(p_key text)
returns boolean language sql stable security definer set search_path = private as $$
  select exists (select 1 from private.admin where key = p_key);
$$;

create or replace function public.admin_upsert_item(
  p_key text, p_id uuid, p_title text, p_price text, p_link text, p_note text, p_level int
) returns uuid language plpgsql security definer set search_path = public as $$
declare v uuid;
begin
  if not public.admin_check(p_key) then raise exception 'forbidden'; end if;
  if coalesce(p_link, '') <> '' and p_link !~* '^https?://' then raise exception 'link must start with http(s)://'; end if;
  if p_id is null then
    insert into items (title, price, link, note, level)
    values (btrim(p_title), coalesce(btrim(p_price), ''), coalesce(btrim(p_link), ''), coalesce(btrim(p_note), ''), coalesce(p_level, 2))
    returning id into v;
  else
    update items set title = btrim(p_title), price = coalesce(btrim(p_price), ''), link = coalesce(btrim(p_link), ''),
      note = coalesce(btrim(p_note), ''), level = coalesce(p_level, 2)
    where id = p_id returning id into v;
  end if;
  return v;
end $$;

create or replace function public.admin_delete_item(p_key text, p_id uuid)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.admin_check(p_key) then raise exception 'forbidden'; end if;
  delete from items where id = p_id;
end $$;

create or replace function public.admin_set_birthday(p_key text, p_birthday date)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.admin_check(p_key) then raise exception 'forbidden'; end if;
  update settings set birthday = p_birthday where id = 1;
end $$;

grant execute on function public.claim_item(uuid, text, text), public.unclaim_item(uuid, text), public.my_claims(text),
  public.admin_check(text), public.admin_upsert_item(text, uuid, text, text, text, text, int),
  public.admin_delete_item(text, uuid), public.admin_set_birthday(text, date)
  to anon, authenticated;

notify pgrst, 'reload schema';

-- Your owner key:
select key as admin_key from private.admin;
