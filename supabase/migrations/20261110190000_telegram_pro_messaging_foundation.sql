-- Telegram Pro messaging foundation
-- Phone numbers are deliberately not stored in public.tp_profiles.
-- Supabase Auth owns the verified phone; the public profile contains only public identity fields.

create extension if not exists pgcrypto;

create table if not exists public.tp_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text unique,
  display_name text not null default 'Member',
  bio text not null default '',
  avatar_url text,
  phone_visibility text not null default 'nobody' check (phone_visibility in ('nobody','contacts','selected')),
  discoverable_by_phone boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint tp_username_format check (username is null or username ~ '^[A-Za-z0-9_]{3,24}$')
);

create table if not exists public.tp_conversations (
  id uuid primary key default gen_random_uuid(),
  kind text not null check (kind in ('direct','group','channel')),
  title text,
  created_by uuid not null references auth.users(id) on delete cascade,
  is_public boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists public.tp_conversation_members (
  conversation_id uuid not null references public.tp_conversations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  member_role text not null default 'member' check (member_role in ('owner','admin','member')),
  joined_at timestamptz not null default now(),
  primary key (conversation_id, user_id)
);

create table if not exists public.tp_messages (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.tp_conversations(id) on delete cascade,
  sender_id uuid not null references auth.users(id) on delete cascade,
  body text not null check (char_length(body) between 1 and 10000),
  created_at timestamptz not null default now(),
  edited_at timestamptz
);

create table if not exists public.tp_user_blocks (
  blocker_id uuid not null references auth.users(id) on delete cascade,
  blocked_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (blocker_id, blocked_id),
  check (blocker_id <> blocked_id)
);

create table if not exists public.tp_reports (
  id uuid primary key default gen_random_uuid(),
  reporter_id uuid not null references auth.users(id) on delete cascade,
  reported_user_id uuid references auth.users(id) on delete set null,
  conversation_id uuid references public.tp_conversations(id) on delete set null,
  message_id uuid references public.tp_messages(id) on delete set null,
  reason text not null check (char_length(reason) between 3 and 1000),
  status text not null default 'open' check (status in ('open','reviewing','resolved','dismissed')),
  created_at timestamptz not null default now()
);

create index if not exists tp_messages_conversation_created_idx on public.tp_messages(conversation_id, created_at desc);
create index if not exists tp_members_user_idx on public.tp_conversation_members(user_id);
create index if not exists tp_profiles_username_idx on public.tp_profiles(username);

alter table public.tp_profiles enable row level security;
alter table public.tp_conversations enable row level security;
alter table public.tp_conversation_members enable row level security;
alter table public.tp_messages enable row level security;
alter table public.tp_user_blocks enable row level security;
alter table public.tp_reports enable row level security;

create policy "tp profile public read" on public.tp_profiles for select to authenticated using (true);
create policy "tp profile self insert" on public.tp_profiles for insert to authenticated with check (id = (select auth.uid()));
create policy "tp profile self update" on public.tp_profiles for update to authenticated using (id = (select auth.uid())) with check (id = (select auth.uid()));

create policy "tp conversations visible to members or public" on public.tp_conversations for select to authenticated using (
  is_public = true or exists (select 1 from public.tp_conversation_members m where m.conversation_id = id and m.user_id = (select auth.uid()))
);
create policy "tp conversations create by creator" on public.tp_conversations for insert to authenticated with check (created_by = (select auth.uid()));

create policy "tp members read own membership" on public.tp_conversation_members for select to authenticated using (user_id = (select auth.uid()));
create policy "tp members self join public" on public.tp_conversation_members for insert to authenticated with check (
  user_id = (select auth.uid()) and exists (select 1 from public.tp_conversations c where c.id = conversation_id and (c.is_public = true or c.created_by = (select auth.uid())))
);
create policy "tp members leave self" on public.tp_conversation_members for delete to authenticated using (user_id = (select auth.uid()));

create policy "tp messages read by members" on public.tp_messages for select to authenticated using (
  exists (select 1 from public.tp_conversation_members m where m.conversation_id = conversation_id and m.user_id = (select auth.uid()))
);
create policy "tp messages send as self to member chat" on public.tp_messages for insert to authenticated with check (
  sender_id = (select auth.uid()) and exists (
    select 1 from public.tp_conversation_members m where m.conversation_id = conversation_id and m.user_id = (select auth.uid())
  ) and not exists (
    select 1 from public.tp_conversation_members m join public.tp_user_blocks b on b.blocker_id = m.user_id
    where m.conversation_id = conversation_id and b.blocked_id = (select auth.uid())
  )
);
create policy "tp messages edit own" on public.tp_messages for update to authenticated using (sender_id = (select auth.uid())) with check (sender_id = (select auth.uid()));
create policy "tp messages delete own" on public.tp_messages for delete to authenticated using (sender_id = (select auth.uid()));

create policy "tp blocks read own" on public.tp_user_blocks for select to authenticated using (blocker_id = (select auth.uid()));
create policy "tp blocks create own" on public.tp_user_blocks for insert to authenticated with check (blocker_id = (select auth.uid()));
create policy "tp blocks remove own" on public.tp_user_blocks for delete to authenticated using (blocker_id = (select auth.uid()));

create policy "tp reports submit own" on public.tp_reports for insert to authenticated with check (reporter_id = (select auth.uid()));
create policy "tp reports read own" on public.tp_reports for select to authenticated using (reporter_id = (select auth.uid()));

grant select, insert, update on public.tp_profiles to authenticated;
grant select, insert on public.tp_conversations to authenticated;
grant select, insert, delete on public.tp_conversation_members to authenticated;
grant select, insert, update, delete on public.tp_messages to authenticated;
grant select, insert, delete on public.tp_user_blocks to authenticated;
grant select, insert on public.tp_reports to authenticated;

create or replace function public.tp_create_profile_for_new_user()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  insert into public.tp_profiles (id, display_name)
  values (new.id, coalesce(nullif(new.raw_user_meta_data->>'display_name',''), 'Member'))
  on conflict (id) do nothing;
  return new;
end;
$$;
revoke all on function public.tp_create_profile_for_new_user() from public, anon, authenticated;
create trigger tp_auth_user_profile after insert on auth.users for each row execute function public.tp_create_profile_for_new_user();

create or replace function public.tp_add_creator_as_member()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  insert into public.tp_conversation_members (conversation_id, user_id, member_role)
  values (new.id, new.created_by, 'owner')
  on conflict do nothing;
  return new;
end;
$$;
revoke all on function public.tp_add_creator_as_member() from public, anon, authenticated;
create trigger tp_conversation_creator_member after insert on public.tp_conversations for each row execute function public.tp_add_creator_as_member();
