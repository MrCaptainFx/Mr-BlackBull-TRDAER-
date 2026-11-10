-- Enable realtime delivery and provide a safe username-based direct-chat entry point.
do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime'
      and schemaname = 'public'
      and tablename = 'tp_messages'
  ) then
    alter publication supabase_realtime add table public.tp_messages;
  end if;
end $$;

create or replace function public.tp_create_direct_conversation(p_username text)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_me uuid := auth.uid();
  v_other uuid;
  v_conversation uuid;
begin
  if v_me is null then raise exception 'Authentication required'; end if;
  if p_username is null or length(trim(p_username)) < 3 then raise exception 'Enter a valid username'; end if;
  select p.id into v_other from public.tp_profiles p
    where lower(p.username) = lower(trim(p_username)) limit 1;
  if v_other is null then raise exception 'User not found'; end if;
  if v_other = v_me then raise exception 'You cannot start a chat with yourself'; end if;
  if exists (
    select 1 from public.tp_user_blocks b
    where (b.blocker_id = v_me and b.blocked_id = v_other)
       or (b.blocker_id = v_other and b.blocked_id = v_me)
  ) then raise exception 'This conversation is unavailable'; end if;
  select c.id into v_conversation
    from public.tp_conversations c
    join public.tp_conversation_members a on a.conversation_id = c.id and a.user_id = v_me
    join public.tp_conversation_members b on b.conversation_id = c.id and b.user_id = v_other
    where c.kind = 'direct' limit 1;
  if v_conversation is not null then return v_conversation; end if;
  insert into public.tp_conversations(kind, created_by, is_public)
    values ('direct', v_me, false) returning id into v_conversation;
  insert into public.tp_conversation_members(conversation_id, user_id, member_role)
    values (v_conversation, v_other, 'member');
  return v_conversation;
end;
$$;
revoke all on function public.tp_create_direct_conversation(text) from public, anon;
grant execute on function public.tp_create_direct_conversation(text) to authenticated;