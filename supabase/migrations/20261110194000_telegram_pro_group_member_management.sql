create or replace function public.tp_add_conversation_member(p_conversation_id uuid, p_username text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_actor uuid := auth.uid();
  v_target uuid;
begin
  if v_actor is null then raise exception 'Authentication required'; end if;
  select p.id into v_target from public.tp_profiles p
    where lower(p.username) = lower(trim(p_username)) limit 1;
  if v_target is null then raise exception 'User not found'; end if;
  if v_target = v_actor then raise exception 'You are already a member'; end if;
  if not exists (
    select 1 from public.tp_conversation_members m
    where m.conversation_id = p_conversation_id
      and m.user_id = v_actor
      and m.member_role in ('owner','admin')
  ) then raise exception 'Only space owners and admins can add members'; end if;
  if exists (
    select 1 from public.tp_user_blocks b
    where (b.blocker_id = v_actor and b.blocked_id = v_target)
       or (b.blocker_id = v_target and b.blocked_id = v_actor)
  ) then raise exception 'This member cannot be added'; end if;
  insert into public.tp_conversation_members(conversation_id,user_id,member_role)
  values (p_conversation_id,v_target,'member')
  on conflict do nothing;
end;
$$;
revoke all on function public.tp_add_conversation_member(uuid,text) from public, anon;
grant execute on function public.tp_add_conversation_member(uuid,text) to authenticated;