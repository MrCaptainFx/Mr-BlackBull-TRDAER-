-- Performance indexes for Telegram Pro messaging tables
create index if not exists tp_conversations_created_by_idx on public.tp_conversations(created_by);
create index if not exists tp_messages_sender_id_idx on public.tp_messages(sender_id);
create index if not exists tp_reports_reporter_id_idx on public.tp_reports(reporter_id);
create index if not exists tp_reports_reported_user_id_idx on public.tp_reports(reported_user_id);
create index if not exists tp_reports_conversation_id_idx on public.tp_reports(conversation_id);
create index if not exists tp_reports_message_id_idx on public.tp_reports(message_id);
create index if not exists tp_user_blocks_blocked_id_idx on public.tp_user_blocks(blocked_id);
