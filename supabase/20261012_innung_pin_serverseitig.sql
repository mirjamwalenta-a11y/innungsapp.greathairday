-- ════════════════════════════════════════════════════════════
--  P0 — Innungs-App: PIN wird in der Datenbank geprüft, pin_hash nicht
--  mehr ohne Login lesbar. Projekt wrxlaltgtgkdomklgrlj.
--  Fund der wöchentlichen RLS-Prüfung (Mitarbeiterhandbuch, Issue #35),
--  bestätigt am 2026-10-12: innungs_trainerinnen war samt pin_hash
--  (MD5 einer 4-stelligen PIN) für anon lesbar → alle PINs in Sekunden
--  zurückrechenbar, Anmeldung als jede Trainerin möglich.
--
--  Neu:
--    * innung_login(kennung, pin): prüft serverseitig, liefert nur
--      id, name, kennung. Nach 5 Fehlversuchen je Kennung 15 Minuten Sperre
--      (gegen Durchprobieren aller 10 000 PINs über die Funktion).
--    * pin_hash ist für anon und authenticated nicht mehr lesbar (Spalten-
--      rechte); alle übrigen Spalten bleiben lesbar wie bisher. Setzen einer
--      neuen PIN durch die Organisatorin (UPDATE/INSERT) bleibt unverändert.
--    * Die PIN-Speicherung bleibt MD5 (bisherige PINs gelten weiter).
--
--  Reihenfolge: Innungs-App-Update mergen, dann diese Datei ausführen.
--  (Die alte App liest innungs_trainerinnen mit select=* und bräche nach
--  Abschnitt 3; die neue App fragt nur einzelne Spalten ab.)
--  Sicher mehrfach ausführbar. Eine Transaktion.
-- ════════════════════════════════════════════════════════════
begin;

do $pruef$
begin
  if to_regclass('public.innungs_trainerinnen') is null then
    raise exception 'Abbruch: innungs_trainerinnen fehlt – richtiges Supabase-Projekt?';
  end if;
  if not exists (select 1 from information_schema.columns
                  where table_schema = 'public' and table_name = 'innungs_trainerinnen' and column_name = 'pin_hash') then
    raise exception 'Abbruch: Spalte pin_hash fehlt – bitte Claude Bescheid geben.';
  end if;
end $pruef$;

-- ── 1. Fehlversuche (nur für die Login-Funktion, keine App liest sie) ──
create table if not exists public.innung_login_fehlversuche (
  kennung text        not null,
  zeit    timestamptz not null default now()
);
alter table public.innung_login_fehlversuche enable row level security;
revoke all on public.innung_login_fehlversuche from anon, authenticated;
create index if not exists innung_login_fehlversuche_kennung_zeit
  on public.innung_login_fehlversuche (kennung, zeit);

-- ── 2. Login-Funktion ───────────────────────────────────────────
create or replace function public.innung_login(p_kennung text, p_pin text)
returns table (id text, name text, kennung text)
language plpgsql
security definer
set search_path = public
as $$
declare
  k text := lower(trim(coalesce(p_kennung, '')));
begin
  delete from innung_login_fehlversuche f where f.zeit < now() - interval '1 day';
  if (select count(*) from innung_login_fehlversuche f
       where f.kennung = k and f.zeit > now() - interval '15 minutes') >= 5 then
    raise exception 'Zu viele Fehlversuche – bitte in 15 Minuten erneut versuchen';
  end if;
  return query
    select t.id::text, t.name::text, t.kennung::text
      from innungs_trainerinnen t
     where t.kennung = k
       and t.pin_hash = md5(coalesce(p_pin, ''))
       and t.aktiv is true;
  if not found then
    insert into innung_login_fehlversuche (kennung) values (k);
  end if;
end $$;

revoke all on function public.innung_login(text, text) from public;
grant execute on function public.innung_login(text, text) to anon, authenticated;

-- ── 3. pin_hash nicht mehr lesbar, alle anderen Spalten wie bisher ──
revoke select on public.innungs_trainerinnen from anon, authenticated;
do $spalten$
declare cols text;
begin
  select string_agg(quote_ident(column_name), ', ' order by ordinal_position) into cols
    from information_schema.columns
   where table_schema = 'public' and table_name = 'innungs_trainerinnen' and column_name <> 'pin_hash';
  execute format('grant select (%s) on public.innungs_trainerinnen to anon, authenticated', cols);
end $spalten$;

commit;

-- ── Kontrolle: erwartet pin_hash_oeffentlich = false, login_funktion = true ──
select
  has_column_privilege('anon', 'public.innungs_trainerinnen', 'pin_hash', 'SELECT') as pin_hash_oeffentlich,
  has_function_privilege('anon', 'public.innung_login(text, text)', 'EXECUTE')        as login_funktion;
