-- =====================================================================
-- Dashboard de Processos - Supabase
-- Cole tudo no SQL Editor e execute (ordem já organizada).
-- Perfis: 'admin' (edita) e 'viewer' (somente visualiza).
-- O dono (is_owner) é admin permanente e imutável.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------------------------------------------------------------------
-- 1. TABELAS
-- ---------------------------------------------------------------------
create table if not exists public.profiles (
  id         uuid primary key references auth.users(id) on delete cascade,
  email      text not null unique,
  nome       text not null,
  nasc       date,
  foto       text,
  role       text not null default 'viewer' check (role in ('admin','viewer')),
  is_owner   boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- só pode existir um dono
create unique index if not exists one_owner_only on public.profiles (is_owner) where is_owner;

create table if not exists public.processos (
  id         bigint generated always as identity primary key,
  nome       text not null,
  resp       text not null default '—',
  tipo       text not null default 'Processo',
  status     text not null default 'novo' check (status in ('novo','andamento','aguardando','concluido')),
  prazo      date not null,
  hora       time not null default '09:00',
  prog       int  not null default 0 check (prog between 0 and 100),
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists processos_prazo_idx on public.processos (prazo);

-- ---------------------------------------------------------------------
-- 2. FUNÇÕES AUXILIARES
-- ---------------------------------------------------------------------
create or replace function public.is_admin()
returns boolean
language sql stable security definer
set search_path = public
as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;

create or replace function public.touch_updated_at()
returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end $$;

drop trigger if exists trg_profiles_touch on public.profiles;
create trigger trg_profiles_touch before update on public.profiles
  for each row execute function public.touch_updated_at();

drop trigger if exists trg_processos_touch on public.processos;
create trigger trg_processos_touch before update on public.processos
  for each row execute function public.touch_updated_at();

-- cria o perfil automaticamente quando um login é criado (padrão: viewer)
create or replace function public.handle_new_user()
returns trigger
language plpgsql security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, nome)
  values (new.id, new.email,
          coalesce(nullif(new.raw_user_meta_data->>'nome',''), split_part(new.email,'@',1)))
  on conflict (id) do nothing;
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- ---------------------------------------------------------------------
-- 3. PROTEÇÃO DO DONO (imutável)
-- ---------------------------------------------------------------------
create or replace function public.protect_owner()
returns trigger language plpgsql as $$
begin
  if tg_op = 'DELETE' then
    if old.is_owner then raise exception 'O usuário dono não pode ser removido.'; end if;
    return old;
  end if;
  if old.is_owner and (new.role <> old.role or new.is_owner <> old.is_owner or new.email <> old.email) then
    raise exception 'O usuário dono é imutável.';
  end if;
  return new;
end $$;

drop trigger if exists trg_protect_owner_upd on public.profiles;
create trigger trg_protect_owner_upd before update on public.profiles
  for each row execute function public.protect_owner();

drop trigger if exists trg_protect_owner_del on public.profiles;
create trigger trg_protect_owner_del before delete on public.profiles
  for each row execute function public.protect_owner();

-- ---------------------------------------------------------------------
-- 4. RLS (segurança por linha)
-- ---------------------------------------------------------------------
alter table public.profiles  enable row level security;
alter table public.processos enable row level security;

-- profiles: cada um vê o próprio perfil; admin vê todos
drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles for select to authenticated
  using (id = auth.uid() or public.is_admin());

-- profiles: cada um edita só nome, nascimento e foto do próprio perfil
drop policy if exists profiles_update_self on public.profiles;
create policy profiles_update_self on public.profiles for update to authenticated
  using (id = auth.uid()) with check (id = auth.uid());

revoke update on public.profiles from authenticated, anon;
grant  update (nome, nasc, foto) on public.profiles to authenticated;
revoke insert, delete on public.profiles from authenticated, anon;

-- processos: todos os logados visualizam; só admin cria/edita/exclui
drop policy if exists processos_select on public.processos;
create policy processos_select on public.processos for select to authenticated using (true);

drop policy if exists processos_insert on public.processos;
create policy processos_insert on public.processos for insert to authenticated with check (public.is_admin());

drop policy if exists processos_update on public.processos;
create policy processos_update on public.processos for update to authenticated
  using (public.is_admin()) with check (public.is_admin());

drop policy if exists processos_delete on public.processos;
create policy processos_delete on public.processos for delete to authenticated using (public.is_admin());

revoke all on public.processos from anon;

-- ---------------------------------------------------------------------
-- 5. FUNÇÕES DE ADMINISTRAÇÃO (chamadas via supabase.rpc)
-- ---------------------------------------------------------------------

-- 5.1 Criar login (email + senha) - somente admin
create or replace function public.admin_create_user(
  p_email text, p_password text, p_nome text default null, p_admin boolean default false
) returns uuid
language plpgsql security definer
set search_path = public, extensions, auth
as $$
declare v_id uuid := gen_random_uuid(); v_email text := lower(trim(p_email));
begin
  if not public.is_admin() then raise exception 'Apenas administradores podem criar usuários.'; end if;
  if v_email !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then raise exception 'E-mail inválido.'; end if;
  if length(coalesce(p_password,'')) < 8 then raise exception 'A senha deve ter ao menos 8 caracteres.'; end if;
  if exists (select 1 from auth.users where lower(email) = v_email) then raise exception 'Este e-mail já está cadastrado.'; end if;

  insert into auth.users (
    instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
    raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
    confirmation_token, recovery_token, email_change, email_change_token_new
  ) values (
    '00000000-0000-0000-0000-000000000000', v_id, 'authenticated', 'authenticated', v_email,
    crypt(p_password, gen_salt('bf')), now(),
    '{"provider":"email","providers":["email"]}',
    jsonb_build_object('nome', coalesce(nullif(trim(p_nome),''), split_part(v_email,'@',1))),
    now(), now(), '', '', '', ''
  );

  insert into auth.identities (id, user_id, provider_id, provider, identity_data, last_sign_in_at, created_at, updated_at)
  values (gen_random_uuid(), v_id, v_id::text, 'email',
          jsonb_build_object('sub', v_id::text, 'email', v_email, 'email_verified', true),
          now(), now(), now());

  -- o trigger handle_new_user já criou o perfil como viewer
  if p_admin then update public.profiles set role = 'admin' where id = v_id; end if;
  return v_id;
end $$;

-- 5.2 Remover usuário - somente admin; nunca o dono, nunca a si mesmo
create or replace function public.admin_delete_user(p_id uuid)
returns void
language plpgsql security definer
set search_path = public, auth
as $$
begin
  if not public.is_admin() then raise exception 'Apenas administradores podem remover usuários.'; end if;
  if p_id = auth.uid() then raise exception 'Você não pode remover a si mesmo.'; end if;
  if exists (select 1 from public.profiles where id = p_id and is_owner) then
    raise exception 'O usuário dono não pode ser removido.';
  end if;
  delete from auth.users where id = p_id;   -- perfil sai em cascata
end $$;

-- 5.3 Dar ou retirar o selo de admin - nunca no dono
create or replace function public.admin_set_role(p_id uuid, p_admin boolean)
returns void
language plpgsql security definer
set search_path = public
as $$
begin
  if not public.is_admin() then raise exception 'Apenas administradores podem alterar permissões.'; end if;
  if exists (select 1 from public.profiles where id = p_id and is_owner) then
    raise exception 'O usuário dono é imutável.';
  end if;
  update public.profiles set role = case when p_admin then 'admin' else 'viewer' end where id = p_id;
end $$;

-- 5.4 Lista de usuários para a tela de administração
create or replace function public.admin_list_users()
returns table (id uuid, email text, nome text, role text, is_owner boolean, created_at timestamptz)
language plpgsql stable security definer
set search_path = public
as $$
begin
  if not public.is_admin() then raise exception 'Acesso negado.'; end if;
  return query select p.id, p.email, p.nome, p.role, p.is_owner, p.created_at
               from public.profiles p order by p.is_owner desc, p.created_at;
end $$;

-- permissões de execução
revoke execute on function public.admin_create_user(text,text,text,boolean) from public, anon;
revoke execute on function public.admin_delete_user(uuid)                   from public, anon;
revoke execute on function public.admin_set_role(uuid,boolean)              from public, anon;
revoke execute on function public.admin_list_users()                        from public, anon;
grant  execute on function public.admin_create_user(text,text,text,boolean) to authenticated;
grant  execute on function public.admin_delete_user(uuid)                   to authenticated;
grant  execute on function public.admin_set_role(uuid,boolean)              to authenticated;
grant  execute on function public.admin_list_users()                        to authenticated;

-- ---------------------------------------------------------------------
-- 6. DEFINIR VOCÊ COMO DONO (execute UMA vez)
-- Antes: crie seu login em Authentication > Users > Add user (marque "Auto Confirm").
-- Depois: troque o e-mail abaixo pelo seu e execute este bloco.
-- ---------------------------------------------------------------------
-- Cria o perfil de logins que já existiam antes deste script (ex.: o seu).
insert into public.profiles (id, email, nome)
select u.id, u.email, coalesce(nullif(u.raw_user_meta_data->>'nome',''), split_part(u.email,'@',1))
from auth.users u
where not exists (select 1 from public.profiles p where p.id = u.id);

do $$
declare v_email text := 'gabriel.marcondes@board.com.br';   -- <<< ALTERE AQUI (o mesmo e-mail do seu login)
begin
  if exists (select 1 from public.profiles where is_owner) then
    raise notice 'Já existe um dono definido. Nada foi alterado.';
  elsif not exists (select 1 from public.profiles where lower(email) = lower(v_email)) then
    raise exception 'Perfil não encontrado para %. Crie o login primeiro.', v_email;
  else
    update public.profiles set is_owner = true, role = 'admin' where lower(email) = lower(v_email);
    raise notice 'Dono definido: %', v_email;
  end if;
end $$;

-- ---------------------------------------------------------------------
-- 7. COMO USAR NO HTML (supabase-js)
-- ---------------------------------------------------------------------
-- Login ........ supabase.auth.signInWithPassword({ email, password })
-- Meu perfil ... supabase.from('profiles').select('*').eq('id', user.id).single()
-- Salvar perfil  supabase.from('profiles').update({ nome, nasc, foto }).eq('id', user.id)
-- Processos .... supabase.from('processos').select('*')            (todos veem)
--                supabase.from('processos').insert/update/delete   (só admin)
-- Usuários ..... supabase.rpc('admin_list_users')
--                supabase.rpc('admin_create_user', { p_email, p_password, p_nome, p_admin })
--                supabase.rpc('admin_set_role',    { p_id, p_admin })
--                supabase.rpc('admin_delete_user', { p_id })
-- Importante: no HTML use somente a chave "anon/publishable". NUNCA a service_role.
