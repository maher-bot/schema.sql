-- ============================================================
-- تحصّله — قاعدة بيانات تسجيل التجار والمنتجات (Supabase)
-- شغّل هذا الملف كاملًا مرة واحدة من: SQL Editor ← New query ← Run
-- ============================================================

-- ---------- المشرفون (أنت وفريقك) ----------
create table if not exists public.admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
alter table public.admins enable row level security;
-- لا توجد سياسات على admins: لا أحد يقرأها أو يعدلها من الموقع، فقط من لوحة Supabase.

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.admins where user_id = auth.uid());
$$;

-- ---------- التجار ----------
do $$ begin
  create type public.merchant_status as enum ('pending', 'approved', 'rejected', 'suspended');
exception when duplicate_object then null; end $$;

create table if not exists public.merchants (
  id            uuid primary key references auth.users(id) on delete cascade,
  email         text not null,
  owner_name    text not null check (char_length(owner_name) between 2 and 80),
  store_name    text not null check (char_length(store_name) between 2 and 80),
  activity      text not null,
  city          text not null,
  district      text,
  phone         text not null check (phone ~ '^05[0-9]{8}$'),
  lat           double precision,
  lng           double precision,
  cr_number     text not null check (cr_number ~ '^[0-9]{10}$'),
  vat_registered boolean not null default true,
  vat_number    text check (vat_number is null or vat_number ~ '^3[0-9]{13}3$'),
  bank_name     text not null,
  iban          text not null check (iban ~ '^SA[0-9]{2}[0-9A-Z]{20}$'),
  national_address text check (national_address is null or national_address ~ '^[A-Z]{4}[0-9]{4}$'),  -- العنوان الوطني المختصر من سبل
  plan          text not null default 'free',
  next_plan     text not null default 'commission' check (next_plan in ('commission', 'monthly', 'yearly')),
  trial_started_at timestamptz,   -- بداية الأشهر الثلاثة المجانية (يوم الإطلاق للمشترين أو يوم التفعيل، أيهما أبعد)
  cr_path       text not null,
  vat_path      text,
  iban_path     text not null,
  status        public.merchant_status not null default 'pending',
  review_note   text,
  reviewed_at   timestamptz,
  submitted_at  timestamptz not null default now(),
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  constraint vat_required check (
    (vat_registered and vat_number is not null and vat_path is not null) or not vat_registered
  )
);
create index if not exists merchants_status_idx on public.merchants (status, submitted_at desc);

-- إضافات لاحقة (آمنة لو شغّلت الملف أكثر من مرة على قاعدة قائمة)
alter table public.merchants add column if not exists national_address text;
alter table public.merchants add column if not exists next_plan text not null default 'commission';
alter table public.merchants add column if not exists trial_started_at timestamptz;
alter table public.merchants alter column plan set default 'free';
alter table public.merchants drop constraint if exists merchants_plan_check;
alter table public.merchants add constraint merchants_plan_check check (plan in ('free', 'commission', 'monthly', 'yearly'));
alter table public.merchants drop constraint if exists merchants_national_address_check;
alter table public.merchants add constraint merchants_national_address_check
  check (national_address is null or national_address ~ '^[A-Z]{4}[0-9]{4}$');
alter table public.merchants drop constraint if exists merchants_next_plan_check;
alter table public.merchants add constraint merchants_next_plan_check check (next_plan in ('commission', 'monthly', 'yearly'));

-- يمنع التاجر من تغيير حالته بنفسه، ويعيد الطلب المرفوض للمراجعة عند تعديله
create or replace function public.merchants_guard()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  new.updated_at := now();
  if public.is_admin() then
    if tg_op = 'UPDATE' and new.status is distinct from old.status then
      new.reviewed_at := now();
    end if;
    -- الفترة المجانية تبدأ عند التفعيل إذا كانت خدمة المشتري مفتوحة، وإلا تبدأ يوم فتحها
    if new.status = 'approved' and new.plan = 'free' and new.trial_started_at is null and public.buyer_enabled() then
      new.trial_started_at := now();
    end if;
    return new;
  end if;

  if tg_op = 'INSERT' then
    new.status := 'pending';
    new.review_note := null;
    new.reviewed_at := null;
    new.submitted_at := now();
    new.trial_started_at := null;
    new.email := coalesce((select email from auth.users where id = auth.uid()), new.email);
  else
    new.id := old.id;
    new.email := old.email;
    new.created_at := old.created_at;
    new.reviewed_at := old.reviewed_at;
    new.review_note := old.review_note;
    new.trial_started_at := old.trial_started_at;
    if old.status = 'rejected' then
      new.status := 'pending';          -- أعاد الإرسال بعد الرفض
      new.submitted_at := now();
    else
      new.status := old.status;
      new.submitted_at := old.submitted_at;
    end if;
  end if;
  return new;
end $$;

drop trigger if exists merchants_guard on public.merchants;
create trigger merchants_guard before insert or update on public.merchants
  for each row execute function public.merchants_guard();

alter table public.merchants enable row level security;

drop policy if exists "merchant reads own" on public.merchants;
create policy "merchant reads own" on public.merchants for select
  using (id = auth.uid() or public.is_admin());

drop policy if exists "merchant registers self" on public.merchants;
create policy "merchant registers self" on public.merchants for insert
  with check (id = auth.uid());

-- التاجر يعدل طلبه فقط وهو قيد المراجعة أو مرفوض. بعد التفعيل التعديل عن طريقكم.
drop policy if exists "merchant edits while not approved" on public.merchants;
create policy "merchant edits while not approved" on public.merchants for update
  using (id = auth.uid() and status in ('pending', 'rejected'))
  with check (id = auth.uid());

drop policy if exists "admin updates merchants" on public.merchants;
create policy "admin updates merchants" on public.merchants for update
  using (public.is_admin()) with check (public.is_admin());

drop policy if exists "admin deletes merchants" on public.merchants;
create policy "admin deletes merchants" on public.merchants for delete
  using (public.is_admin());

create or replace function public.is_approved_merchant(mid uuid default auth.uid())
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.merchants where id = mid and status = 'approved');
$$;

-- ---------- مفاتيح الإطلاق ----------
-- المرحلة 1: جمع المحلات فقط. خدمة المشتري والمدفوعات مقفلة لين تفعّلها من لوحة الإدارة.
create table if not exists public.app_settings (
  id               boolean primary key default true check (id),   -- صف واحد فقط
  buyer_enabled    boolean not null default false,
  payments_enabled boolean not null default false,
  launch_city      text not null default 'مكة المكرمة',
  updated_at       timestamptz not null default now()
);
insert into public.app_settings (id) values (true) on conflict (id) do nothing;
alter table public.app_settings enable row level security;
drop policy if exists "everyone reads settings" on public.app_settings;
create policy "everyone reads settings" on public.app_settings for select using (true);
drop policy if exists "admin changes settings" on public.app_settings;
create policy "admin changes settings" on public.app_settings for update
  using (public.is_admin()) with check (public.is_admin());
grant select on public.app_settings to anon, authenticated;

create or replace function public.buyer_enabled()
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((select buyer_enabled from public.app_settings where id), false);
$$;

-- ---------- الباقة المجانية (3 أشهر) ----------
-- يوم فتح خدمة المشتري: تبدأ الأشهر الثلاثة لكل محل مفعّل على الباقة المجانية
create or replace function public.start_trials_on_launch()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.buyer_enabled and not old.buyer_enabled then
    update public.merchants set trial_started_at = now()
    where plan = 'free' and status = 'approved' and trial_started_at is null;
  end if;
  return new;
end $$;
drop trigger if exists start_trials_on_launch on public.app_settings;
create trigger start_trials_on_launch after update on public.app_settings
  for each row execute function public.start_trials_on_launch();

-- التاجر يختار باقته بعد الفترة المجانية (حتى بعد التفعيل)
create or replace function public.set_next_plan(p text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if p not in ('commission', 'monthly', 'yearly') then raise exception 'invalid plan'; end if;
  update public.merchants set next_plan = p where id = auth.uid();
end $$;
revoke execute on function public.set_next_plan(text) from anon;

-- ينقل من انتهت فترته المجانية إلى الباقة اللي اختارها. يشتغل يوميًا (راجع اقرأني).
create or replace function public.end_expired_trials()
returns integer language plpgsql security definer set search_path = public as $$
declare n integer;
begin
  update public.merchants set plan = next_plan
  where plan = 'free' and trial_started_at is not null and trial_started_at + interval '3 months' <= now();
  get diagnostics n = row_count;
  return n;
end $$;
revoke execute on function public.end_expired_trials() from anon, authenticated;

-- بيانات المحلات المفعّلة للعامة (بدون آيبان أو مستندات) لتطبيق المشترين لاحقًا
create or replace view public.stores_public with (security_invoker = false) as
  select id, store_name, activity, city, district, lat, lng
  from public.merchants where status = 'approved' and public.buyer_enabled();
grant select on public.stores_public to anon, authenticated;

-- ---------- المنتجات ----------
create table if not exists public.products (
  id           uuid primary key default gen_random_uuid(),
  merchant_id  uuid not null references public.merchants(id) on delete cascade default auth.uid(),
  name         text not null check (char_length(name) between 2 and 120),
  description  text check (description is null or char_length(description) <= 1000),
  category     text,
  barcode      text,
  price        numeric(10,2) not null check (price >= 0),
  sale_price   numeric(10,2) check (sale_price is null or (sale_price >= 0 and sale_price < price)),
  quantity     integer not null default 0 check (quantity >= 0),
  image_path   text,
  is_active    boolean not null default true,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);
create index if not exists products_merchant_idx on public.products (merchant_id, created_at desc);
create index if not exists products_name_idx on public.products (lower(name));

create or replace function public.touch_updated_at()
returns trigger language plpgsql as $$ begin new.updated_at := now(); return new; end $$;
drop trigger if exists products_touch on public.products;
create trigger products_touch before update on public.products
  for each row execute function public.touch_updated_at();

alter table public.products enable row level security;

drop policy if exists "public reads active products" on public.products;
create policy "public reads active products" on public.products for select
  using (
    merchant_id = auth.uid()
    or public.is_admin()
    or (is_active and public.is_approved_merchant(merchant_id) and public.buyer_enabled())
  );

drop policy if exists "approved merchant inserts" on public.products;
create policy "approved merchant inserts" on public.products for insert
  with check (merchant_id = auth.uid() and public.is_approved_merchant());

drop policy if exists "approved merchant updates" on public.products;
create policy "approved merchant updates" on public.products for update
  using (merchant_id = auth.uid() and public.is_approved_merchant())
  with check (merchant_id = auth.uid());

drop policy if exists "approved merchant deletes" on public.products;
create policy "approved merchant deletes" on public.products for delete
  using ((merchant_id = auth.uid() and public.is_approved_merchant()) or public.is_admin());

-- ---------- التخزين ----------
-- merchant-docs: خاص (السجل، الشهادة الضريبية، شهادة الآيبان). المسار: <user_id>/<file>
-- product-images: عام (صور المنتجات). المسار: <user_id>/<file>
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values
  ('merchant-docs', 'merchant-docs', false, 5242880, array['application/pdf', 'image/jpeg', 'image/png', 'image/webp']),
  ('product-images', 'product-images', true, 2097152, array['image/jpeg', 'image/png', 'image/webp'])
on conflict (id) do update set public = excluded.public,
  file_size_limit = excluded.file_size_limit, allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "docs: owner uploads" on storage.objects;
create policy "docs: owner uploads" on storage.objects for insert to authenticated
  with check (bucket_id = 'merchant-docs' and (storage.foldername(name))[1] = auth.uid()::text);

drop policy if exists "docs: owner or admin reads" on storage.objects;
create policy "docs: owner or admin reads" on storage.objects for select to authenticated
  using (bucket_id = 'merchant-docs' and ((storage.foldername(name))[1] = auth.uid()::text or public.is_admin()));

drop policy if exists "docs: owner replaces" on storage.objects;
create policy "docs: owner replaces" on storage.objects for update to authenticated
  using (bucket_id = 'merchant-docs' and (storage.foldername(name))[1] = auth.uid()::text);

drop policy if exists "images: approved merchant uploads" on storage.objects;
create policy "images: approved merchant uploads" on storage.objects for insert to authenticated
  with check (bucket_id = 'product-images' and (storage.foldername(name))[1] = auth.uid()::text
              and public.is_approved_merchant());

drop policy if exists "images: approved merchant updates" on storage.objects;
create policy "images: approved merchant updates" on storage.objects for update to authenticated
  using (bucket_id = 'product-images' and (storage.foldername(name))[1] = auth.uid()::text
         and public.is_approved_merchant());

drop policy if exists "images: owner deletes" on storage.objects;
create policy "images: owner deletes" on storage.objects for delete to authenticated
  using (bucket_id = 'product-images' and (storage.foldername(name))[1] = auth.uid()::text);


-- ---------- أرقام الجاهزية للإطلاق (للمشرف فقط) ----------
create or replace function public.launch_stats()
returns json language plpgsql stable security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'not allowed'; end if;
  return json_build_object(
    'by_status', (select coalesce(json_object_agg(status, n), '{}') from (select status, count(*) n from merchants group by status) x),
    'by_city', (select coalesce(json_agg(json_build_object('city', city, 'approved', a, 'pending', p, 'products', pr) order by a desc, p desc), '[]') from (
        select m.city,
               count(*) filter (where m.status = 'approved') a,
               count(*) filter (where m.status = 'pending') p,
               coalesce(sum((select count(*) from products pp where pp.merchant_id = m.id and pp.is_active)), 0) pr
        from merchants m group by m.city) c),
    'by_activity', (select coalesce(json_agg(json_build_object('activity', activity, 'n', n) order by n desc), '[]') from (
        select activity, count(*) n from merchants where status = 'approved' group by activity) a),
    'by_plan', (select coalesce(json_object_agg(plan, n), '{}') from (select plan, count(*) n from merchants where status = 'approved' group by plan) x),
    'products', (select count(*) from products where is_active),
    'stores_with_products', (select count(distinct merchant_id) from products where is_active),
    'last_7_days', (select count(*) from merchants where created_at > now() - interval '7 days')
  );
end $$;
revoke execute on function public.launch_stats() from anon;

-- ============================================================
-- بعد ما تسوي حسابك من Authentication ← Users ← Add user، شغّل هذا بإيميلك:
-- insert into public.admins (user_id) select id from auth.users where email = 'ضع-إيميلك-هنا';
-- ============================================================
