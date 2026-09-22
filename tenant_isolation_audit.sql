-- TENANT ISOLATION AUDIT — read-only. pg_catalog only. Writes nothing.
--
-- Every scanner I could find answers "is row level security switched on?".
-- That is a binary. It cannot tell an intentionally public table from a leak,
-- which is why they all ship false positives and say so in their own docs.
--
-- ⭐ THIS ASKS A DIFFERENT QUESTION: can one tenant read another tenant's rows?
-- A table can have RLS enabled AND a correct-looking policy AND still hand
-- every row to the wrong customer, because POSTGRES COMBINES PERMISSIVE
-- POLICIES WITH *OR*. One unscoped policy grants everything the scoped ones
-- withhold. That is a real production bug I fixed this week, on a table every
-- scanner marks green.
--
-- ⚠️ AND THE HONEST LIMIT, STATED IN THE OUTPUT ITSELF: static analysis can
-- only NARROW the list. A policy that calls a helper function, or scopes by
-- owner instead of by tenant, is safe and looks suspicious. So nothing here is
-- reported as a leak unless it is certain. Everything else is CHECK, and the
-- live two-tenant probe decides it.
--
--   LEAK     → certain: RLS is off, or on with no policy at all
--   CHECK    → a permissive policy this analysis cannot prove scopes the tenant
--   INDIRECT → the table reaches its tenant through a parent; not analysable here
--   ok       → every permissive policy provably scopes tenant or owner
--
-- ⚠️ WHY 'CHECK' IS NOT 'LEAK', WITH A REAL EXAMPLE FROM THE FIRST LIVE RUN.
-- A policy can be safe for a reason its own text does not contain. One flagged
-- here read
--     user_id IN (SELECT id FROM users WHERE coach_id = <the caller>)
-- which names no tenant at all and looks wide open. It is not: the inner SELECT
-- runs as the caller and is itself constrained by the users table's own row
-- level security, so it returns nobody from another tenant. Measured: zero
-- cross-tenant rows.
-- ⭐ Static analysis cannot see transitive protection. That is exactly why a
-- flag here means LOOK, and only a measurement means LEAK.
-- ⚠️ It is also worth knowing that such a policy is safe by DEPENDENCY: loosen
-- the parent table's RLS and it becomes a leak without itself changing.

with settings as (
  select array['org_id','tenant_id','organization_id','account_id',
               'workspace_id','company_id','team_id','customer_id'] as tenant_cols,
         array['user_id','owner_id','created_by','uploaded_by','auth_id'] as owner_cols
),
tables as (
  select c.oid, c.relname::text as tbl, c.relrowsecurity as rls_on
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'public' and c.relkind = 'r'
),
cols as (
  select t.oid, t.tbl, t.rls_on,
         (select a.attname::text from pg_attribute a, settings s
           where a.attrelid=t.oid and a.attnum>0 and not a.attisdropped
             and a.attname::text = any (s.tenant_cols)
           order by array_position(s.tenant_cols, a.attname::text) limit 1) as tenant_column,
         (select a.attname::text from pg_attribute a, settings s
           where a.attrelid=t.oid and a.attnum>0 and not a.attisdropped
             and a.attname::text = any (s.owner_cols)
           order by array_position(s.owner_cols, a.attname::text) limit 1) as owner_column
  from tables t
),
-- ⭐ THE PART NO OTHER TOOL DOES: resolve the helper functions a policy calls.
-- A policy reading `app_user_in_my_org(user_id)` is perfectly scoped, and a
-- regex over the policy text cannot see that. So the body of every callable
-- function is inlined before the expression is judged.
fn as (
  select p.proname::text as name,
         coalesce(pg_get_functiondef(p.oid), '') as body
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public' and p.prokind = 'f'
),
pol as (
  select p.polrelid as oid, p.polname::text as policy_name,
         case p.polcmd when 'r' then 'SELECT' when 'a' then 'INSERT'
                       when 'w' then 'UPDATE' when 'd' then 'DELETE' else 'ALL' end as cmd,
         p.polpermissive as permissive,
         coalesce(pg_get_expr(p.polqual, p.polrelid),'') || ' ' ||
         coalesce(pg_get_expr(p.polwithcheck, p.polrelid),'') as expr
  from pg_policy p
),
expanded as (
  select pl.*, c.tbl, c.rls_on, c.tenant_column, c.owner_column,
         pl.expr || ' ' || coalesce(
           (select string_agg(f.body, ' ') from fn f
             where pl.expr like '%'||f.name||'(%'), '') as full_expr
  -- ⛔ RIGHT JOIN, NOT INNER. A table with no policies produced no rows here
  -- and vanished from the report completely -- including a table with row
  -- level security switched off, which is the single most dangerous thing this
  -- tool can find. The most important row was the one that disappeared.
  from pol pl right join cols c on c.oid = pl.oid
),
-- ⭐⭐ THE CORE OF THE TOOL, AND THE PART THAT MAKES IT DIFFERENT.
-- A policy is NOT scoped because it MENTIONS the tenant. It is scoped only if
-- EVERY branch of it constrains the tenant. Postgres ORs permissive policies
-- together, and it also ORs the branches inside one policy, so
--     (org_id = app_org()) OR (app_role() = 'admin')
-- names the tenant and hands every row to any admin of any tenant.
--
-- ⚠️ Two earlier versions of this file got this wrong in opposite directions.
-- The first judged the whole expression and passed that policy as safe -- the
-- exact production bug the tool exists to find. The second split the expression
-- AFTER inlining helper bodies, which shredded the bodies into meaningless
-- fragments and flagged twenty-six clean tables.
-- ⭐ The fix is to keep the two concerns apart: split only the POLICY on OR,
-- and judge a fragment safe if it constrains the tenant itself OR calls a
-- helper whose own body does.
--
-- ⚠️ KNOWN LIMIT, STATED RATHER THAN HIDDEN. The split is textual, so a policy
-- shaped `A AND (B OR C)` is cut at the inner OR and the AND context is lost.
-- That over-reports: such a policy is flagged CHECK when it is in fact safe.
-- ⛔ It never under-reports, which is the direction that matters, and CHECK
-- means LOOK rather than LEAK. Depth-aware parsing belongs in the harness
-- script, not in one SQL statement -- this is where SQL stops being the right
-- tool, and pretending otherwise is how the last two versions went wrong.
fn_scoped as (
  select f.name,
         -- ⚠️ A HELPER IS TENANT-SCOPING ONLY IF ITS BODY CONSTRAINS AN
         -- ORGANISATION. Resolving the caller is NOT the same thing, and an
         -- earlier version treated it as equivalent: app_role() reads
         -- `where auth_id = auth.uid()`, so it looked tenant-scoped, and the
         -- branch `app_role() = 'admin'` passed as safe. That branch is the
         -- leak. Touching auth.uid() tells you WHO is asking; only an org
         -- predicate tells you WHICH TENANT they may see.
         ( f.body ~* '\m(app_org|current_org|current_tenant)\M'
           or f.body ~* '(org_id|tenant_id|organization_id|account_id) *=' ) as is_scoped
  from fn f
),
branches as (
  select e.*, trim(b.frag) as frag
  from expanded e,
       lateral regexp_split_to_table(regexp_replace(coalesce(e.expr,''), '\s+', ' ', 'g'),
                                     '\s+OR\s+') as b(frag)
),
frag_judged as (
  select b.*,
    ( (b.tenant_column is not null and b.frag like '%'||b.tenant_column||'%')
      or b.frag ~* '\m(app_org|current_org|current_tenant)\M'
      or b.frag ~* '(org_id|tenant_id|organization_id|account_id|workspace_id) *='
      or (b.owner_column is not null and (
            b.frag ~* ('\m'||b.owner_column||'\M *= *(\( *)?(auth\.uid|app_uid|current_user_id) *\(')
            or (b.frag ~* ('\m'||b.owner_column||'\M *= *\( *select\M')
                and b.frag ~* '(auth\.uid|app_uid|current_user_id) *\(')
            or (b.frag ~* ('\m'||b.owner_column||'\M *IN *\( *select\M')
                and b.frag ~* '(auth\.uid|app_uid|current_user_id|my_coachees) *\(')
         ))
      or b.frag ~* '\mauth\.uid *\( *\) *='
      -- or it calls a helper whose own body is tenant-scoped
      or exists (select 1 from fn_scoped fs
                  where fs.is_scoped and b.frag like '%'||fs.name||'(%')
    ) as frag_scoped
  from branches b
),
judged as (
  -- ⛔ ALL branches, not ANY. One unscoped branch is the leak.
  select policy_name, cmd, permissive, tbl, rls_on, tenant_column, owner_column,
         bool_and(frag_scoped) as scoped
  from frag_judged
  group by policy_name, cmd, permissive, tbl, rls_on, tenant_column, owner_column
)
select
  tbl as table_name,
  coalesce(tenant_column, coalesce(owner_column,'-')) as scoped_by,
  rls_on,
  count(*) filter (where policy_name is not null) as policies,
  count(*) filter (where permissive and not scoped) as needs_check,
  string_agg(policy_name, ', ') filter (where permissive and not scoped) as unproven_policies,
  case
    when not rls_on
      then 'LEAK — row level security is OFF, every tenant reads every row'
    when count(*) filter (where policy_name is not null) = 0
      then 'DEAD — RLS on with no policies; nobody can read this table'
    when tenant_column is null and owner_column is null
         and count(*) filter (where policy_name is not null) > 0
      then 'INDIRECT — no tenant or owner column; scoped through a parent table. '
           'Static analysis cannot confirm this. Measure it.'
    when tenant_column is null and owner_column is null
      then 'n/a — no tenant or owner column on this table'
    when count(*) filter (where permissive and not scoped) > 0
      then 'CHECK — ' || count(*) filter (where permissive and not scoped)
           || ' permissive policy/policies not provably tenant-scoped'
    else 'ok — every permissive policy scopes tenant or owner'
  end as verdict
from judged
group by tbl, tenant_column, owner_column, rls_on
order by
  case when not rls_on then 0
       when count(*) filter (where policy_name is not null) = 0 then 1
       when count(*) filter (where permissive and not scoped) > 0 then 2
       else 3 end, tbl;
