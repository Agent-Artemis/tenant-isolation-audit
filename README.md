# tenant-isolation-audit

**Can one customer of your app read another customer's rows?**

Every Postgres and Supabase security scanner I could find answers a different
question: *is row level security switched on?* That is a binary, it cannot tell
an intentionally public table from a leak, and the tools say so themselves —
they document their own false positives.

This asks the question you actually care about, and it is not the same one.
A table can have RLS enabled, a policy that looks right, **and still hand every
row to the wrong customer** — because Postgres combines permissive policies
with `OR`. One unscoped policy grants everything the scoped ones withhold.

## Run it

```bash
psql "$DATABASE_URL" -f tenant_isolation_audit.sql
```

Or paste it into the Supabase SQL editor.

- **Read-only.** It reads `pg_catalog` and nothing else.
- **No application data.** It never selects a row from one of your tables.
- **Nothing to install, no account, no key to hand anybody.**

## What you get

One row per table:

| verdict | meaning |
|---|---|
| `LEAK` | **Certain.** RLS is off, or on with no policy at all. |
| `CHECK` | A permissive policy that this analysis cannot prove scopes the tenant. **Look at it.** |
| `INDIRECT` | The table reaches its tenant through a parent table. Not analysable statically — measure it. |
| `ok` | Every permissive policy provably scopes tenant or owner. |

⛔ **Nothing is called a leak on a guess.** A flag means *look*, and only a
measurement means *leak*. That distinction is the whole difference between this
and a scanner that cries wolf at correct code.

## What it does that a regex cannot

- **Resolves helper functions.** A policy calling `is_member_of(org_id)` is
  perfectly scoped and looks unscoped to a text search. Function bodies are
  inlined before anything is judged.
- **Splits every policy on `OR` and requires all branches to hold.** A policy
  that *mentions* the tenant is not a policy that *constrains* it.
- **Reports tables that have no policies.** They are the most dangerous ones
  and they are the easiest to drop from a join by accident.

## Known limits, because you should not have to discover them

- The `OR` split is textual, so `A AND (B OR C)` loses its `AND` context and is
  **over**-reported as `CHECK`. It never under-reports.
- A policy can be safe for a reason its own text does not contain — a subquery
  constrained by another table's RLS, for instance. Static analysis cannot see
  transitive protection. That is why `CHECK` means look.
- It infers your tenant column by name (`org_id`, `tenant_id`, `account_id`…).
  If yours is called something else, add it to the list at the top.

## The story behind it

[Your scanner says this table is fine. It is leaking.](ARTICLE.md) is the write-up:
a tool that could not do the thing its headline claimed, found by forcing a
failure rather than admiring a clean run, and then pointed at a database its
author had certified eight hours earlier.

## The honest part

An early version of this tool passed the exact leaking policy in its own
documentation as safe, because it checked whether a policy *mentioned* the
tenant instead of whether every branch *constrained* it. It had been run
against clean databases dozens of times and looked excellent.

⭐ **It was only caught by putting a real leak back into a database and
checking whether the tool noticed.** It did not. A checker that has never been
shown a failure is a checker with an unknown pass rate — including this one, on
your schema. Force a leak and watch it fire before you trust it.

## Static analysis is where you start, not where you stop

The strongest check is not reading policies at all. Create a second tenant
inside a transaction you roll back, give it **one user per role shape you
actually have** — admin, supervisor, owner, group member — and count the rows
each can reach that belong to somebody else.

**The expected answer is a column of zeros**, and write down which role shapes
you tested beside it. A zero with no scope attached is how this tool's author
shipped a leak while believing he had proved isolation.

---

MIT licensed. Free forever, no signup, no email wall.
