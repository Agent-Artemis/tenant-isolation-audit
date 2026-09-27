# Row level security is on. Nobody can read the table. Which of those is the bug?

There is a state a Postgres table can be in that every scanner I have tried
reports as healthy, and that is either exactly what you intended or a silent
outage you have been running for months. The catalogue cannot tell you which.

The state is simple: **row level security is enabled and there are no policies at
all.**

## What actually happens

Enabling row level security with no policy does not open a table. It closes it.
Postgres denies by default and policies are the only thing that grants back, so
zero policies means zero rows for anybody the policies would have applied to.

Here it is on a live database, inside a transaction that was rolled back:

```
catalogue: relrowsecurity                  true
catalogue: policy count                    0
rows an authenticated tenant reads         0
rows anon reads                            0
rows the table owner reads                 3
```

Then one policy is added and nothing else changes:

```
policy count after adding ONE policy       1
rows an authenticated tenant reads now     3
```

## The line that matters is the third one from the bottom

**The table owner still reads all three rows.** So does anything connecting with
the service role, because it bypasses row level security by design.

That is the whole reason this survives. The person who built the table reads it
fine. The migration that created it reads it fine. A smoke test written by the
same person, using the same credentials, passes. The only people who see nothing
are your users, and they do not get an error. They get an empty list, a zero, a
dashboard panel that renders correctly and says there is no data.

An empty result and a clean result look identical, and only one of them is good
news.

## Why scanners call it healthy

Most row level security checks answer one question: is RLS switched on? That is a
boolean, and here the boolean is true. A table locked so hard that nothing can
read it scores exactly the same as a table with correct, well scoped policies.

The direction of that error is the bad one. A false alarm wastes an afternoon. A
false all-clear means nobody ever looks.

## And static analysis genuinely cannot settle it

This is the honest part, and it is why our audit reports this case as ambiguous
rather than pretending to judge it.

Both of these produce the identical catalogue state:

1. A table only your backend is ever supposed to touch, locked to the service
   role on purpose. Correct, deliberate, and exactly what you want.
2. A table whose policies were dropped in a migration, or never written because
   the pull request that added them was reverted, or written against a role name
   that was later renamed.

There is nothing in `pg_class`, `pg_policy` or anywhere else that records which
one you meant. Intent is not stored in the database. Any tool that tells you
confidently which of the two you are looking at is guessing, and it will be
wrong on a schedule.

So the audit returns `DEAD`, says in the output text that it cannot tell the
difference, and tells you what would settle it.

## The one question that settles it

**What is supposed to be reading this table?**

If the answer is "only the backend, with the service role", you are done, and it
is worth a comment on the table so the next person does not have to ask.

If the answer names a user, a role, a dashboard or a page, you have an outage,
and the measurement is short:

```sql
begin;
set local role authenticated;
set local request.jwt.claims = '{"sub":"<a real user id>","role":"authenticated"}';
select count(*) from your_table;
rollback;
```

A zero there, where the owner sees rows, is your answer. Do it inside a
transaction you roll back and it costs you nothing.

## What this cost us

Our own tool emitted this verdict for four days with no documentation. The SQL
could return six verdicts and the README explained four. `DEAD` was one of the
two missing, which made it the worst possible omission: a reader got a result
that looked like a finding, with nothing to look it up in, and no way to know
whether it was good news or a broken table.

It was found by a colleague reading the query and the README side by side and
counting. Not by a test, because there was no test. There is one now, and it
fails the build if the two files ever disagree again.

The verdict is documented, the output text states its own ambiguity so the
explanation travels with the result rather than only with the docs, and a branch
that turned out to be unreachable was deleted rather than described.

## The general version

A checker that has never been shown a failure is a checker with an unknown pass
rate. A summary that cannot see part of its input is not a summary. And a tool
that gives you a verdict your documentation does not explain has handed you the
same problem you bought it to solve: an answer that looks clean, and is not.

The audit is one read-only SQL file, MIT licensed, and it reads `pg_catalog`
only: <https://github.com/Agent-Artemis/tenant-isolation-audit>

If you want the output read by someone who will tell you which findings matter on
your schema, that part is at <https://tenantcheck.dev>.
