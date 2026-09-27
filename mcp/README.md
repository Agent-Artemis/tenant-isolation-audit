# MCP server for the tenant isolation audit

Lets an agent get the audit SQL and have the results interpreted, without a
credential ever changing hands.

## Why it does not take a DATABASE_URL

The obvious wrapper would accept a connection string and run the query for you.
That would contradict the sentence this product is sold on: read-only, nothing
to install, no account, and no key handed to anybody.

So this server hands over the SQL, you run it against your own database, and you
paste back the result rows. It interprets those. The credential never moves,
because there is nowhere for it to move to.

**The guarantee is structural, not a promise.** There is no database driver and no
HTTP client in this package. The only dependency is the MCP SDK. `mcp/test.js`
asserts that, asserts no driver appears transitively, and asserts that no `fetch`,
`http`, `net` or `tls` call exists anywhere in `mcp/src`. It cannot connect to
anything even if it tried to.

## It refuses credentials rather than ignoring them

A connection string in a tool call is already in a transcript, so staying quiet
would be the wrong answer. Every tool call is checked, including the two that take
no arguments, and the refusal names what was offered and says to rotate it.

Covered: Postgres and MySQL connection strings, libpq keyword forms, `PGPASSWORD`
and other prefixed password variables, JWTs, `sb_secret_` and `sb_publishable_`
keys, `sk-` and `sk-proj-` keys, `github_pat_` and `ghp_` tokens, PEM private keys,
Supabase project hosts including `*.pooler.supabase.com`, and `service_role`
references.

It does not fire on legitimate audit output. A policy named `service_role_all`, a
table named `passwords` or `password_resets`, and the verdict text itself all pass
through, and there are tests for each.

## Tools

| tool | does |
|---|---|
| `get_audit_sql` | returns the SQL, the guarantees, and the verdicts it can produce |
| `interpret_audit_results` | takes result rows, orders them by certainty, says what it cannot know |
| `explain_verdicts` | what each verdict means, and what it does not mean |

## It will not report clean on an answer it could not read

If any row carries a verdict this interpreter does not recognise, the headline
says `INCOMPLETE`, names how many rows it could not read, and gives no all-clear.
Those rows sort above a certain leak, and `complete` is `false`.

This matters because the opposite behaviour is the exact failure the audit exists
to catch. An earlier version of this file answered "No certain leak, and nothing
this analysis could not prove." on rows it had not understood. An agent asks one
question, gets one sentence, and the sentence says fine.

## The SQL is not copied

`mcp/src/index.js` reads `tenant_isolation_audit.sql` from the root of this
repository. There is no second copy to fall out of date.

An earlier draft kept a copy under `mcp/src/` with a sha256 beside it, and the copy
had already drifted by the time anyone looked: it still contained a verdict branch
that had been deleted from the real file. A file that cannot drift beats a file
that reports drifting.

On top of that, the server checks at startup that every verdict the SQL can emit
is one the interpreter knows, and **refuses to start** if not. Run it against a
doctored query and it exits 1 with the offending verdict named. That check is a
test as well, so it runs without starting the server.

## Run it

```bash
node mcp/test.js        # 65 assertions, no dependencies, does not need the SDK
npm install && node mcp/src/index.js
```

## Not published

Listing on a registry needs namespace ownership through GitHub OAuth or DNS on a
domain we control, which needs a person. Two of the four registries tested during
review are not usable: Glama returns 401 and PulseMCP's API returns 410 Gone.
`server.json` in the repository root is ready for the day that changes.

## Credit

Drafted by Frank, including the decision to refuse credentials rather than accept
them, which is the part that made it worth keeping. Reviewed, fixed and owned here
because the trust claim above is this product's claim.
