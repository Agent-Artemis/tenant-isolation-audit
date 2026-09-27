YOUR SCANNER SAYS THIS TABLE IS FINE. IT IS LEAKING.

I wrote a tool that checks whether one customer of a multi-tenant app can read another customer's rows. The first database I pointed it at was one I had personally fixed and personally proved was watertight, eight hours earlier.

It found twelve policies I had missed.

This is what it found, why every scanner on the market marks that table green, and why I did not catch it by reading the policies — because I had read them, carefully, that morning.

THE SHAPE

Postgres combines permissive policies with OR.

That sentence is in the documentation and everybody nods at it. Here is what it means when you have shipped a few dozen policies and stopped reading them one at a time.

A table has two policies on it. The first is correct:

    create policy reports_tenant_read on reports
      for select using (org_id = current_org());

The second was written months earlier, by someone reasonable, to let support staff help customers:

    create policy reports_admin_read on reports
      for select using (user_role() = 'admin');

Each policy is sensible on its own. Together they say: you may read this row if it belongs to your organisation, OR if you are an admin of any organisation at all. The second clause does not mention tenancy, so it does not constrain it. Every row, every tenant, to anyone holding that role.

And the part that makes it survive audits: row level security is enabled, and a policy exists, and one of the policies is genuinely correct. Ask any scanner whether RLS is on for this table and the honest answer is yes.

WHY I DID NOT SEE IT

I was fixing exactly this class of bug at the time. I went through the database methodically, found every policy that granted broad access, and bound each one to the caller's organisation. I measured the result: a second tenant's administrator could read zero rows belonging to the first. I wrote that number down and shipped it.

The number was true. It was also a statement about administrators.

The policies I had missed were not admin policies. They were a different role — a supervisor who sees the people assigned to them — and they resolved through a helper function that looked like this:

    create function my_assigned_users() returns setof uuid
    language sql security definer as $$
      select assigned_user_id from assignments
       where supervisor_id = current_user_id()
    $$;

No organisation test anywhere in it. Twelve policies across ten tables called that function. I had enumerated policies by searching for the text of the admin check, and these policies do not contain that text. My method was reasonable and it was shape-blind.

A supervisor-shaped leak is invisible to an admin-shaped test. My test was correct. My coverage was not, and the two produce an identical green result.

WHAT THE MEASUREMENT SAID

I built the second tenant inside a transaction I rolled back, linked one supervisor across the boundary — the exact configuration the product was about to ship — and counted.

Before the fix, that supervisor could read a four-figure number of rows belonging to a customer in a different organisation, from a single assignment. Task records, daily activity, goals, historical scores. After the fix, zero.

One function was wrong. Twelve policies inherited it. Nothing in any policy's own text was incorrect.

THREE THINGS THIS TAUGHT ME ABOUT TOOLS

A flag is not a finding. The first version of my own tool marked twenty tables as leaking. They were fine: their policies called helper functions, and a regular expression over policy text cannot see what a function body does. I was about to ship the exact failure I had spent a week criticising — a scanner that cries wolf at correct code. It now resolves function bodies before judging, and it reports CHECK where it cannot prove something, reserving LEAK for the cases that are certain.

For three versions, my tool could not do the thing its headline claims. It tested whether a policy referenced the organisation column. The leaking policy above references it — in the branch that works. So the tool read the policy at the top of this article and called it safe.

I did not find that by reading my own code. I found it by putting the leak back into a database and checking whether the tool noticed. It did not. A policy is safe only if every branch constrains the tenant, so each branch now gets split on OR and judged on its own.

If you take one thing from this article, let it be that rather than the Postgres trivia: a checker that has never been shown a failure is a checker with an unknown pass rate. Mine had been run dozens of times against clean databases and looked excellent.

The most dangerous table is the one that disappears. A later version joined tables to policies and quietly dropped every table that had no policies at all — including a table with row level security switched off, which is the worst thing the tool can find. It reported a clean sheet because the bad row was not in it. An empty result and a clean result look identical, and only one of them is good news.

WHAT TO DO ABOUT IT

Read your policies, per table, and ask of each branch separately: does this clause constrain which tenant may read the row? Not the policy as a whole — the branch. One clause that does not is the whole table.

Then stop reading and measure, because reading is what failed me. Create a second tenant in a transaction you roll back, give it one user per role shape you actually have — admin, supervisor, owner, group member — and count the rows each of them can reach that belong to somebody else.

The expected answer is a column of zeros. If you get a number instead, that is one customer reading another customer's data.

And write down which role shapes you tested, beside the zero. A zero with no scope attached is how I got here.

THE PART NOBODY PLANS FOR: THE CLEAN RESULT

Most databases come back clean. Mine did, on the second run — a column of zeros, and one leftover table of my own with security switched off that I deleted the same day.

A clean result on Tuesday proves nothing on Friday, and Friday is when somebody adds three tables. Policies barely change; schemas change constantly, and a new table with no policy is the most common way this breaks. The dangerous week is never the week you ran the check.

That is also why a quiet week has to arrive as an email rather than as silence. Silence and success are indistinguishable, and I have spent this month fixing software that reported success over writes that never happened.

RUN IT ON YOUR OWN DATABASE

The harness is free, open source and permanently ungated. There is no signup and no email wall. Run it as often as you like and never pay me anything.

    https://github.com/GREG_REPO_PLACEHOLDER

It runs read-only against your own database and prints one row per table. A column of zeros means no table is handing rows to the wrong tenant. A number instead of a zero means one customer can read another customer's data, and that line tells you which table.

Nothing leaves your database. The harness reads your schema and the shape of your policies. It never selects a row from one of your tables, and it never sends anything anywhere — you run it, you see the output, and if you never speak to me that is a perfectly good outcome.

IF YOU WANT MORE THAN THE TOOL

Two things you can buy, and both are work I do rather than data I hold.

249 dollars, once. I run the audit against your database, work out which of the findings actually matter and in what order to fix them, and write it up as a document you can hand to whoever asked you for it.

29 dollars a month. It runs every week on its own and watches the tables you add after the audit, which is where this usually breaks. You get the dated result by email, including the weeks when nothing happened — because a week with nothing wrong in it is the evidence, and nobody has that evidence, since nobody was checking on the quiet weeks.

To be plain about what that is, since it is the question I would ask: you are not buying your own data back. Your data never moves. You are buying a dated history that says isolation held, which is the thing a security questionnaire asks for and the thing almost nobody can produce.

THE ASK

Run the harness, then paste the output to me and I will tell you which of the findings actually matter.

The output contains no data from your tables. If it is a column of zeros I will say so and you will have lost five minutes.
