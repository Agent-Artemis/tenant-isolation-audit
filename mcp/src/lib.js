// Pure logic. No MCP, no network, no database driver. Testable on its own.
//
// Originally drafted by Frank (Master-Brain 38da644). Three defects fixed here;
// each one has a named regression test in ../test.js.

/* 1. CREDENTIAL REFUSAL
   The product's promise is "no key to hand anybody". So this server does not
   merely avoid using a credential, it REFUSES the call when one is offered.
   Ignoring it silently would leave the secret sitting in a transcript.

   Order matters. Specific secrets come before host names, because the refusal
   names what it found and a password reported as "a project URL" sends the
   reader to rotate the wrong thing. That happened: PGPASSWORD on a line with a
   Supabase host was refused as "a Supabase project URL". */
const CREDENTIAL_PATTERNS = [
  // Secrets first.
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/,                        'a private key'],
  // No leading \b: there is no word boundary inside PGPASSWORD, which is the
  // most common way a Postgres password is ever written down.
  [/[A-Za-z_]*(?:password|passwd|pwd)\s*[=:]\s*\S+/i,            'a password'],
  [/\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}/,                'a JWT (anon or service-role key)'],
  [/\bsb_(?:secret|publishable)_[A-Za-z0-9_-]{10,}/,             'a Supabase API key'],
  [/\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{16,}/,          'an API secret key'],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}/,                             'a GitHub personal access token'],
  [/\bgh[posur]_[A-Za-z0-9]{20,}/,                               'a GitHub token'],
  // Then connection strings and the hosts they point at.
  [/\bpostgres(?:ql)?:\/\/[^\s"']+/i,                            'a Postgres connection string'],
  [/\bmysql:\/\/[^\s"']+/i,                                      'a MySQL connection string'],
  [/\bsslmode\s*=\s*\w+/i,                                       'connection parameters'],
  // .co OR .com: the pooler is *.pooler.supabase.com and a \b after "co"
  // excluded it, so a bare pooler host walked straight through.
  [/\b[A-Za-z0-9-]+\.(?:pooler\.)?supabase\.(?:com?|net|in)\b/i, 'a Supabase project host'],
  [/\bservice_role\b/i,                                          'a service-role reference'],
];

// Every match, not the first, so the refusal can name everything it saw.
export function findCredentials(input) {
  const text = typeof input === 'string' ? input : JSON.stringify(input ?? '');
  const found = [];
  for (const [re, what] of CREDENTIAL_PATTERNS) {
    if (re.test(text) && !found.includes(what)) found.push(what);
  }
  return found;
}

export function findCredential(input) {
  return findCredentials(input)[0] ?? null;
}

export function refusal(what) {
  const list = Array.isArray(what) ? what : [what];
  return {
    refused: true,
    offered: list,
    reason: `This server will not accept ${list.join(' and ')}. It never connects to a database, so a ` +
            `credential cannot help it and can only put your secret somewhere it does not belong.`,
    what_to_do: 'Run the SQL yourself against your own database and paste back only the result rows.',
    rotate_advice: 'If any of those values is real and was pasted into a transcript, treat it as disclosed and rotate it.',
  };
}

/* 2. VERDICTS
   These are the five the audit SQL emits. n/a is kept only so that output from
   an older copy of the SQL still parses; that branch was unreachable and has
   been deleted from the query.
   Nothing is called a leak on a guess. LEAK is only ever certainty. */
export const VERDICTS = {
  LEAK:     { severity: 1, certain: true,  means: 'Certain. Row level security is off, so every tenant reads every row.', action: 'Fix now.' },
  CHECK:    { severity: 2, certain: false, means: 'A permissive policy this analysis cannot prove scopes the tenant.', action: 'Look at it. This means LOOK, not LEAK.' },
  INDIRECT: { severity: 3, certain: false, means: 'Scoped through a parent table. Static analysis cannot confirm it.', action: 'Measure it with a real request.' },
  DEAD:     { severity: 4, certain: true,  means: 'RLS on with no policy at all, so nothing but the service role reads this table. Deliberate lock-down or a table that quietly stopped working; this cannot tell which.', action: 'Confirm nothing is supposed to be reading it.' },
  ok:       { severity: 5, certain: true,  means: 'Every permissive policy provably scopes tenant or owner.', action: 'None.' },
  'n/a':    { severity: 6, certain: true,  means: 'Legacy verdict from an older copy of the audit. No tenant or owner column on this table.', action: 'None, but re-run the current audit.' },
};

/* Separator-agnostic on purpose. The previous version split on whitespace and
   dashes, so renaming the output separator from "LEAK - x" to "LEAK: x" turned
   every row unrecognised, and the old headline then reported all clear. This
   matches the verdict name itself and only requires that a separator, rather
   than another word character, follows it. */
const KEYS = Object.keys(VERDICTS).sort((a, b) => b.length - a.length);
// The dash escapes are deliberate. Written as literal characters a mechanical
// "strip every em dash" pass over the repository would silently delete them and
// stop every verdict parsing, which by the rule above would then report clean.
const SEPARATOR = /[\s\u2014\u2013:;,.\-|]/;

export function parseVerdict(v) {
  if (typeof v !== 'string') return null;
  const t = v.trim();
  for (const k of KEYS) {
    if (t === k) return k;
    if (t.startsWith(k) && SEPARATOR.test(t[k.length])) return k;
  }
  return null;
}

/* 3. INTERPRETATION
   Takes the rows the caller ran themselves. Orders by certainty, never upgrades
   a CHECK into a LEAK, and says plainly what it cannot know.

   A SUMMARY THAT CANNOT SEE PART OF ITS INPUT IS NOT A SUMMARY. If any row is
   unrecognised this refuses to give an all-clear, because the previous version
   answered "No certain leak, and nothing this analysis could not prove." on
   rows it had not understood. That is the failure this whole tool exists to
   catch: an answer that looks clean and is not. */
export function interpret(rows) {
  if (!Array.isArray(rows) || rows.length === 0) {
    return { error: 'Expected an array of result rows from the audit query.' };
  }
  const out = rows.map((r) => {
    const key = parseVerdict(r.verdict);
    return {
      table: r.table_name ?? r.table ?? null,
      verdict: key,
      raw_verdict: r.verdict ?? null,
      scoped_by: r.scoped_by ?? null,
      rls_on: r.rls_on ?? null,
      policies: r.policies ?? null,
      needs_check: r.needs_check ?? null,
      unproven_policies: r.unproven_policies ?? null,
      ...(key ? VERDICTS[key] : {
        severity: 0, certain: false,
        means: 'Unrecognised verdict string. This interpreter does not know what it says.',
        action: 'Check which version of the audit produced this row.',
      }),
    };
  });
  // Unrecognised rows sort to the top, at severity 0, above a certain leak.
  out.sort((a, b) => a.severity - b.severity || String(a.table).localeCompare(String(b.table)));

  const count = (k) => out.filter((r) => r.verdict === k).length;
  const unrecognised = out.filter((r) => !r.verdict);
  const leaks = count('LEAK');
  const needsWork = count('CHECK') + count('INDIRECT');

  let headline;
  let incomplete = false;
  if (unrecognised.length > 0) {
    incomplete = true;
    headline =
      `INCOMPLETE. ${unrecognised.length} of ${out.length} row(s) carry a verdict this ` +
      `interpreter does not recognise, so no all-clear can be given. ` +
      (leaks > 0 ? `${leaks} certain leak(s) were found among the rows it could read. ` : '') +
      `Re-run with a matching version of the audit before drawing any conclusion.`;
  } else if (leaks > 0) {
    headline = `${leaks} table(s) are certainly readable across tenants.`;
  } else if (needsWork > 0) {
    headline = `No certain leak. ${needsWork} table(s) need a human or a measurement.`;
  } else {
    headline = 'No certain leak, and nothing this analysis could not prove.';
  }

  const limits = [
    'A CHECK is not a leak. It means this analysis could not prove the policy scopes the tenant.',
    'An INDIRECT cannot be settled statically at all. Only a real request settles it.',
    'A DEAD table cannot be told apart from an outage by reading policies. Confirm nothing is meant to read it.',
    'This reads the rows you pasted. It did not see your database and cannot confirm they are current.',
  ];
  if (incomplete) {
    limits.unshift('THIS RESULT IS NOT COMPLETE. Some rows were not understood and are listed first.');
  }

  return {
    complete: !incomplete,
    summary: {
      tables: out.length,
      unrecognised: unrecognised.length,
      LEAK: leaks, CHECK: count('CHECK'), INDIRECT: count('INDIRECT'),
      DEAD: count('DEAD'), ok: count('ok'), 'n/a': count('n/a'),
    },
    headline,
    limits,
    tables: out,
  };
}

/* 4. DRIFT
   Frank shipped a copy of the SQL with a sha256 beside it. A hash tells you the
   file moved; it does not tell you whether the move matters, and it has to be
   remembered. This reads the verdicts out of whatever SQL the server actually
   loaded and checks the interpreter knows all of them. A verdict the SQL can
   emit and this file cannot read is the drift that would matter, and it is the
   exact defect that shipped in the repo README. */
export function verdictsInSql(sql) {
  const m = /\n  case\n([\s\S]*?)\n  end as verdict/.exec(sql);
  if (!m) return null;
  const names = [];
  for (const lit of m[1].match(/(?:then|else)\s+'([^']+)'/g) ?? []) {
    const text = /'([^']+)'/.exec(lit)[1];
    const head = text.trim().split(SEPARATOR)[0];
    if (head && !names.includes(head)) names.push(head);
  }
  return names;
}

export function checkSqlParity(sql) {
  const emitted = verdictsInSql(sql);
  if (emitted === null) return { ok: false, reason: 'Could not find the verdict CASE in the audit SQL.' };
  const unknown = emitted.filter((v) => !Object.prototype.hasOwnProperty.call(VERDICTS, v));
  return unknown.length
    ? { ok: false, reason: `The audit SQL emits verdict(s) this interpreter cannot read: ${unknown.join(', ')}.`, emitted, unknown }
    : { ok: true, emitted };
}
