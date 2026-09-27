// Run with: node mcp/test.js   (no dependencies, does not need the MCP SDK)
//
// Frank's original 25 assertions are kept. The blocks marked DEFECT are
// regression tests for the three defects found in review; each one failed
// against the draft at Master-Brain 38da644.
import { findCredential, findCredentials, refusal, interpret, parseVerdict, VERDICTS, checkSqlParity } from './src/lib.js';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
let fail = 0, ran = 0;
const t = (name, pass) => { ran++; if (!pass) fail++; console.log((pass ? '  ok   ' : '  FAIL ') + name); };

console.log('CREDENTIAL REFUSAL');
t('postgres:// connection string', !!findCredential('postgres://u:p@h:5432/db'));
t('postgresql:// connection string', !!findCredential('postgresql://u:p@h/db'));
t('password= parameter', !!findCredential('host=h password=hunter2'));
t('sslmode parameter', !!findCredential('sslmode=require'));
t('service-role JWT', !!findCredential('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0'));
t('sb_secret key', !!findCredential('sb_secret_abcdefghijklmno'));
t('supabase project URL', !!findCredential('https://tbjynbevrhkfzpswehsj.supabase.co'));
t('private key block', !!findCredential('-----BEGIN RSA PRIVATE KEY-----'));
t('mysql:// connection string', !!findCredential('mysql://root:pw@127.0.0.1/app'));
t('clean result rows pass', findCredential([{ table_name: 'orders', verdict: 'ok - fine' }]) === null);
t('refusal names the value and advises rotation', (() => { const r = refusal('a password');
  return r.refused === true && /rotate/i.test(r.rotate_advice) && /paste back only the result rows/.test(r.what_to_do); })());

console.log('\nDEFECT 3: the refusal missed the commonest forms');
t('PGPASSWORD with no supabase host on the line', findCredential('PGPASSWORD=hunter2 psql -h localhost -U postgres') === 'a password');
t('PGPASSWORD is named a password, not a host', (() => {
  const all = findCredentials('PGPASSWORD=hunter2 psql -h db.abcd.supabase.co');
  return all[0] === 'a password' && all.includes('a Supabase project host'); })());
t('bare pooler host, which ends .com not .co', !!findCredential('host is aws-0-us-east-1.pooler.supabase.com'));
t('sk-proj- style key', !!findCredential('sk-proj-AbCdEf1234567890AbCdEf1234567890'));
t('legacy sk- key still caught', !!findCredential('sk-AbCdEf1234567890AbCdEf'));
t('github_pat_ token', !!findCredential('github_pat_11ABCDEFG0123456789abcdefghijklmnop'));
t('ghp_ token', !!findCredential('ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123'));
t('refusal lists every secret it saw', refusal(findCredentials('postgres://u:pw@h/db and sk-proj-AbCdEf1234567890AbCd')).offered.length >= 2);

console.log('\nDEFECT 3b: no false positives on legitimate audit output');
t('a policy named service_role_all is not a credential', findCredential({ rows: [{ table_name: 'orders', unproven_policies: 'service_role_all' }] }) === null);
t('a table named passwords is not a credential', findCredential({ rows: [{ table_name: 'passwords', verdict: 'ok - fine' }] }) === null);
t('a table named password_resets is not a credential', findCredential({ rows: [{ table_name: 'password_resets', verdict: 'LEAK - rls off' }] }) === null);
t('the current DEAD verdict text is not a credential', findCredential({ rows: [{ table_name: 'x',
  verdict: 'DEAD - RLS on with NO policy, so nothing but the service role can read it. Deliberate lock-down or a broken table; this cannot tell which.' }] }) === null);
t('a helper name in scoped_by is not a credential', findCredential({ rows: [{ table_name: 'y', scoped_by: 'is_org_member()' }] }) === null);

console.log('\nVERDICTS');
for (const v of ['LEAK', 'DEAD', 'INDIRECT', 'CHECK', 'ok', 'n/a']) t(`parses ${v} after an em dash`, parseVerdict(`${v} \u2014 text`) === v);
t('LEAK is the only certain bad one', VERDICTS.LEAK.certain === true && VERDICTS.CHECK.certain === false && VERDICTS.INDIRECT.certain === false);
t('unknown verdict is not silently dropped', (() => { const r = interpret([{ table_name: 'x', verdict: 'WAT' }]);
  return r.summary.unrecognised === 1 && r.tables[0].verdict === null; })());

console.log('\nDEFECT 2: the parser was coupled to the separator');
for (const v of ['LEAK', 'DEAD', 'INDIRECT', 'CHECK', 'ok']) t(`parses ${v} after a colon`, parseVerdict(`${v}: text`) === v);
t('parses a bare verdict with no separator at all', parseVerdict('ok') === 'ok');
t('parses after a pipe', parseVerdict('CHECK | 2 policies') === 'CHECK');
t('DEADLINE is not read as DEAD', parseVerdict('DEADLINE exceeded') === null);
t('okay is not read as ok', parseVerdict('okay then') === null);
t('a colon-separated report is not reported as clean', (() => {
  const r = interpret([{ table_name: 'a', verdict: 'LEAK: rls is off' }]);
  return r.summary.LEAK === 1 && r.summary.unrecognised === 0 && /certainly readable/.test(r.headline); })());

console.log('\nDEFECT 1: an unreadable answer was reported as clean');
t('unrecognised rows forbid an all-clear', (() => {
  const r = interpret([{ table_name: 'a', verdict: 'GIBBERISH x' }, { table_name: 'b', verdict: 'ALSO WRONG' }]);
  return r.complete === false && /^INCOMPLETE/.test(r.headline) && !/No certain leak/.test(r.headline); })());
t('the old wording can no longer appear alongside unrecognised rows', (() => {
  const r = interpret([{ table_name: 'a', verdict: 'GIBBERISH' }]);
  return !/nothing this analysis could not prove/.test(r.headline); })());
t('a leak found alongside unrecognised rows is still reported', (() => {
  const r = interpret([{ table_name: 'a', verdict: 'GIBBERISH' }, { table_name: 'b', verdict: 'LEAK - rls off' }]);
  return r.complete === false && /1 certain leak/.test(r.headline); })());
t('unrecognised rows sort above a certain leak', (() => {
  const r = interpret([{ table_name: 'b', verdict: 'LEAK - rls off' }, { table_name: 'a', verdict: 'GIBBERISH' }]);
  return r.tables[0].table === 'a' && r.tables[0].verdict === null; })());
t('limits lead with the incompleteness', (() => {
  const r = interpret([{ table_name: 'a', verdict: 'GIBBERISH' }]);
  return /NOT COMPLETE/.test(r.limits[0]); })());
t('a fully readable clean run still gets its all-clear', (() => {
  const r = interpret([{ table_name: 'a', verdict: 'ok - fine' }]);
  return r.complete === true && /nothing this analysis could not prove/.test(r.headline); })());

console.log('\nINTERPRETATION');
const r = interpret([
  { table_name: 'invoices', verdict: 'CHECK \u2014 2 permissive policy/policies not provably tenant-scoped' },
  { table_name: 'audit_log', verdict: 'LEAK \u2014 row level security is OFF, every tenant reads every row' },
  { table_name: 'lookup', verdict: 'n/a \u2014 no tenant or owner column on this table' },
  { table_name: 'attachments', verdict: 'INDIRECT \u2014 no tenant or owner column; scoped through a parent table.' },
]);
t('LEAK sorts first', r.tables[0].table === 'audit_log');
t('CHECK sorts above INDIRECT', r.tables[1].verdict === 'CHECK' && r.tables[2].verdict === 'INDIRECT');
t('counts are per verdict', r.summary.LEAK === 1 && r.summary.CHECK === 1 && r.summary.INDIRECT === 1 && r.summary['n/a'] === 1);
t('headline states certainty only for LEAK', r.headline.includes('certainly readable'));
t('limits say a CHECK is not a leak', r.limits.some((l) => /CHECK is not a leak/i.test(l)));
t('limits admit it never saw the database', r.limits.some((l) => /did not see your database/i.test(l)));
t('limits say DEAD cannot be told from an outage', r.limits.some((l) => /outage/i.test(l)));
t('empty input is an error, not an all-clear', !!interpret([]).error);
t('DEAD outranks ok', (() => {
  const o = interpret([{ table_name: 'z', verdict: 'ok - fine' }, { table_name: 'a', verdict: 'DEAD - no policy' }]);
  return o.tables[0].verdict === 'DEAD'; })());

console.log('\nDRIFT: the SQL is read from the repository, not copied');
const SQL = readFileSync(join(HERE, '..', 'tenant_isolation_audit.sql'), 'utf8');
const parity = checkSqlParity(SQL);
t('the shipped audit SQL parses into verdicts', Array.isArray(parity.emitted) && parity.emitted.length > 0);
t('every verdict the audit emits is known to this interpreter', parity.ok === true);
t('the audit emits exactly the five current verdicts', (() => {
  const e = [...(parity.emitted ?? [])].sort().join(',');
  return e === 'CHECK,DEAD,INDIRECT,LEAK,ok'; })());
t('parity FAILS when the SQL gains an unknown verdict', (() => {
  const doctored = SQL.replace("else 'ok", "else 'MAYBE");
  return checkSqlParity(doctored).ok === false; })());
t('parity FAILS when the verdict CASE cannot be found', checkSqlParity('select 1;').ok === false);

console.log('\nTHE TRUST CLAIM: it cannot connect to anything');
const pkg = JSON.parse(readFileSync(join(HERE, '..', 'package.json'), 'utf8'));
const deps = Object.keys({ ...pkg.dependencies, ...pkg.optionalDependencies });
const DRIVERS = ['pg', 'pg-native', 'postgres', 'mysql', 'mysql2', 'sqlite3', 'better-sqlite3', 'knex', 'sequelize', 'prisma', '@prisma/client', '@supabase/supabase-js', 'mongodb', 'tedious', 'oracledb', 'undici', 'axios', 'node-fetch', 'got'];
t('no database driver or http client in dependencies', !deps.some((d) => DRIVERS.includes(d)));
t('the only dependency is the MCP SDK', deps.length === 1 && deps[0] === '@modelcontextprotocol/sdk');
const srcText = ['src/lib.js', 'src/index.js'].map((f) => readFileSync(join(HERE, f), 'utf8')).join('\n');
t('no fetch, http or net call anywhere in src', !/\b(?:fetch\s*\(|require\s*\(\s*['"]node:?(?:https?|net|tls|dgram)|from\s+['"]node:(?:https?|net|tls|dgram))/.test(srcText));

console.log(fail ? `\n${fail} of ${ran} FAILED` : `\nALL ${ran} TESTS PASS`);
process.exit(fail ? 1 : 0);
