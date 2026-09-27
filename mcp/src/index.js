#!/usr/bin/env node
// MCP server for the tenant isolation audit.
//
// THE ONE RULE: this server never accepts a credential and never connects to
// anything. It has no database driver and makes no network call. The audit is
// run by the caller against their own database; this server only hands over the
// SQL and interprets rows the caller pastes back.
//
// Drafted by Frank (Master-Brain 38da644). Owned here because the trust claim
// above is this product's claim, so it has to be testable in this repository.
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { findCredentials, refusal, interpret, VERDICTS, checkSqlParity } from './lib.js';

const HERE = dirname(fileURLToPath(import.meta.url));

// THE SQL IS NOT COPIED. It is read from the one file in this repository that
// the audit itself ships, so the server cannot hand a customer a stale query.
// The draft kept a copy in src/ with a sha256 beside it, and it had already
// drifted by the time it was reviewed: the copy still contained a branch that
// had been deleted from the real file.
export const SQL_PATH = join(HERE, '..', '..', 'tenant_isolation_audit.sql');
let SQL;
try {
  SQL = readFileSync(SQL_PATH, 'utf8');
} catch (e) {
  console.error(`FATAL: cannot read the audit SQL at ${SQL_PATH}: ${e.message}`);
  process.exit(1);
}

// A verdict the SQL can emit and lib.js cannot read would make this server
// report on rows it does not understand. Refuse to start instead. This is the
// replacement for the hash: it checks the thing that matters rather than
// noticing that a byte changed.
const parity = checkSqlParity(SQL);
if (!parity.ok) {
  console.error(`FATAL: ${parity.reason}`);
  console.error('Update mcp/src/lib.js VERDICTS to match the audit, then run mcp/test.js.');
  process.exit(1);
}

const TOOLS = [
  {
    name: 'get_audit_sql',
    description:
      'Return the read-only tenant-isolation audit SQL. The caller runs it against their own ' +
      'database; nothing is sent anywhere. Reads pg_catalog only and never selects application rows.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'interpret_audit_results',
    description:
      'Interpret rows produced by the audit SQL. Input is the result rows only. ' +
      'Never send a connection string, key or password: this tool refuses them.',
    inputSchema: {
      type: 'object',
      properties: {
        rows: {
          type: 'array',
          description: 'Result rows, each with table_name, scoped_by, rls_on, policies, needs_check, unproven_policies, verdict.',
          items: { type: 'object' },
        },
      },
      required: ['rows'],
      additionalProperties: false,
    },
  },
  {
    name: 'explain_verdicts',
    description: 'Explain what each verdict means and, importantly, what it does not mean.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
];

const server = new Server(
  { name: 'io.github.agent-artemis/tenant-isolation-audit', version: '0.2.0' },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args = {} } = req.params;

  // Refuse before doing anything else, on EVERY tool, including the ones that
  // take no arguments. Refusing is louder than ignoring and that is the point.
  const offered = findCredentials(args);
  if (offered.length) {
    return {
      isError: true,
      content: [{ type: 'text', text: JSON.stringify(refusal(offered), null, 2) }],
    };
  }

  if (name === 'get_audit_sql') {
    return { content: [{ type: 'text', text: JSON.stringify({
      sql: SQL,
      how_to_run: 'psql "$DATABASE_URL" -f tenant_isolation_audit.sql, or paste it into the Supabase SQL editor.',
      guarantees: [
        'Read-only. It reads pg_catalog and nothing else.',
        'It never selects a row from one of your tables.',
        'Nothing to install, no account, and no key handed to anybody.',
      ],
      verdicts_it_can_return: parity.emitted,
      then: 'Paste the result rows into interpret_audit_results. Do not paste your connection string.',
    }, null, 2) }] };
  }

  if (name === 'interpret_audit_results') {
    return { content: [{ type: 'text', text: JSON.stringify(interpret(args.rows), null, 2) }] };
  }

  if (name === 'explain_verdicts') {
    return { content: [{ type: 'text', text: JSON.stringify({
      verdicts: VERDICTS,
      emitted_by_the_bundled_sql: parity.emitted,
      rule: 'Nothing is called a leak on a guess. LEAK is certainty; CHECK means look; INDIRECT means measure; DEAD means confirm nothing is reading it.',
    }, null, 2) }] };
  }

  return { isError: true, content: [{ type: 'text', text: `Unknown tool: ${name}` }] };
});

await server.connect(new StdioServerTransport());
