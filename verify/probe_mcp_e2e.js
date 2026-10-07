#!/usr/bin/env node
/**
 * End-to-end acceptance for the Entra path of the todo0 MCP plane. Runs INSIDE the container.
 *
 *   ROPC sign-in as the test user    ->  access token audienced at agent0
 *   On-Behalf-Of exchange            ->  access token audienced at todo0 with the mcp:* scopes
 *   POST /mcp initialize             ->  an MCP session, authenticated as that user
 *   tools/call create-todo           ->  a row written under the userId the MCP server derives
 *   tools/call get-todos             ->  the same row read back
 *   controls: no Authorization header, and a zia-egress-audienced token -> both must be 401
 *
 * ROPC (the password grant) is for a cloud-only TEST user only — see verify/probe_obo.py.
 * Reads the client id, secret, tenant and scopes from the container's OWN mounted env files, so it
 * measures the configuration actually mounted. The test user's credentials arrive on STDIN as
 * KEY=value lines (TEST_USER_UPN, TEST_USER_PASSWORD) and never touch disk or argv. Prints claims,
 * lengths and status codes only — never a token, secret or password.
 *
 *   docker cp verify/probe_mcp_e2e.js ai-agent-entra-zscaler:/tmp/probe.js
 *   docker exec -i ai-agent-entra-zscaler node /tmp/probe.js < entra-setup/out/test-user.env
 */

const fs = require('fs');

const MCP_URL = 'http://127.0.0.1:5002/mcp';

function envFile(p) {
  const out = {};
  for (const line of fs.readFileSync(p, 'utf8').split('\n')) {
    const m = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (m) out[m[1]] = m[2];
  }
  return out;
}

function readStdin() {
  try {
    return fs.readFileSync(0, 'utf8');
  } catch {
    return '';
  }
}

// Claims only. `atob` on the payload segment - no verification, this is for reporting, and the MCP
// server is the thing actually verifying.
function claims(jwt) {
  const p = jwt.split('.')[1];
  return JSON.parse(Buffer.from(p.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString());
}

let failures = 0;
function check(label, ok, detail) {
  console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${label}${ok || detail === undefined ? '' : '   <- ' + detail}`);
  if (!ok) failures++;
}

async function form(url, params) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params).toString(),
  });
  const body = await res.text();
  let json = null;
  try { json = JSON.parse(body); } catch { /* reported by status below */ }
  return { status: res.status, json, body };
}

// The MCP server answers a JSON-RPC POST either as application/json or as a single SSE event,
// depending on the transport's mood. Parse both rather than assuming one.
function parseRpc(body) {
  const t = body.trim();
  if (t.startsWith('{')) return JSON.parse(t);
  const line = t.split('\n').find(l => l.startsWith('data:'));
  return line ? JSON.parse(line.slice(5).trim()) : null;
}

async function rpc(token, sessionId, payload) {
  const headers = {
    'Content-Type': 'application/json',
    Accept: 'application/json, text/event-stream',
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (sessionId) headers['mcp-session-id'] = sessionId;
  const res = await fetch(MCP_URL, { method: 'POST', headers, body: JSON.stringify(payload) });
  const body = await res.text();
  return { status: res.status, sessionId: res.headers.get('mcp-session-id'), body };
}

async function main() {
  const app = envFile('/app/packages/agent0/.env.app');
  const agent = envFile('/app/packages/agent0/.env.agent');
  const stdin = {};
  for (const line of readStdin().split('\n')) {
    const m = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (m) stdin[m[1]] = m[2];
  }

  const tenant = app.ENTRA_TENANT_ID;
  const clientId = app.OKTA_CLIENT_ID;
  const clientSecret = app.OKTA_CLIENT_SECRET;
  const loginScopes = app.IDP_LOGIN_SCOPES;
  const todoScopes = agent.ENTRA_TODO0_SCOPES;
  const user = stdin.TEST_USER_UPN;
  const password = stdin.TEST_USER_PASSWORD;

  console.log('configuration read from the MOUNTED env files (values withheld)');
  check(`tenant ${tenant}`, !!tenant);
  check(`agent0 client id ${clientId}`, !!clientId);
  check(`agent0 client secret present (${(clientSecret || '').length} chars)`, !!clientSecret);
  check(`login scopes: ${loginScopes}`, !!loginScopes);
  check(`todo0 scopes: ${todoScopes}`, !!todoScopes);
  check(`test user ${user} from stdin`, !!user);
  check(`test-user password present (${(password || '').length} chars)`, !!password);
  if (failures) { console.log('\nconfiguration incomplete - nothing further attempted'); return 1; }

  const tokenUrl = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`;

  console.log('\n1. ROPC: the user logs in headlessly, as verify/probe_obo.py does');
  const leg1 = await form(tokenUrl, {
    grant_type: 'password',
    client_id: clientId,
    client_secret: clientSecret,
    scope: loginScopes,
    username: user,
    password,
  });
  check(`HTTP ${leg1.status}`, leg1.status === 200,
        leg1.json ? `${leg1.json.error}: ${(leg1.json.error_description || '').split('\n')[0]}` : leg1.body.slice(0, 200));
  if (leg1.status !== 200) return 1;
  const userToken = leg1.json.access_token;
  const c1 = claims(userToken);
  check(`aud ${c1.aud} is agent0 itself, so it can be the OBO assertion`, c1.aud === clientId, c1.aud);
  check(`scp ${c1.scp}`, !!c1.scp);
  check(`preferred_username ${c1.preferred_username}`, !!c1.preferred_username);
  check('a refresh token was issued (offline_access)', !!leg1.json.refresh_token);

  console.log('\n2. OBO: agent0 exchanges it for a token audienced at todo0');
  const leg2 = await form(tokenUrl, {
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    client_id: clientId,
    client_secret: clientSecret,
    assertion: userToken,
    scope: todoScopes,
    requested_token_use: 'on_behalf_of',
  });
  check(`HTTP ${leg2.status}`, leg2.status === 200,
        leg2.json ? `${leg2.json.error}: ${(leg2.json.error_description || '').split('\n')[0]}` : leg2.body.slice(0, 200));
  if (leg2.status !== 200) return 1;
  const mcpToken = leg2.json.access_token;
  const c2 = claims(mcpToken);
  const mcp = envFile('/app/packages/todo0/.env.mcp');
  check(`aud ${c2.aud} equals MCP_EXPECTED_AUDIENCE`, c2.aud === mcp.MCP_EXPECTED_AUDIENCE,
        `${c2.aud} vs ${mcp.MCP_EXPECTED_AUDIENCE}`);
  check(`iss ${c2.iss} equals MCP_OKTA_ISSUER`, c2.iss === mcp.MCP_OKTA_ISSUER,
        `${c2.iss} vs ${mcp.MCP_OKTA_ISSUER}`);
  check(`scp "${c2.scp}" carries all three mcp: scopes`,
        ['mcp:connect', 'mcp:tools:read', 'mcp:tools:manage'].every(s => (c2.scp || '').split(' ').includes(s)),
        c2.scp);
  check(`oid ${c2.oid} is the stable object id the MCP door keys on`, !!c2.oid);
  check(`sub ${c2.sub} is PAIRWISE and differs from oid - why todo0 keys users on oid`,
        !!c2.sub && c2.sub !== c2.oid, `${c2.sub} vs ${c2.oid}`);
  check('there is no `uid` claim, so requireMcpAuth falls through to `oid`', c2.uid === undefined, c2.uid);

  console.log('\n3. control FIRST: an unauthenticated POST must be refused');
  const ctl = await rpc(null, null, { jsonrpc: '2.0', id: 0, method: 'initialize',
    params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'probe', version: '1' } } });
  check(`HTTP ${ctl.status} without an Authorization header`, ctl.status === 401,
        `${ctl.status} ${ctl.body.slice(0, 160)}`);

  console.log('\n4. MCP initialize with the OBO token');
  const init = await rpc(mcpToken, null, { jsonrpc: '2.0', id: 1, method: 'initialize',
    params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'probe', version: '1' } } });
  check(`HTTP ${init.status}`, init.status === 200, init.body.slice(0, 300));
  if (init.status !== 200) return 1;
  const sid = init.sessionId;
  check(`got an mcp-session-id (${sid ? sid.slice(0, 8) + '...' : 'none'})`, !!sid);
  await rpc(mcpToken, sid, { jsonrpc: '2.0', method: 'notifications/initialized' });

  console.log('\n5. tools/call create-todo - the write door');
  const title = `entra-e2e ${new Date().toISOString()}`;
  const created = await rpc(mcpToken, sid, { jsonrpc: '2.0', id: 2, method: 'tools/call',
    params: { name: 'create-todo', arguments: { title } } });
  check(`HTTP ${created.status}`, created.status === 200, created.body.slice(0, 300));
  const cj = parseRpc(created.body);
  const ctext = JSON.stringify(cj && cj.result ? cj.result : cj);
  check('the tool reported success, not an error', !!(cj && cj.result && !cj.result.isError),
        ctext.slice(0, 300));
  console.log(`      title written: ${title}`);

  console.log('\n6. tools/call get-todos - the read door must find it');
  const got = await rpc(mcpToken, sid, { jsonrpc: '2.0', id: 3, method: 'tools/call',
    params: { name: 'get-todos', arguments: {} } });
  check(`HTTP ${got.status}`, got.status === 200, got.body.slice(0, 300));
  const gj = parseRpc(got.body);
  const gtext = JSON.stringify(gj && gj.result ? gj.result : gj);
  check('the todo just written is in the list', gtext.includes(title), gtext.slice(0, 400));

  console.log('\n7. a token for the WRONG audience must be refused');
  const wrong = await form(tokenUrl, {
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    client_id: clientId,
    client_secret: clientSecret,
    assertion: userToken,
    scope: app.ENTRA_ZIA_EGRESS_SCOPE,
    requested_token_use: 'on_behalf_of',
  });
  if (wrong.status === 200) {
    const bad = await rpc(wrong.json.access_token, null, { jsonrpc: '2.0', id: 4, method: 'initialize',
      params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'probe', version: '1' } } });
    check(`HTTP ${bad.status} for a zia-egress-audienced token`, bad.status === 401,
          `${bad.status} ${bad.body.slice(0, 160)}`);
  } else {
    check('could not mint a wrong-audience token to test with', false,
          wrong.json ? wrong.json.error : wrong.status);
  }

  console.log();
  if (failures) { console.log(`${failures} check(s) FAILED`); return 1; }
  console.log('the Entra MCP plane works end to end: one headless login -> OBO -> authenticated');
  console.log('tool call -> the todo is readable through the same door, and both negative controls');
  console.log(`refuse. The userId this wrote under is oid=${c2.oid}.`);
  return 0;
}

main().then(c => process.exit(c)).catch(e => { console.error('probe crashed: ' + e.message); process.exit(1); });
