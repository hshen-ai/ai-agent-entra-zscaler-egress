# NOTICE

## Upstream

`app/` contains the source of **oktadev/okta-secure-ai-agent-example**
(https://github.com/oktadev/okta-secure-ai-agent-example), snapshot of commit
`439602b639324d460c56c46d33075ebbfcd0b2ad` (2026-04-30), with the modifications listed below.

**Upstream license, stated as found.** The upstream repository declares the **ISC** license in two
places — the `"license": "ISC"` field of its root `package.json`, and a "License: ISC" badge in its
`README.md`. It does **not** include a LICENSE file or a copyright notice (checked against the
repository and the GitHub API, which reports no license file, on 2026-10-07). No upstream copyright line
has been added here, because none was published. The upstream code is redistributed on the basis of
that ISC declaration; the ISC terms are at https://opensource.org/licenses/ISC.

The author's additions (outside `app/`) and modifications are personal work by Henry Shen, not an
official Zscaler solution, and are covered by `LICENSE` in the repository root.

## How to see every change

The repository history has exactly two commits: the pristine upstream snapshot, then the author's
changes. `git diff HEAD~1 -- app/` shows every modified line.

## Modified and added files in `app/`

The upstream sample is an Okta Cross App Access demo. The modifications add an **Entra ID**
code path, selected by `IDP=entra`, and send the agent's Bedrock traffic through a **ZIA explicit
proxy** with the user's token. The Okta path is preserved — `IDP` unset or `okta` behaves as upstream,
plus the ZIA egress changes.

| File | IdP path | What changed and why |
|---|---|---|
| `packages/agent0/src/auth/entra-obo.ts` (new) | Entra | On-Behalf-Of exchange: trades the user's agent0-audienced access token for downstream tokens (todo0, zia-egress). Entra rejects RFC 8693 token-exchange, so OBO replaces Okta's ID-JAG step. Logs claims, never tokens. |
| `packages/agent0/src/auth/okta-auth.ts` | both | Login scopes configurable via `IDP_LOGIN_SCOPES` (Entra needs an access token audienced at agent0). On login, mints the per-session ZIA egress token — via OBO on Entra, via a `prompt=none` authorization request on Okta. Fails closed: any error leaves the session without a token, so egress is refused (407) rather than sent as someone else. |
| `packages/agent0/src/connections/auth-strategy.ts` | both | Adds an `OboAuthStrategy` for the MCP connection and selects ID-JAG (Okta) or OBO (Entra) from `IDP`. |
| `packages/agent0/src/agent.ts` | both | Bedrock client uses HTTP/1.1 (ZIA SSL inspection does not negotiate ALPN, so HTTP/2 fails) over an explicit-proxy CONNECT to `ZIA_PROXY` carrying `Proxy-Authorization: Bearer <this session's zia-egress token>`; the token is read per CONNECT so a refreshed token applies immediately and concurrent users egress as themselves. Hands the Entra user token to the session's agent before the MCP connect. |
| `packages/agent0/src/app.ts` | both | `GET /api/zia/status` (decoded egress-token claims, never the token); a process-level egress token for the agent itself (Okta path only); helmet: HSTS and CSP `upgrade-insecure-requests` disabled so the UI works over plain HTTP. |
| `packages/agent0/src/connections/authorization-server/handler.ts` | Okta | Supports `client_secret_post` alongside the private-key JWT assertion. |
| `packages/agent0/public/app.js` | neither | API base URL made relative, so the UI works from any origin (tunnel or reverse proxy), not only `localhost:3000`. |
| `packages/todo0/src/middleware/requireMcpAuth.ts` | both | Verifies Entra-issued MCP access tokens against Entra's JWKS (v2.0 issuer, bare-GUID audience); normalises the user id (`oid` on Entra) and space-delimited scopes. |
| `packages/todo0/src/routes/auth.ts` | both | Web login keys the user on `oid` before `sub`: on Entra `sub` is pairwise per application, so without this the UI and the MCP server would see two different users. |
| `packages/todo0/src/mcp-server.ts` | both | Authorization-server metadata: tries RFC 8414, falls back to OpenID discovery (Entra returns an empty 404 on the former, which crashed the MCP server at start-up). |
| `packages/todo0/src/app-server.ts` | neither | helmet: HSTS and CSP `upgrade-insecure-requests` disabled, as in agent0. |
| `scripts/bootstrap-okta-tenant.ts`, `scripts/lib/agent-identity-api.ts` | Okta | Okta Agent Identity API payload updates; not used on the Entra path. |
| `Dockerfile`, `.dockerignore` (new) | neither | Container build; adds the Zscaler root CA for builds behind SSL inspection, and keeps env files and keys out of the build context. |

Some code comments refer to the change sets by their internal names (`patch_*.py`, probe scripts) and
to lab measurements; they are kept because they explain *why* a line is the way it is. Example values
in comments are masked values from the reference lab.
