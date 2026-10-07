# AI agent egress with Microsoft Entra ID and Zscaler proxy authentication

A reference implementation of one idea: **an AI agent's internet traffic should carry the identity of
the person using it, and the network should check that identity — without a second sign-in.**

A user signs in to an agent web app with Microsoft Entra ID. The app exchanges the user's token
**On-Behalf-Of** for two narrowly-audienced tokens: one for its MCP tool server, one for Zscaler. The
agent's calls to Amazon Bedrock then leave through the **ZIA explicit proxy**, presenting that token as
`Proxy-Authorization: Bearer`. ZIA validates it against the same Entra signing keys that issued the
sign-in, maps its `email` claim to a ZIA user, and logs and governs the request per user.

`docs/entra-oidc-plus-proxy-auth.pdf` walks through the 17-step flow on one diagram.

> **Not an official Zscaler solution.** This is personal work by Henry Shen. It does not represent
> Zscaler's official position and is not supported by Zscaler — it only shares one way to configure
> and consume Zscaler products. For supported configurations, use Zscaler's official documentation and
> support channels. **For educational purposes only — it must not be used in production.** Provided
> as-is; see `LICENSE` and `NOTICE.md`. The agent and MCP
> server are based on the open-source `oktadev/okta-secure-ai-agent-example` sample, extended with an
> Entra ID path and ZIA proxy authentication.

## About the example values

Every example value in this repository is a **real value from the reference lab with its middle
masked**, so you can see the exact format — whether a field is a bare GUID, an `api://` URI or a v2.0
issuer URL is exactly the kind of detail that breaks an Entra setup. Next to each one, a comment or
table column gives the generic placeholder and where to find your own value. Secrets (client secrets,
passwords, tokens) are never shown, only their shape.

| Placeholder | Masked example | Where to find yours |
|---|---|---|
| `<TENANT_ID>` | `cddbxxxx-xxxx-xxxx-xxxx-xxxxxxxxf7c6` | Entra admin center > Overview > Tenant ID |
| `<TENANT_DOMAIN>` | `h*****s.onmicrosoft.com` | Entra admin center > Domain names |
| `<AGENT0_CLIENT_ID>` | `1135xxxx-xxxx-xxxx-xxxx-xxxxxxxx4766` | App registrations > agent0-entra > Application (client) ID |
| `<TODO0_APP_ID>` | `d5ccxxxx-xxxx-xxxx-xxxx-xxxxxxxx5729` | App registrations > todo0-entra |
| `<ZIA_EGRESS_APP_ID>` | `a015xxxx-xxxx-xxxx-xxxx-xxxxxxxxc4d6` | App registrations > zia-egress |
| `<ZIA_PROXY>` | `185.46.xxx.xxx:80` | Your ZIA Service Edge or `gateway.<zscaler-cloud>.net:80` |
| `<ZIA_USERNAME>` | `b**********r@o**a.h***n.de` | ZIA Admin Portal > Users — must equal the user's Entra `mail` |
| `<CLIENT_SECRET>` | `xxx8Q~xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` | App registration > Certificates & secrets (shown once) |

## What's in the box

```
app/            the agent (agent0, :3000) and the MCP tool app (todo0, :5001 UI, :5002 MCP), with the
                Entra and ZIA changes listed in NOTICE.md
config/         *.example env files — one per mounted file, every key commented
deploy/run.sh   build the image, run the container, follow the log
entra-setup/    bootstrap_entra_objects.py creates the three app registrations; render_config.py fills config/
verify/         probe_obo.py (token chain), probe_zia_proxy.py (407/200 control matrix), probe_mcp_e2e.js
docs/           the flow diagram and its explanation (HTML and PDF)
```

## How it works

1. **Sign-in (steps 1–9)** — standard OpenID Connect authorization code + PKCE between the browser,
   agent0 and Entra. No token transits the browser; agent0 holds the user's access token server-side.
2. **Token reuse (10–11)** — agent0 presents that access token as the `assertion` of an On-Behalf-Of
   request, once per downstream audience: `todo0` (MCP scopes) and `zia-egress`. No new user credential.
3. **Egress (12–17)** — the MCP call is loopback inside the container (not proxied). The Bedrock call is
   a CONNECT to the ZIA explicit proxy with `Proxy-Authorization: Bearer <zia-egress token>`. ZIA's
   Token Validator checks signature, issuer, audience and expiry against Entra's JWKS, maps `email` to a
   ZIA user, and answers `200 Connection Established`. The same CONNECT without the header gets `407`.

Every token is per signed-in session and read per connection, so concurrent users egress as
themselves, and a session without a token is **refused** — there is no fallback identity.

## Prerequisites

**Microsoft Entra ID**
- Permission to create app registrations and (for option A below) to grant admin consent to an
  automation app's Microsoft Graph application permissions.
- Users whose **`mail` attribute equals their ZIA username**. The `email` claim ZIA reads comes from `mail`.

**Zscaler**
- **Proxy JWT authentication** enabled for your ZIA and ZIdentity tenants. If you do not see the Token
  Validator in ZIdentity or the JWT option for explicit-proxy authentication in ZIA, ask your Zscaler
  account team to enable it.
- A ZIA user for every identity that will egress, with username = the Entra `mail` value.
- A network path from the container host to your ZIA **explicit proxy** (`<ZIA_PROXY>`). A default route
  or transparent tunnel is not proxy-authenticated.
- Your Zscaler root CA certificate (PEM), if ZIA SSL-inspects the traffic (it must, to inspect AI
  prompts): save it as `config/zscaler-root-ca.crt`.

**Runtime**
- Docker; Python 3.10+ with `cryptography` (for `entra-setup/`); `curl` (for `verify/probe_zia_proxy.py`).
- Amazon Bedrock access to an Anthropic Claude model. Short-lived credentials are strongly preferred.

## Setup

### 1. Entra setup — option A: script

1. Create an **automation** app registration (any name), upload a certificate to it (Certificates &
   secrets > Certificates), and grant it these Microsoft Graph **application** permissions with admin
   consent: `Application.ReadWrite.OwnedBy`, `User.ReadWrite.All`, `Directory.Read.All`.
   A self-signed certificate is fine:
   ```bash
   openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=entra-automation" \
     -keyout entra-setup/entra-automation.key -out entra-setup/entra-automation.crt
   chmod 600 entra-setup/entra-automation.key
   openssl x509 -in entra-setup/entra-automation.crt -noout -fingerprint -sha1   # the thumbprint
   ```
2. Copy `entra-setup/entra-automation.example.json` to `entra-automation.json` and fill it in.
   Check with `python3 entra-setup/entra_graph.py whoami`.
3. Create the app registrations (idempotent — safe to re-run):
   ```bash
   cd entra-setup
   python3 bootstrap_entra_objects.py
   # optional, for the headless probes: a cloud-only test user whose mail = its ZIA username
   python3 bootstrap_entra_objects.py --test-user zia-probe --zia-domain example.com
   ```
   Outputs go to `entra-setup/out/` (ids in `entra-objects.json`; client secrets in `secrets.env`,
   mode 600 — Entra shows a secret only once, so keep that file).

### 1. Entra setup — option B: by hand

Create three app registrations (single tenant, access token version 2 —
Manifest `"requestedAccessTokenVersion": 2`):

| App | Expose an API | Other settings |
|---|---|---|
| `zia-egress` | Application ID URI `api://<ZIA_EGRESS_APP_ID>`; scope `zia:egress` | Token configuration > optional claims, **access** token: `email`, `upn` |
| `todo0-entra` | `api://<TODO0_APP_ID>`; scopes `mcp:connect`, `mcp:tools:read`, `mcp:tools:manage` | Web redirect URI `http://localhost:5001/callback`; a client secret |
| `agent0-entra` | `api://<AGENT0_CLIENT_ID>`; scope `agent.access` | Web redirect URI `http://localhost:3000/callback`; a client secret; API permissions: the scopes above on zia-egress and todo0-entra |

On `zia-egress` and `todo0-entra`, add `agent0-entra` as an **authorized client application** for
their scopes (Expose an API > Add a client application), so On-Behalf-Of needs no consent prompt.
Then write `entra-setup/out/entra-objects.json` (same keys as option A writes; see
`bootstrap_entra_objects.py`) and `entra-setup/out/secrets.env` with `AGENT0_CLIENT_SECRET=` and
`TODO0_CLIENT_SECRET=`.

### 2. Zscaler setup

**ZIdentity > Token Validator** (one per issuer):

| Field | Value | Masked example |
|---|---|---|
| Issuer | `https://login.microsoftonline.com/<TENANT_ID>/v2.0` | `https://login.microsoftonline.com/cddbxxxx-xxxx-xxxx-xxxx-xxxxxxxxf7c6/v2.0` |
| JWKS URL | `https://login.microsoftonline.com/<TENANT_ID>/discovery/v2.0/keys` | `…/cddbxxxx-xxxx-xxxx-xxxx-xxxxxxxxf7c6/discovery/v2.0/keys` |
| Subject Claim | `email` (not `preferred_username`) | `email` |
| Required claim | `aud` = `<ZIA_EGRESS_APP_ID>` (bare GUID) | `a015xxxx-xxxx-xxxx-xxxx-xxxxxxxxc4d6` |

The required `aud` claim is what stops a token issued for another app in your tenant from
authenticating to the proxy. ZIdentity's "Test Token" checks signature and expiry only — use
`verify/probe_zia_proxy.py` as the real acceptance test.

**ZIA** — a user per identity, username = the `email` claim (e.g. `b**********r@o**a.h***n.de`), and
JWT authentication enabled for the explicit-proxy traffic from the container's location.

### 3. Configuration

```bash
python3 entra-setup/render_config.py --zia-proxy <ZIA_PROXY>     # e.g. 185.46.xxx.xxx:80
cp config/bedrock.env.example config/bedrock.env && chmod 600 config/bedrock.env    # then fill it in
cp /path/to/your/zscaler-root-ca.pem config/zscaler-root-ca.crt
```

`render_config.py` writes the four `config/*.env` files (mode 600) from their templates and refuses to
leave any masked example value behind. To configure by hand instead, copy each `config/*.example` and
follow its comments.

### 4. Build and run

```bash
deploy/run.sh build
deploy/run.sh run          # waits for "[Agent] Ready!"
```

Ports bind to `127.0.0.1` only. From another machine use an SSH tunnel
(`ssh -L 3000:127.0.0.1:3000 -L 5001:127.0.0.1:5001 <host>`) or a reverse proxy — and keep the redirect
URIs registered in Entra in step with the origin your browser actually uses.

### 5. Try it

Open `http://localhost:3000`, sign in with an Entra user that has a matching ZIA username, and ask the
agent to create a todo. Then:
- `http://localhost:5001` (sign in as the same user) shows the todo — written through MCP under your `oid`.
- In ZIA's logs, the Bedrock request appears under **your** username, not the host's address.
- `http://localhost:3000/api/zia/status`, opened in the same signed-in browser, shows the decoded
  egress-token claims for your session — never the token itself.

## Verify

```bash
python3 verify/probe_obo.py                                  # token chain: 1 sign-in -> 2 audiences, still the user
python3 verify/probe_zia_proxy.py --proxy <ZIA_PROXY>        # 407 without / 407 bad / 407 wrong aud / 200 right
docker cp verify/probe_mcp_e2e.js ai-agent-entra-zscaler:/tmp/probe.js
docker exec -i ai-agent-entra-zscaler node /tmp/probe.js < entra-setup/out/test-user.env
```

The probes use the optional test user (ROPC — see Security notes). The **control rows are the point**:
a `200` alone could be traffic that never needed authentication; the matching `407`s prove it did.

## Security notes

- **ROPC is for the probes only.** The headless probes sign in with the password grant for a cloud-only
  test user. ROPC does not do MFA or federation, and Entra ID Protection may block it for an account it
  flags as risky (`AADSTS53004`). The shipped flow is the browser authorization-code + PKCE login.
- **Fail closed, by design.** A session with no egress token sends its CONNECT without credentials and
  gets `407`. There is deliberately no fallback to another identity — attribution is the point.
- **Secrets** are mounted read-only from mode-600 files and passed with `--env-file`, never with `-e`
  (visible in `ps`, shell history and `docker inspect`). `.dockerignore` keeps env files and keys out
  of the image.
- **Plain HTTP demo settings.** helmet's HSTS and CSP `upgrade-insecure-requests` are disabled in both
  web apps so the UIs work over HTTP through a tunnel. Re-enable them when you serve over TLS.
- **The MCP server (:5002) is never published**, and its hop is loopback — it is protected by the
  todo0-audienced OAuth token, not by the proxy (proxy authentication applies only to egress).
- **Session vs process identity.** On the Entra path every egress token is per signed-in session.
  Calls that belong to no session (start-up, background work) would need a separate, process-level
  workload identity; that is not configured on the Entra path here and is an extension point.
- **Least privilege for Bedrock**: scope the AWS role to `bedrock:InvokeModel*`; prefer STS credentials.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| ZIA answers `407` with a valid-looking token | `email` claim missing or not equal to an existing ZIA username; Token Validator Subject Claim not `email`; `aud` claim mismatch |
| `email` claim absent from new tokens | user's `mail` not set, or set minutes ago (can take several minutes to appear); `email` optional claim missing on zia-egress |
| No `407` at all without a token | traffic is not using the explicit proxy, or JWT authentication is not enabled for it |
| `LLM processing failed: Protocol error` | HTTP/2 through SSL inspection — the Bedrock client here pins HTTP/1.1; check no other client is in use |
| `UNABLE_TO_GET_ISSUER_CERT_LOCALLY` | Zscaler root CA missing from `config/zscaler-root-ca.crt` / the build |
| Agent says MCP tools are unavailable after a restart | the MCP connection is established on the first request after sign-in; sign in again after every restart |
| todo0 MCP rejects every token with `unexpected aud` | `MCP_EXPECTED_AUDIENCE` must be the bare GUID, not `api://…` |
| `unexpected iss` | a v1 token: set `requestedAccessTokenVersion` to 2 on the app registrations |
| `AADSTS53004` from a probe | Entra blocked ROPC for that account — remediate the risky user or use a fresh test user |
| `ZIA_PROXY is not set` | add `ZIA_PROXY=<host:port>` to `config/agent0.env.agent` |
