#!/usr/bin/env python3
"""Create the three Entra ID app registrations this reference implementation needs. Idempotent.

    zia-egress    the AUDIENCE of the token ZIA validates. Exposes `zia:egress`, and requests the
                  `email` optional claim in its access tokens — ZIA's Token Validator maps that claim
                  to a ZIA username.
    todo0-entra   the MCP resource server (exposes mcp:connect, mcp:tools:read, mcp:tools:manage) AND
                  the confidential client for todo0's own web login.
    agent0-entra  the confidential client the user signs in to. Exposes `agent.access`, because
                  On-Behalf-Of requires the inbound token's audience to be agent0 itself.

Why a separate zia-egress app: an access token carries exactly one audience. Keeping the proxy token's
audience apart from the tool-plane token means a token stolen from one plane is refused by the other.

Why preAuthorizedApplications rather than a consent grant: agent0 is pre-authorised on zia-egress and
todo0, so On-Behalf-Of never needs an interactive consent prompt for those downstream resources.

Writes (never prints a secret):
    out/entra-objects.json   every id and scope string — no secrets
    out/secrets.env          the agent0 and todo0 client secrets, mode 600. Entra returns a secret
                             exactly ONCE; if this file is lost, delete the credential and re-run.
    out/test-user.env        only with --test-user: a cloud test user for the headless probes

Then: python3 render_config.py   (fills config/*.env from these outputs)

    python3 bootstrap_entra_objects.py
    python3 bootstrap_entra_objects.py --test-user zia-probe --zia-domain example.com

Redirect URIs default to http://localhost:3000/callback and http://localhost:5001/callback; override
with AGENT0_REDIRECT_URI / TODO0_REDIRECT_URI to match the origin your browser will use.
"""

import argparse
import json
import os
import pathlib
import secrets
import string
import sys
import time
import uuid

import entra_graph as eg

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE / "out"
TENANT_DOMAIN = eg.CONF["tenant_domain"]
AGENT0_REDIRECT = os.environ.get("AGENT0_REDIRECT_URI", "http://localhost:3000/callback")
TODO0_REDIRECT = os.environ.get("TODO0_REDIRECT_URI", "http://localhost:5001/callback")

ZIA_SCOPE = "zia:egress"
TODO0_SCOPES = ("mcp:connect", "mcp:tools:read", "mcp:tools:manage")
AGENT0_SCOPE = "agent.access"

# Deterministic scope ids: a re-run must reuse the same GUIDs, or every pre-authorisation breaks.
NS = uuid.UUID("6f0c1b3e-5a8e-5c2a-9d41-0e7a2b6c8d90")


def scope_id(app: str, value: str) -> str:
    return str(uuid.uuid5(NS, f"{app}/{value}"))


# Entra is eventually consistent for seconds to minutes after a write. A GET on a just-created
# application can 404, POST /servicePrincipals for it can return Authorization_RequestDenied, and a
# PATCH that returned 204 can still read back the old value. None of these is a permission gap; all
# clear on retry. Matched on specific codes/messages so a genuinely wrong request is not swallowed.
TRANSIENT = ("Request_ResourceNotFound", "Authorization_RequestDenied",
             "CannotDeleteOrUpdateEnabledEntitlement",
             "cannot be found in the AppPermissions sets")


def settle(fn, tries: int = 8, delay: int = 5):
    for attempt in range(tries):
        try:
            return fn()
        except RuntimeError as e:
            if attempt == tries - 1 or not any(t in str(e) for t in TRANSIENT):
                raise
            time.sleep(delay)


def find_app(display_name: str):
    hits = eg.paged(f"/applications?$filter=displayName eq '{display_name}'")
    if len(hits) > 1:
        sys.exit(f"FATAL: {len(hits)} apps named {display_name!r} — resolve by hand")
    return hits[0] if hits else None


def body_landed(app: dict, body: dict) -> bool:
    """True when every field `body` writes already reads back the same (one level into complex
    types; requiredResourceAccess compared order-insensitively, because Graph may reorder it)."""
    def norm(rra):
        return {(r["resourceAppId"], frozenset(a["id"] for a in r["resourceAccess"]))
                for r in rra or []}

    for key, want in body.items():
        got = app.get(key)
        if key == "requiredResourceAccess":
            if norm(got) != norm(want):
                return False
        elif isinstance(want, dict):
            if any((got or {}).get(k) != v for k, v in want.items()):
                return False
        elif got != want:
            return False
    return True


def patch_until(oid: str, body: dict, pred, what: str,
                rounds: int = 5, polls: int = 4, delay: int = 5) -> dict:
    """PATCH an application, then confirm by reading it back, re-issuing if the write did not land.
    A 204 from Graph means "accepted", not "applied". Every body here is idempotent."""
    for _ in range(rounds):
        settle(lambda: eg.graph("PATCH", f"/applications/{oid}", body))
        for _ in range(polls):
            time.sleep(delay)
            app = settle(lambda: eg.graph("GET", f"/applications/{oid}"))
            if pred(app):
                return app
    sys.exit(f"FATAL: {oid} never reached '{what}' — Graph accepted the write and dropped it")


def upsert_app(display_name: str, body: dict) -> dict:
    existing = find_app(display_name)
    if existing:
        app = eg.graph("GET", f"/applications/{existing['id']}")
        if not body_landed(app, body):
            app = patch_until(app["id"], body, lambda a: body_landed(a, body),
                              f"{display_name} matches its declared body")
        print(f"  = {display_name:24} updated   appId={app['appId']}")
    else:
        app = eg.graph("POST", "/applications", {"displayName": display_name, **body})
        print(f"  + {display_name:24} created   appId={app['appId']}")
    # A service principal is what carries assignments and consent; an app alone is inert.
    sps = eg.paged(f"/servicePrincipals?$filter=appId eq '{app['appId']}'")
    if not sps:
        sp = settle(lambda: eg.graph("POST", "/servicePrincipals", {"appId": app["appId"]}))
        print(f"    service principal created  {sp['id']}")
    return settle(lambda: eg.graph("GET", f"/applications/{app['id']}"))


def scopes_of(app: dict) -> list:
    return (app.get("api") or {}).get("oauth2PermissionScopes", [])


def set_identifier_uri(app: dict) -> dict:
    """Give the app `api://<appId>`, the prefix of every scope string the code sends."""
    if app.get("identifierUris"):
        return app
    uri = f"api://{app['appId']}"
    app = patch_until(app["id"], {"identifierUris": [uri]},
                      lambda a: a.get("identifierUris") == [uri], f"identifierUris == [{uri}]")
    print(f"    identifierUri {uri}")
    return app


def set_scopes(app: dict, desired: list) -> dict:
    """Make the app expose exactly `desired`. Two-phase, because Entra refuses to remove or rename an
    ENABLED delegated permission: it must be disabled in one write and dropped in the next."""
    oid = app["id"]
    current = {s["value"]: s for s in scopes_of(app)}
    want = {s["value"]: s for s in desired}
    if set(current) == set(want) and all(current[v]["id"] == want[v]["id"] for v in want):
        print(f"    scopes {', '.join(sorted(want))} (already correct)")
        return app
    if [v for v in current if v not in want]:
        # A pre-authorisation pins the scope ids it references, so it has to go first.
        if (app.get("api") or {}).get("preAuthorizedApplications"):
            patch_until(oid, {"api": {"preAuthorizedApplications": []}},
                        lambda a: not (a.get("api") or {}).get("preAuthorizedApplications"),
                        "preAuthorizedApplications empty")
        disabled = [{**s, "isEnabled": False} for s in current.values()]
        app = patch_until(oid, {"api": {"oauth2PermissionScopes": disabled}},
                          lambda a: all(not s["isEnabled"] for s in scopes_of(a)),
                          "every existing scope disabled")
    app = patch_until(oid, {"api": {"oauth2PermissionScopes": desired}},
                      lambda a: {s["value"] for s in scopes_of(a)} == set(want)
                      and all(s["isEnabled"] for s in scopes_of(a)),
                      f"exposes exactly {sorted(want)}, all enabled")
    print(f"    scopes {', '.join(sorted(want))}")
    return app


def ensure_email_claim(app: dict) -> dict:
    """`email` must be an optional claim on the RESOURCE app — a client cannot add claims to someone
    else's audience. Entra fills it from the user's `mail` attribute, so `mail` must equal the user's
    ZIA username for ZIA to accept the token."""
    names = lambda a: sorted(c["name"] for c in
                             ((a.get("optionalClaims") or {}).get("accessToken") or []))
    if "email" in names(app):
        print(f"    optional claims {names(app)} (already correct)")
        return app
    want = [{"name": n, "source": None, "essential": False, "additionalProperties": []}
            for n in ("email", "upn")]
    app = patch_until(app["id"], {"optionalClaims": {"idToken": [], "accessToken": want,
                                                     "saml2Token": []}},
                      lambda a: "email" in names(a), "the email optional claim")
    print(f"    optional claims {names(app)}")
    return app


def delegated_scope(app_name: str, value: str, label: str, description: str) -> dict:
    return {
        "id": scope_id(app_name, value), "value": value, "type": "User", "isEnabled": True,
        "adminConsentDisplayName": label, "adminConsentDescription": description,
        "userConsentDisplayName": label, "userConsentDescription": description,
    }


def web(redirect: str) -> dict:
    return {"redirectUris": [redirect],
            "implicitGrantSettings": {"enableIdTokenIssuance": False,
                                      "enableAccessTokenIssuance": False}}


def add_secret_once(app: dict, label: str, have: dict) -> str | None:
    """Create a client secret only if this run has no stored value for it. Returns the value."""
    if label in have:
        print(f"  = {label} already in out/secrets.env — left alone (a reset would break the container)")
        return None
    res = settle(lambda: eg.graph("POST", f"/applications/{app['id']}/addPassword",
                                 {"passwordCredential": {"displayName": "container"}}))
    print(f"  + {label} created (value written to out/secrets.env, never printed)")
    return res["secretText"]


def write600(path: pathlib.Path, text: str):
    old = os.umask(0o077)           # before the file exists, so there is no world-readable window
    try:
        path.write_text(text)
    finally:
        os.umask(old)
    path.chmod(0o600)


def read_env(path: pathlib.Path) -> dict:
    out = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--test-user", help="mailNickname of a cloud test user for the headless probes")
    ap.add_argument("--zia-domain", help="domain of that user's ZIA username, e.g. example.com")
    a = ap.parse_args()
    if bool(a.test_user) != bool(a.zia_domain):
        sys.exit("--test-user and --zia-domain go together")
    OUT.mkdir(mode=0o700, exist_ok=True)

    print(f"tenant {eg.CONF['tenant_id']}  ({TENANT_DOMAIN})\n")

    print("1. zia-egress — the audience of the ZIA Proxy-Authorization token")
    zia = upsert_app("zia-egress", {"signInAudience": "AzureADMyOrg",
                                    "api": {"requestedAccessTokenVersion": 2}})
    zia = set_scopes(zia, [delegated_scope(
        "zia-egress", ZIA_SCOPE, "Authenticate egress through Zscaler",
        "Lets the agent attach the signed-in user's identity to its outbound proxy CONNECT.")])
    zia = set_identifier_uri(zia)
    zia = ensure_email_claim(zia)

    print("\n2. todo0-entra — the MCP resource server, and todo0's own web-login client")
    todo0 = upsert_app("todo0-entra", {"signInAudience": "AzureADMyOrg",
                                       "web": web(TODO0_REDIRECT),
                                       "api": {"requestedAccessTokenVersion": 2}})
    todo0 = set_scopes(todo0, [
        delegated_scope("todo0-entra", TODO0_SCOPES[0], "Connect to the MCP server",
                        "Open an MCP session as the signed-in user."),
        delegated_scope("todo0-entra", TODO0_SCOPES[1], "Read tools and todos",
                        "List tools and read the signed-in user's todos."),
        delegated_scope("todo0-entra", TODO0_SCOPES[2], "Manage todos",
                        "Create and change the signed-in user's todos."),
    ])
    todo0 = set_identifier_uri(todo0)

    print("\n3. agent0-entra — the confidential client the user signs in to")
    agent0 = upsert_app("agent0-entra", {
        "signInAudience": "AzureADMyOrg",
        "web": web(AGENT0_REDIRECT),
        "api": {"requestedAccessTokenVersion": 2},
        "requiredResourceAccess": [
            {"resourceAppId": zia["appId"],
             "resourceAccess": [{"id": scope_id("zia-egress", ZIA_SCOPE), "type": "Scope"}]},
            {"resourceAppId": todo0["appId"],
             "resourceAccess": [{"id": scope_id("todo0-entra", s), "type": "Scope"}
                                for s in TODO0_SCOPES]},
        ],
    })
    agent0 = set_scopes(agent0, [delegated_scope(
        "agent0-entra", AGENT0_SCOPE, "Use the agent", "Lets the signed-in user talk to the agent.")])
    agent0 = set_identifier_uri(agent0)

    print("\n4. preAuthorizedApplications — agent0 needs no consent prompt for its downstream resources")
    for res, name, scopes in ((zia, "zia-egress", [ZIA_SCOPE]),
                              (todo0, "todo0-entra", list(TODO0_SCOPES))):
        ids = [scope_id(name, s) for s in scopes]
        want = {"appId": agent0["appId"], "delegatedPermissionIds": ids}

        def landed(x, ids=ids):
            mine = [p for p in (x.get("api") or {}).get("preAuthorizedApplications") or []
                    if p["appId"] == agent0["appId"]]
            return len(mine) == 1 and set(mine[0]["delegatedPermissionIds"]) == set(ids)

        patch_until(res["id"], {"api": {"preAuthorizedApplications": [want]}}, landed,
                    f"{name} pre-authorises agent0", rounds=8, polls=6)
        print(f"  {name:12} pre-authorises agent0 for {', '.join(scopes)}")

    print("\n5. client secrets (file-based, mode 600)")
    sec_file = OUT / "secrets.env"
    have = read_env(sec_file)
    new = {}
    for app, label in ((agent0, "AGENT0_CLIENT_SECRET"), (todo0, "TODO0_CLIENT_SECRET")):
        value = add_secret_once(app, label, have)
        if value:
            new[label] = value
    if new:
        merged = {**have, **new}
        write600(sec_file, "# Entra client secrets. Mode 600. Never commit. Never paste into a ticket.\n"
                 + "".join(f"{k}={v}\n" for k, v in merged.items()))

    upn = None
    if a.test_user:
        print("\n6. test user for the headless probes (ROPC) — NOT for production use")
        upn = f"{a.test_user}@{TENANT_DOMAIN}"
        zia_name = f"{a.test_user}@{a.zia_domain}"
        existing = eg.paged(f"/users?$filter=userPrincipalName eq '{upn}'")
        if existing:
            print(f"  = {upn} already exists — its password is whatever out/test-user.env holds")
        else:
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_"
            pw = "".join(secrets.choice(alphabet) for _ in range(28))
            eg.graph("POST", "/users", {
                "accountEnabled": True, "displayName": f"{a.test_user} (probe test user)",
                "mailNickname": a.test_user, "userPrincipalName": upn,
                # Must be false, or the password grant the probes use can never succeed.
                "passwordProfile": {"password": pw, "forceChangePasswordNextSignIn": False},
            })
            write600(OUT / "test-user.env",
                     "# Probe test user. Mode 600. Never commit.\n"
                     f"TEST_USER_UPN={upn}\nTEST_USER_PASSWORD={pw}\nTEST_USER_ZIA_NAME={zia_name}\n")
            print(f"  + {upn} created; password in out/test-user.env (never printed)")
        # `mail` cannot be set in the create call. It is what the `email` claim carries, so it must be
        # the user's ZIA username. Re-asserted on every run.
        u = eg.paged(f"/users?$filter=userPrincipalName eq '{upn}'")[0]
        if u.get("mail") != zia_name:
            eg.graph("PATCH", f"/users/{u['id']}", {"mail": zia_name, "otherMails": [zia_name]})
        print(f"    mail = {zia_name}  -> create this exact username in ZIA. The email claim can take")
        print("    several minutes to appear in new tokens after `mail` is first set.")

    tid = eg.CONF["tenant_id"]
    state = {
        "tenant_id": tid,
        "tenant_domain": TENANT_DOMAIN,
        "issuer": f"https://login.microsoftonline.com/{tid}/v2.0",
        "jwks_uri": f"https://login.microsoftonline.com/{tid}/discovery/v2.0/keys",
        "zia_egress_app_id": zia["appId"],
        "zia_egress_scope": f"api://{zia['appId']}/{ZIA_SCOPE}",
        "agent0_app_id": agent0["appId"],
        "agent0_scope": f"api://{agent0['appId']}/{AGENT0_SCOPE}",
        "todo0_app_id": todo0["appId"],
        "todo0_scopes": [f"api://{todo0['appId']}/{s}" for s in TODO0_SCOPES],
        "agent0_redirect_uri": AGENT0_REDIRECT,
        "todo0_redirect_uri": TODO0_REDIRECT,
        "test_user": upn,
    }
    (OUT / "entra-objects.json").write_text(json.dumps(state, indent=2) + "\n")
    print("\nwrote out/entra-objects.json (ids only, no secrets)")
    print("\nNext, in the Zscaler consoles (README.md, 'Zscaler setup'):")
    print(f"  ZIdentity Token Validator: Issuer = {state['issuer']}")
    print(f"                             JWKS URL = {state['jwks_uri']}")
    print("                             Subject Claim = email")
    print(f"                             required claim aud = {zia['appId']}")
    print("Then: python3 render_config.py --zia-proxy <host:port>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
