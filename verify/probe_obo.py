#!/usr/bin/env python3
"""Verify the On-Behalf-Of token chain, headlessly. Read-only against Entra; changes nothing.

    python3 verify/probe_obo.py

One sign-in, two downstream audiences, still the same user:
  1. a user access token audienced at agent0 (stands in for the browser login — see below)
  2. OBO -> todo0      : aud = todo0, the three mcp: scopes, identity still the USER
  3. OBO -> zia-egress : aud = zia-egress, `email` present — the claim ZIA maps to a username
  4. control: RFC 8693 token-exchange is rejected by Entra, so OBO is the only route

THE LOGIN HERE IS ROPC (the password grant) for a cloud-only TEST user, because it makes the chain
measurable with nobody at the keyboard. The shipped flow is the browser authorization-code + PKCE login.
ROPC does not support MFA or federated users, and Entra ID Protection can block it outright for an
account it considers risky (AADSTS53004). Never use ROPC for real users or in production.

Reads: entra-setup/out/entra-objects.json, entra-setup/out/secrets.env, entra-setup/out/test-user.env
(all written by bootstrap_entra_objects.py). Prints claim names and non-secret values only.
"""

import base64
import json
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request

OUT = pathlib.Path(__file__).resolve().parent.parent / "entra-setup" / "out"


def env_file(p: pathlib.Path) -> dict:
    out = {}
    for line in p.read_text().splitlines():
        if line.strip() and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


S = json.loads((OUT / "entra-objects.json").read_text())
SEC = env_file(OUT / "secrets.env")
USER = env_file(OUT / "test-user.env")
TOKEN_URL = f"https://login.microsoftonline.com/{S['tenant_id']}/oauth2/v2.0/token"
fails = []


def claims(tok: str) -> dict:
    p = tok.split(".")[1]
    p += "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))


def post(form: dict):
    req = urllib.request.Request(TOKEN_URL, data=urllib.parse.urlencode(form).encode(),
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return True, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return False, json.loads(e.read())


def why(err: dict) -> str:
    d = err.get("error_description", "")
    return f"{err.get('error')}  {d.splitlines()[0][:220] if d else ''}"


def check(name, ok, detail=""):
    print(f"  {'ok  ' if ok else 'FAIL'}  {name}" + (f"   {detail}" if detail else ""))
    if not ok:
        fails.append(name)


def show(c: dict, res: dict):
    # `iss` and `ver` matter: todo0 pins the v2.0 issuer, and a v1 token (iss=https://sts.windows.net/...)
    # fails every request with an opaque "unexpected iss".
    for k in ("aud", "iss", "scp", "preferred_username", "email", "oid", "azp", "ver"):
        if k in c:
            print(f"      {k:20} {c[k]}")
    print(f"      expires_in           {res.get('expires_in')}s")


print(f"tenant {S['tenant_id']}\n")

print("1. user access token, aud = agent0 (ROPC test login standing in for the browser)")
ok, res = post({"grant_type": "password",
                "client_id": S["agent0_app_id"], "client_secret": SEC["AGENT0_CLIENT_SECRET"],
                "username": USER["TEST_USER_UPN"], "password": USER["TEST_USER_PASSWORD"],
                "scope": S["agent0_scope"] + " offline_access"})
if not ok:
    print(f"  FAIL  {why(res)}")
    sys.exit(1)
inbound = res["access_token"]
ic = claims(inbound)
show(ic, res)
check("aud is agent0 itself — OBO requires this; an ID token cannot be the assertion",
      ic["aud"] == S["agent0_app_id"], ic["aud"])
user_pu, user_oid = ic.get("preferred_username"), ic.get("oid")
check("a refresh token is issued (a session can outlive one hour)", "refresh_token" in res)


def obo(label: str, scope: str, expect_aud: str):
    print(f"\n{label}")
    ok, res = post({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "client_id": S["agent0_app_id"], "client_secret": SEC["AGENT0_CLIENT_SECRET"],
                    "assertion": inbound, "requested_token_use": "on_behalf_of", "scope": scope})
    if not ok:
        check(f"OBO for {scope}", False, why(res))
        return None
    c = claims(res["access_token"])
    show(c, res)
    check("audience is the downstream resource", c["aud"] == expect_aud, c["aud"])
    check("identity is STILL the user, not agent0",
          c.get("preferred_username") == user_pu and c.get("oid") == user_oid,
          f"{c.get('preferred_username')} / {c.get('oid')}")
    check("azp is agent0 — the caller is recorded as the agent",
          c.get("azp") == S["agent0_app_id"], str(c.get("azp")))
    return c


t = obo("2. OBO -> todo0 (the MCP tool plane)", " ".join(S["todo0_scopes"]), S["todo0_app_id"])
if t:
    want = {v.rsplit("/", 1)[1] for v in S["todo0_scopes"]}
    got = set((t.get("scp") or "").split())
    check(f"all three MCP scopes came through as {sorted(want)}", got == want, str(sorted(got)))

z = obo("3. OBO -> zia-egress (the token ZIA validates), from the SAME inbound token",
        S["zia_egress_scope"], S["zia_egress_app_id"])
if z:
    check("the email claim is present — ZIA's Subject Claim", bool(z.get("email")),
          "" if z.get("email") else
          "absent: set the user's `mail` and wait a few minutes; check the optional claim on zia-egress")
    if USER.get("TEST_USER_ZIA_NAME"):
        check("email equals the ZIA username you created", z.get("email") == USER["TEST_USER_ZIA_NAME"],
              f"{z.get('email')} vs {USER['TEST_USER_ZIA_NAME']}")
    check("ONE sign-in fans out to BOTH planes — no second authentication", t is not None)

print("\n4. control: RFC 8693 token-exchange must be rejected")
ok, res = post({"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id": S["agent0_app_id"], "client_secret": SEC["AGENT0_CLIENT_SECRET"],
                "subject_token": inbound,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "scope": S["todo0_scopes"][0]})
print(f"      {'ISSUED (unexpected)' if ok else 'rejected: ' + why(res)}")
check("token-exchange is rejected, so On-Behalf-Of is the route", not ok)

print()
if fails:
    print(f"{len(fails)} check(s) FAILED: {fails}")
    sys.exit(1)
print("the token chain works: one sign-in -> tool plane + egress plane, still the user")
