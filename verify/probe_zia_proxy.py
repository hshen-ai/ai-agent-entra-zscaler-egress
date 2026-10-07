#!/usr/bin/env python3
"""Verify that ZIA really authenticates the Entra token — with control rows, or a 200 proves nothing.

    python3 verify/probe_zia_proxy.py --proxy 185.46.xxx.xxx:80
    python3 verify/probe_zia_proxy.py --proxy <host:port> --host ipinfo.io     (a non-Bedrock destination)

Run it on a host whose egress reaches your ZIA explicit proxy (the same network position as the
container). Uses curl.

WHY THE CONTROL ROWS ARE THE POINT. Proxy JWT authentication applies only to explicit-proxy traffic.
Traffic on a default route or a transparent tunnel reaches ZIA with no identity and is handled by your
unauthenticated-traffic policy — so a lone 200 could be that path. Each 200 below is bracketed by a 407
that isolates one variable:

    1  default route, no proxy, no token     no 407        unauthenticated path (expected to differ)
    2  explicit proxy, NO token              407 + Bearer  JWT auth is engaged. No Bearer challenge here
                                                           and nothing else in this table means anything.
    3  explicit proxy, literal 'badtoken'    407           signature validation is running
    4  explicit proxy, todo0-audienced token 407           the validator's required `aud` claim is enforced
    5  explicit proxy, zia-egress token      200           the real thing

A 407 on row 5 with rows 2-4 correct almost always means the token's `email` does not match an existing
ZIA username, or the Token Validator's Subject Claim is not `email`.

Tokens are minted with the ROPC test user (see probe_obo.py for why that is test-only). Each token is
handed to curl in a config file inside a private temporary directory (-K), never on the command line,
and deleted on exit. Prints status lines only — never a token.
"""

import argparse
import base64
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
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


def post(form: dict) -> dict:
    req = urllib.request.Request(TOKEN_URL, data=urllib.parse.urlencode(form).encode(),
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        err = json.loads(e.read())
        sys.exit(f"token request failed: {err.get('error')} {err.get('error_description', '')[:200]}")


def claims(tok: str) -> dict:
    p = tok.split(".")[1]
    p += "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))


def mint() -> tuple[str, str]:
    """ROPC -> agent0 token, then OBO to zia-egress and to todo0 (the wrong-audience control)."""
    base = {"client_id": S["agent0_app_id"], "client_secret": SEC["AGENT0_CLIENT_SECRET"]}
    inbound = post({**base, "grant_type": "password", "username": USER["TEST_USER_UPN"],
                    "password": USER["TEST_USER_PASSWORD"], "scope": S["agent0_scope"]})["access_token"]
    obo = lambda scope: post({**base, "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                              "assertion": inbound, "requested_token_use": "on_behalf_of",
                              "scope": scope})["access_token"]
    return obo(S["zia_egress_scope"]), obo(" ".join(S["todo0_scopes"]))


def curl(work: pathlib.Path, label: str, proxy: str | None, token: str | None, host: str) -> str:
    cfg = work / "curl.cfg"
    lines = []
    if proxy:
        lines.append(f'proxy = "http://{proxy}"')
    if token:
        lines.append(f'proxy-header = "Proxy-Authorization: Bearer {token}"')
    fd = os.open(cfg, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    p = subprocess.run(["curl", "-sS", "-v", "--http1.1", "--max-time", "25", "-o", os.devnull,
                        "-K", str(cfg), f"https://{host}/"], capture_output=True, text=True)
    cfg.unlink()
    keep = [re.sub(r"(Bearer )\S+", r"\1<redacted>", l)[:140] for l in (p.stdout + p.stderr).splitlines()
            if re.match(r"^(< HTTP|< Proxy-Auth|curl: )", l, re.I)]
    print(f"\n── {label}")
    for l in keep:
        print("      " + l)
    return "\n".join(keep)


def check(name, ok, detail=""):
    print(f"  {'ok  ' if ok else 'FAIL'}  {name}" + (f"   {detail}" if detail else ""))
    if not ok:
        fails.append(name)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--proxy", required=True, help="ZIA explicit proxy, host:port")
    ap.add_argument("--host", default="bedrock-runtime.eu-central-1.amazonaws.com",
                    help="destination (default: the Bedrock endpoint the agent calls)")
    a = ap.parse_args()
    if not shutil.which("curl"):
        sys.exit("curl is required")

    zia_tok, todo0_tok = mint()
    c = claims(zia_tok)
    print(f"zia-egress token: aud={c.get('aud')} email={c.get('email', '<absent>')}")
    check("the token carries an email claim", "email" in c)

    work = pathlib.Path(tempfile.mkdtemp(prefix="zia-probe-"))
    os.chmod(work, 0o700)
    try:
        t = curl(work, "1  default route, no proxy, no token", None, None, a.host)
        check("1 the default route is NOT proxy-authenticated (no 407)", "407" not in t)
        t = curl(work, "2  explicit proxy, NO token", a.proxy, None, a.host)
        check("2 the proxy challenges (407)", "407" in t)
        bearer = re.search(r"Proxy-Authenticate:\s*Bearer", t, re.I) is not None
        check("2 the challenge is Bearer — JWT authentication is engaged", bearer,
              "" if bearer else "no Bearer challenge: JWT authentication is not enabled for this traffic")
        t = curl(work, "3  explicit proxy, 'badtoken'", a.proxy, "badtoken", a.host)
        check("3 a garbage token is refused (407)", "407" in t)
        t = curl(work, "4  explicit proxy, todo0-audienced token (wrong aud)", a.proxy, todo0_tok, a.host)
        check("4 a validly signed token with the wrong aud is refused (407)", "407" in t)
        t = curl(work, "5  explicit proxy, zia-egress token", a.proxy, zia_tok, a.host)
        accepted = "Connection Established" in t or re.search(r"HTTP/[\d.]+ 200", t) is not None
        check("5 accepted (200 Connection Established)", accepted,
              "" if accepted else "407: check the email claim matches a ZIA username and Subject Claim = email")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print()
    if fails:
        print(f"{len(fails)} check(s) FAILED: {fails}")
        return 1
    print("ZIA authenticates the Entra token, and every control row refuses.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
