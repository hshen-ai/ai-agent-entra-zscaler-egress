#!/usr/bin/env python3
"""Unattended Microsoft Graph access for the Entra setup scripts.

Authenticates as an automation app registration with a CERTIFICATE (private_key_jwt client
assertion), so the setup can run without a browser or an interactive admin sign-in. The private key
is read from the file named in the config and never printed.

Configuration: entra-automation.json next to this file, or the path in $ENTRA_AUTOMATION_CONF.
See entra-automation.example.json and README.md, "Entra setup — option A".

One dependency, `cryptography`, which signs the client assertion directly.

    import entra_graph
    org = entra_graph.graph("GET", "/organization")

    python3 entra_graph.py whoami      # decoded claims + a live read probe, no token printed
"""

import base64
import json
import os
import pathlib
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

HERE = pathlib.Path(__file__).resolve().parent
CONF_PATH = pathlib.Path(os.environ.get("ENTRA_AUTOMATION_CONF", HERE / "entra-automation.json"))
CONF = json.loads(CONF_PATH.read_text())
GRAPH_ROOT = "https://graph.microsoft.com/v1.0"
TOKEN_URL = f"https://login.microsoftonline.com/{CONF['tenant_id']}/oauth2/v2.0/token"

_cached = {"token": None, "exp": 0}


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _client_assertion() -> str:
    """A private_key_jwt assertion. `aud` is the tenant's v2.0 token endpoint."""
    key = serialization.load_pem_private_key(
        (CONF_PATH.parent / CONF["key_file"]).read_bytes(), password=None
    )
    # x5t is the base64url of the raw SHA-1 thumbprint bytes, not of its hex text.
    x5t = _b64u(bytes.fromhex(CONF["cert_thumbprint_sha1"]))
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "x5t": x5t}
    payload = {
        "aud": TOKEN_URL,
        "iss": CONF["client_id"],
        "sub": CONF["client_id"],
        "jti": str(uuid.uuid4()),
        "nbf": now - 60,
        "iat": now,
        "exp": now + 300,
    }
    signing_input = (
        _b64u(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + _b64u(json.dumps(payload, separators=(",", ":")).encode())
    ).encode()
    sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return signing_input.decode() + "." + _b64u(sig)


def token() -> str:
    """An app-only Graph access token, cached until 5 minutes before it expires."""
    if _cached["token"] and time.time() < _cached["exp"] - 300:
        return _cached["token"]
    body = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": CONF["client_id"],
            "scope": "https://graph.microsoft.com/.default",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": _client_assertion(),
        }
    ).encode()
    req = urllib.request.Request(
        TOKEN_URL, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            res = json.loads(r.read())
    except urllib.error.HTTPError as e:
        err = json.loads(e.read())
        raise RuntimeError(
            f"token request failed: {err.get('error')} — "
            f"{err.get('error_description', '').splitlines()[0]}"
        ) from None
    _cached["token"] = res["access_token"]
    _cached["exp"] = time.time() + int(res.get("expires_in", 3600))
    return _cached["token"]


def claims(tok: str | None = None) -> dict:
    """Decode a token's payload. Used for reporting identity without ever printing the token."""
    p = (tok or token()).split(".")[1]
    p += "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))


def graph(method: str, path: str, body: dict | None = None, raw: bool = False):
    """Call Graph. `path` is relative to /v1.0. Raises RuntimeError carrying the Graph error code,
    which is what makes a permission gap readable instead of a bare 403."""
    # `$filter=displayName eq 'x'` contains spaces, which http.client rejects outright. Encode here
    # rather than at every call site; `%` is safe so an already-encoded path is not double-encoded,
    # and an absolute @odata.nextLink is passed through untouched.
    url = path if path.startswith("http") else GRAPH_ROOT + urllib.parse.quote(
        path, safe="/?&=$,'()*!:@+%"
    )
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", "Bearer " + token())
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            payload = r.read()
            if raw:
                return r.status, payload
            return json.loads(payload) if payload else {}
    except urllib.error.HTTPError as e:
        payload = e.read()
        try:
            err = json.loads(payload).get("error", {})
            detail = f"{err.get('code')}: {err.get('message', '')[:300]}"
        except Exception:
            detail = payload[:300].decode(errors="replace")
        raise RuntimeError(f"{method} {path} -> HTTP {e.code}  {detail}") from None


def paged(path: str):
    """Follow @odata.nextLink so callers never silently see only the first page."""
    out = []
    res = graph("GET", path)
    out.extend(res.get("value", []))
    while "@odata.nextLink" in res:
        res = graph("GET", res["@odata.nextLink"])
        out.extend(res.get("value", []))
    return out


if __name__ == "__main__":
    import sys

    cmd = sys.argv[1] if len(sys.argv) > 1 else "whoami"
    if cmd != "whoami":
        print(f"usage: {sys.argv[0]} whoami", file=sys.stderr)
        raise SystemExit(2)

    c = claims()
    print("authenticated with a certificate")
    for k in ("iss", "aud", "appid", "app_displayname", "oid", "idtyp"):
        if k in c:
            print(f"    {k:18} {c[k]}")
    print(f"    roles ({len(c.get('roles', []))}):")
    for r in sorted(c.get("roles", [])):
        print(f"        {r}")

    org = graph("GET", "/organization?$select=id,displayName")["value"][0]
    print(f"    live read probe   /organization -> {org['displayName']}")
