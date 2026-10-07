#!/usr/bin/env python3
"""Fill config/*.env from the bootstrap outputs. Writes mode 600; never prints a secret.

    python3 render_config.py --zia-proxy 185.46.xxx.xxx:80        (your ZIA explicit proxy, host:port)

Reads  out/entra-objects.json and out/secrets.env (written by bootstrap_entra_objects.py)
Writes ../config/agent0.env.app, agent0.env.agent, todo0.env.app, todo0.env.mcp

Each output starts from its config/*.example template; the masked example values in the template are
replaced with your real ones, and the run fails if any masked value survives — so a template line
this script does not know about cannot silently ship with an example value in it.
bedrock.env is NOT rendered: copy config/bedrock.env.example and fill in your AWS credentials.

If you did the Entra setup by hand instead, write out/entra-objects.json and out/secrets.env
yourself (README.md, "Entra setup — option B") and run this the same way.
"""

import argparse
import json
import os
import pathlib
import re
import secrets
import sys

HERE = pathlib.Path(__file__).resolve().parent
CONFIG = HERE.parent / "config"

# The masked example values used in config/*.example (format examples from the reference lab).
EX_TENANT = "cddbxxxx-xxxx-xxxx-xxxx-xxxxxxxxf7c6"
EX_AGENT0 = "1135xxxx-xxxx-xxxx-xxxx-xxxxxxxx4766"
EX_TODO0 = "d5ccxxxx-xxxx-xxxx-xxxx-xxxxxxxx5729"
EX_ZIA_EGRESS = "a015xxxx-xxxx-xxxx-xxxx-xxxxxxxxc4d6"
EX_PROXY = "185.46.xxx.xxx:80"
MASKED = re.compile(r"xxxx|xxx8Q~")


def read_env(p: pathlib.Path) -> dict:
    out = {}
    for line in p.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def set_key(text: str, key: str, value: str) -> str:
    new, n = re.subn(rf"^{key}=.*$", f"{key}={value}", text, flags=re.M)
    if n != 1:
        sys.exit(f"FATAL: expected exactly one {key}= line in the template, found {n}")
    return new


def write600(path: pathlib.Path, text: str, force: bool):
    if path.exists() and not force:
        sys.exit(f"FATAL: {path} exists — re-run with --force to replace it")
    old = os.umask(0o077)
    try:
        path.write_text(text)
    finally:
        os.umask(old)
    path.chmod(0o600)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--zia-proxy", required=True, help="ZIA explicit proxy as host:port")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9.-]+:\d+", a.zia_proxy):
        sys.exit("--zia-proxy must be host:port, e.g. gateway.<zscaler-cloud>.net:80")

    s = json.loads((HERE / "out" / "entra-objects.json").read_text())
    sec = read_env(HERE / "out" / "secrets.env")
    for k in ("AGENT0_CLIENT_SECRET", "TODO0_CLIENT_SECRET"):
        if not sec.get(k):
            sys.exit(f"FATAL: {k} missing from out/secrets.env")

    swap = {EX_TENANT: s["tenant_id"], EX_AGENT0: s["agent0_app_id"],
            EX_TODO0: s["todo0_app_id"], EX_ZIA_EGRESS: s["zia_egress_app_id"],
            EX_PROXY: a.zia_proxy}

    def render(name: str, keys: dict) -> str:
        text = (CONFIG / f"{name}.example").read_text()
        for ex, real in swap.items():
            text = text.replace(ex, real)
        for k, v in keys.items():
            text = set_key(text, k, v)
        body = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
        if MASKED.search(body):
            sys.exit(f"FATAL: a masked example value survived in {name} — template and script disagree")
        return text

    files = {
        "agent0.env.app": render("agent0.env.app", {
            "SESSION_SECRET": secrets.token_hex(32),
            "OKTA_CLIENT_SECRET": sec["AGENT0_CLIENT_SECRET"],
            "OKTA_REDIRECT_URI": s["agent0_redirect_uri"]}),
        "agent0.env.agent": render("agent0.env.agent", {}),
        "todo0.env.app": render("todo0.env.app", {
            "SESSION_SECRET": secrets.token_hex(32),
            "OKTA_CLIENT_SECRET": sec["TODO0_CLIENT_SECRET"],
            "OKTA_REDIRECT_URI": s["todo0_redirect_uri"]}),
        "todo0.env.mcp": render("todo0.env.mcp", {}),
    }
    for name, text in files.items():
        write600(CONFIG / name, text, a.force)
        print(f"  wrote config/{name} (mode 600)")
    print("\nStill yours to provide: config/bedrock.env and config/zscaler-root-ca.crt — then deploy/run.sh build")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
