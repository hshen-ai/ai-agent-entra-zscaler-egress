#!/usr/bin/env bash
# Build and run agent0 (port 3000) + todo0 (port 5001, MCP on loopback 5002) in one container, signed in
# with Microsoft Entra ID, with the agent's Bedrock traffic sent through the ZIA explicit proxy carrying
# the user's Entra token as Proxy-Authorization: Bearer.
#
#   deploy/run.sh build      build the image from app/
#   deploy/run.sh run        (re)create the container from the files in config/
#   deploy/run.sh logs       follow the container log
#
# Prerequisites (README.md, "Setup"):
#   config/agent0.env.app  config/agent0.env.agent  config/todo0.env.app  config/todo0.env.mcp
#   config/bedrock.env     config/zscaler-root-ca.crt
#
# Secrets reach the container ONLY as read-only bind mounts and --env-file, never as -e arguments:
# a -e value is visible in `ps`, in shell history and in `docker inspect` for the container's lifetime.
#
# Overridable: CONFIG (default ./config), IMAGE, NAME, VOLUME, and the host-side ports AGENT0_PORT
# (default 3000) and TODO0_PORT (default 5001). If you change a port, change the matching redirect URI
# in Entra and in config/ too — the browser returns to whatever origin is registered there.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="${CONFIG:-$ROOT/config}"
IMAGE="${IMAGE:-ai-agent-entra-zscaler:local}"
NAME="${NAME:-ai-agent-entra-zscaler}"
VOLUME="${VOLUME:-ai-agent-entra-zscaler-todo0-db}"
AGENT0_PORT="${AGENT0_PORT:-3000}"
TODO0_PORT="${TODO0_PORT:-5001}"
CA="$CONFIG/zscaler-root-ca.crt"

need() { [ -f "$1" ] || { echo "FATAL: $1 is missing — see README.md, Setup" >&2; exit 2; }; }

case "${1:-}" in
  build)
    # The build installs packages from the internet. Behind ZIA SSL inspection that fails with
    # UNABLE_TO_GET_ISSUER_CERT_LOCALLY unless the Zscaler root CA is in the build context.
    need "$CA"
    cp "$CA" "$ROOT/app/zscaler-root-ca.crt"
    docker build -t "$IMAGE" "$ROOT/app"
    ;;

  run)
    # Every file is checked BEFORE the old container is removed: docker silently creates an empty
    # DIRECTORY at a missing bind-mount source, which would start a container with no configuration.
    for f in agent0.env.app agent0.env.agent todo0.env.app todo0.env.mcp bedrock.env zscaler-root-ca.crt; do
      need "$CONFIG/$f"
    done
    for f in agent0.env.app todo0.env.app bedrock.env; do
      perm=$(stat -c %a "$CONFIG/$f" 2>/dev/null || stat -f %Lp "$CONFIG/$f")
      [ "$perm" = 600 ] || echo "warning: $CONFIG/$f is mode $perm — it holds a secret; chmod 600 it" >&2
    done

    docker rm -f "$NAME" >/dev/null 2>&1 || true

    # IDP=entra selects the Entra code path; it is container environment rather than a line in an env
    # file because several modules read it before those files are loaded. NODE_EXTRA_CA_CERTS: Node does
    # not use the OS trust store, and ZIA re-signs the TLS sessions it inspects.
    # Ports bind to 127.0.0.1: reach the UIs through an SSH tunnel or a reverse proxy, and keep the
    # registered redirect URIs in step with whatever origin the browser uses. Port 5002 (MCP) is
    # never published.
    docker run -d --name "$NAME" --restart unless-stopped \
      --env-file "$CONFIG/bedrock.env" \
      -e IDP=entra \
      -e NODE_EXTRA_CA_CERTS=/etc/ssl/zscaler-root-ca.crt \
      -p "127.0.0.1:$AGENT0_PORT:3000" \
      -p "127.0.0.1:$TODO0_PORT:5001" \
      -v "$CA:/etc/ssl/zscaler-root-ca.crt:ro" \
      -v "$CONFIG/agent0.env.app:/app/packages/agent0/.env.app:ro" \
      -v "$CONFIG/agent0.env.agent:/app/packages/agent0/.env.agent:ro" \
      -v "$CONFIG/todo0.env.app:/app/packages/todo0/.env.app:ro" \
      -v "$CONFIG/todo0.env.mcp:/app/packages/todo0/.env.mcp:ro" \
      -v "$VOLUME:/app/packages/todo0/prisma" \
      "$IMAGE" >/dev/null

    echo "started $NAME; waiting for '[Agent] Ready!' (up to 3 minutes)..."
    for _ in $(seq 1 36); do
      if docker logs "$NAME" 2>&1 | grep -qF '[Agent] Ready!'; then
        echo "ready: agent0 http://localhost:$AGENT0_PORT   todo0 http://localhost:$TODO0_PORT"
        exit 0
      fi
      sleep 5
    done
    echo "FAILED: no '[Agent] Ready!' after 3 minutes — run: deploy/run.sh logs" >&2
    exit 1
    ;;

  logs)
    docker logs -f "$NAME"
    ;;

  *)
    echo "usage: deploy/run.sh build|run|logs" >&2
    exit 2
    ;;
esac
