#!/usr/bin/env bash
# Deploy EVIDIQ Circuit as a Docker container behind the shared Coolify Traefik
# proxy on the mcp.evidiq.dev box. Routed by PathPrefix(/circuit) with the prefix
# stripped, so the container still sees /mcp, /x402, /health. Secrets come from
# the env file, never baked into the image. Mirrors the sibling MCP deploys.
set -euo pipefail

IMAGE="${IMAGE:-evidiq-circuit:latest}"
NAME="${NAME:-evidiq-circuit}"
NETWORK="${NETWORK:-coolify}"
ENV_FILE="${ENV_FILE:-/root/evidiq-circuit.env}"
HOST_PORT="${HOST_PORT:-3014}"

docker rm -f "$NAME" >/dev/null 2>&1 || true

docker run -d \
  --name "$NAME" \
  --restart unless-stopped \
  --network "$NETWORK" \
  --env-file "$ENV_FILE" \
  -p 127.0.0.1:${HOST_PORT}:3000 \
  --label 'traefik.enable=true' \
  --label 'traefik.http.middlewares.circuit-strip.stripprefix.prefixes=/circuit' \
  --label 'traefik.http.routers.circuit.middlewares=circuit-strip' \
  --label 'traefik.http.routers.circuit.rule=Host(`mcp.evidiq.dev`) && PathPrefix(`/circuit`)' \
  --label 'traefik.http.routers.circuit.tls=true' \
  --label 'traefik.http.routers.circuit.tls.certresolver=letsencrypt' \
  --label 'traefik.http.services.circuit.loadbalancer.server.port=3000' \
  "$IMAGE"

echo "started:"
docker ps --filter "name=^/${NAME}$" --format '{{.Names}}  {{.Status}}'
