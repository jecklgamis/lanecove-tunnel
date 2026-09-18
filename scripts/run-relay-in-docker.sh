#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_ABS="${SCRIPT_DIR}/../config/relay.yaml"
CONFIG_DIR="${SCRIPT_DIR}/../config"

KEY_CONTAINER=$(python3 -c "import yaml; cfg=yaml.safe_load(open('${CONFIG_ABS}')); print(cfg.get('private_key_file','peer.key'))")
KEY_HOST="${CONFIG_DIR}/$(basename "$KEY_CONTAINER")"

docker network create lanecove-net 2>/dev/null || true
docker rm -f lanecove-tunnel-relay 2>/dev/null || true
docker run \
  --name lanecove-tunnel-relay \
  --network lanecove-net \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -v "${KEY_HOST}:${KEY_CONTAINER}:ro" \
  -v "${CONFIG_ABS}:/lanecove/peer.yaml:ro" \
  -p 5040:5040/udp \
  -p 9901:9901 \
  -e PEER_IP="10.9.0.1/24" \
  -e ENVOY_UPSTREAM_HOST="127.0.0.1" \
  -e ENVOY_UPSTREAM_PORT="9901" \
  lanecove-tunnel-peer:latest
