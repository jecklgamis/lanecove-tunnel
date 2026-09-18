#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_ABS="${SCRIPT_DIR}/../config/peer-1.yaml"
CONFIG_DIR="${SCRIPT_DIR}/../config"

KEY_CONTAINER=$(python3 -c "import yaml; cfg=yaml.safe_load(open('${CONFIG_ABS}')); print(cfg.get('private_key_file','peer.key'))")
KEY_HOST="${CONFIG_DIR}/$(basename "$KEY_CONTAINER")"

docker network create lanecove-net 2>/dev/null || true
docker rm -f lanecove-tunnel-peer-1 2>/dev/null || true
docker run \
  --name lanecove-tunnel-peer-1 \
  --network lanecove-net \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -v "${KEY_HOST}:${KEY_CONTAINER}:ro" \
  -v "${CONFIG_ABS}:/lanecove/peer.yaml:ro" \
  -p 5042:5040/udp \
  -p 15042:15040 \
  -p 15052:15050 \
  -p 9902:9901 \
  -e PEER_IP="10.9.0.2/24" \
  -e ENVOY_UPSTREAM_HOST="10.9.0.3" \
  -e ENVOY_UPSTREAM_PORT="80" \
  lanecove-tunnel-peer:latest
