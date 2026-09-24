#!/usr/bin/env bash
set -e
TARGET_IP="${1:-10.9.0.2}"
echo "Pinging $TARGET_IP from peer-2..."
docker exec lanecove-tunnel-peer-2 ping -c 2 "$TARGET_IP"
echo "Curling http://$TARGET_IP from peer-2..."
docker exec lanecove-tunnel-peer-2 curl -s --max-time 5 "http://$TARGET_IP"
