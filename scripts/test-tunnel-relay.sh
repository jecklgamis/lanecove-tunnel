#!/usr/bin/env bash
set -e
for TARGET_IP in 10.9.0.2 10.9.0.3; do
    echo "Pinging $TARGET_IP from relay..."
    docker exec lanecove-tunnel-relay ping -c 2 "$TARGET_IP"
    echo "Curling http://$TARGET_IP from relay..."
    docker exec lanecove-tunnel-relay curl -s --max-time 5 "http://$TARGET_IP"
done
