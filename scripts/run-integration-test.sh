#!/usr/bin/env bash
# Full local integration test: builds the image (if needed), brings up
# relay + peer-1 + peer-2 on the shared lanecove-net Docker network, waits
# for the overlay tunnel to actually establish (relay handshakes with both
# peers), runs the existing ping+curl smoke tests from all three sides, and
# tears everything down on exit regardless of outcome.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}/.."

LOG_DIR="$(mktemp -d)"
HANDSHAKE_TIMEOUT="${HANDSHAKE_TIMEOUT:-30}"

cleanup() {
    local status=$?
    if [[ $status -ne 0 ]]; then
        echo "--- Integration test failed (exit $status) — container logs in ${LOG_DIR} ---"
        for c in relay peer-1 peer-2; do
            echo "--- lanecove-tunnel-${c} log (tail) ---"
            tail -n 30 "${LOG_DIR}/${c}.log" 2>/dev/null || true
        done
    fi
    echo "Tearing down integration test containers..."
    docker rm -f lanecove-tunnel-relay lanecove-tunnel-peer-1 lanecove-tunnel-peer-2 >/dev/null 2>&1 || true
    docker network rm lanecove-net >/dev/null 2>&1 || true
    exit $status
}
trap cleanup EXIT

echo "=== Starting relay ==="
./scripts/run-relay-in-docker.sh >"${LOG_DIR}/relay.log" 2>&1 &

for i in $(seq 1 "${HANDSHAKE_TIMEOUT}"); do
    grep -q "Listening on UDP" "${LOG_DIR}/relay.log" 2>/dev/null && break
    sleep 1
    if [[ $i -eq ${HANDSHAKE_TIMEOUT} ]]; then
        echo "Relay did not come up within ${HANDSHAKE_TIMEOUT}s"
        exit 1
    fi
done
echo "Relay is listening."

echo "=== Starting peer-1 and peer-2 ==="
./scripts/run-peer-1-in-docker.sh >"${LOG_DIR}/peer-1.log" 2>&1 &
./scripts/run-peer-2-in-docker.sh >"${LOG_DIR}/peer-2.log" 2>&1 &

echo "=== Waiting for both peers to complete a handshake with the relay ==="
for i in $(seq 1 "${HANDSHAKE_TIMEOUT}"); do
    grep -q "Active peers (2)" "${LOG_DIR}/relay.log" 2>/dev/null && break
    sleep 1
    if [[ $i -eq ${HANDSHAKE_TIMEOUT} ]]; then
        echo "Peers did not both connect to the relay within ${HANDSHAKE_TIMEOUT}s"
        exit 1
    fi
done
echo "Both peers connected."

echo "=== Running tunnel smoke tests ==="
./scripts/test-tunnel-relay.sh
./scripts/test-tunnel-using-peer-1.sh
./scripts/test-tunnel-using-peer-2.sh

echo "=== Integration test passed ==="
