# lanecove-tunnel

## Project Overview
A simple Linux hub-and-spoke layer 3 overlay network using a TUN virtual interface over UDP. Implements a basic VPN for learning purposes. Not for production use.

## Architecture

- `src/peer.c` — symmetric peer binary. Reads a YAML config file (`-c peer.yaml`), binds a UDP socket, accepts inbound handshakes, and initiates outbound connections to peers with a configured endpoint. Maintains a session table with per-peer AllowedIPs, sequence counters, and replay windows. Periodically checks whether outbound peers need rekeying (every 3 minutes).
- `src/common.c/h` — TUN interface allocation, logging macros, AES-256-GCM encrypt/decrypt helpers, X25519 DH handshake functions with identity hiding, and a 2048-bit sliding-window replay-protection implementation.

### Topology
```
peer-1 (10.9.0.2) ──┐
                     ├── UDP 5040 ── relay (10.9.0.1, public IP)
peer-2 (10.9.0.3) ──┘
```

- **relay** — public IP, inbound-only, routes traffic between peers
- **peer-1 / peer-2** — behind NAT, connect outbound to relay

### Key Provisioning
Keys are X25519 key pairs stored in PEM files. Use `scripts/lanecove-generate-peer-keys.sh` to generate key pairs.

```
./scripts/lanecove-generate-peer-keys.sh relay peer-1 peer-2
# produces: relay.key/crt, peer-1.key/crt, peer-2.key/crt
```

Keys and YAML configs for local testing are kept in `config/`:

| File | Purpose |
|------|---------|
| `config/relay.key` / `config/relay.crt` | Relay identity |
| `config/peer-1.key` / `config/peer-1.crt` | Peer-1 identity |
| `config/peer-2.key` / `config/peer-2.crt` | Peer-2 identity |
| `config/relay.yaml` | Relay runtime config |
| `config/peer.yaml` | Generic peer runtime config |
| `config/peer-1.yaml` | Peer-1 runtime config |
| `config/peer-2.yaml` | Peer-2 runtime config |

### YAML Config Format
```yaml
interface: lanecove0
port: 5040
address: ""                          # optional: bind to specific local IP (default: 0.0.0.0)
private_key_file: /lanecove/peer-1.key   # absolute path inside container
pre_shared_key: some-psk
verbose: false
keepalive_interval: 25               # seconds between keepalive packets
rekey_after: 180                     # seconds before initiating a rekey
reconnect_interval: 30               # seconds between reconnect attempts
session_expiry: 540                  # seconds before an idle session expires
prev_key_grace: 90                   # seconds old key is retained after rekey
handshake_timeout: 5                 # seconds before pending handshake is abandoned
handshake_cooldown: 5                # seconds between handshake attempts to same peer

peers:
  - public_key: <hex>
    endpoint: 1.2.3.4:5040          # omit for inbound-only peers
    allowed_ips:
      - 10.9.0.0/24
```

### Session Management
- Sessions are stored in a flat array (`sessions[]`, max 64)
- Slot reuse: existing slot found by pub key first, then addr, then free slot
- Outbound peers checked every 10 seconds; reconnect attempted every `reconnect_interval` seconds (default: 30) on failure
- Rekeying initiated at 80% of `rekey_after` (default: 180s), i.e. at ~144s
- Handshake is **non-blocking** (async): initiation and response are split across epoll iterations
- Simultaneous rekey collisions resolved by tie-breaking: higher public key wins
- **Previous session key grace period** (`prev_key_grace`, default 90s): responder retains old key as decrypt fallback after rekeying, eliminating packet loss during the initiator's response window (matches WireGuard's overlap window)
- **Pre-generated ephemeral keypair**: responder pre-generates the next X25519 ephemeral keypair at startup and after each handshake, so keygen never blocks the event loop on the hot path

### Handshake Wire Format
```
[8 magic][32 eph_pub][48 AES-256-GCM(static_pub)][32 HMAC-SHA256(psk,...)]?
```

- **`eph_pub`** — fresh X25519 ephemeral public key, generated per handshake
- **`AES-256-GCM(static_pub)`** — static public key encrypted to hide identity from passive observers:
  - Initiator encrypts its static_pub with `key = SHA-256(DH(eph_c, server_static))`
  - Responder encrypts its static_pub with `key = SHA-256(DH(eph_s, eph_c))`
  - Zero IV is safe because the encryption key is derived from a fresh ephemeral DH every time
- **`HMAC-SHA256`** — optional PSK authentication over `[magic][eph_pub][encrypted_static_pub]`; omitted if no PSK

### Session Key Derivation
```
SHA-256(
  DH(eph_c, eph_s)          ||
  DH(static_c, eph_s)       ||
  DH(eph_c, static_s)       ||
  client_eph_pub            ||
  server_eph_pub            ||
  client_static_pub         ||
  server_static_pub
)
```

### Data Packets
Each datagram on the wire is:
```
[12-byte IV][AES-256-GCM ciphertext of (8-byte magic + 8-byte seq + payload)][16-byte GCM tag]
```
Magic is `0xdeadbeefcafebabe`. Packets with a bad magic header, invalid GCM tag, or replayed/too-old sequence number are silently dropped. The receiver uses a **2048-bit sliding window** (`32 × uint64_t`) to detect replays.

### AllowedIPs Routing
On the TUN→UDP path, destination IP is looked up using longest-prefix match across all peer session route tables. On the UDP→TUN path, source IP is validated against the sending peer's AllowedIPs — packets with an unexpected source IP are dropped.

## Logging
Custom `fprintf`-based logging defined in `common.h`. Global `log_level` variable (0=INFO, 1=DEBUG). Set `verbose: true` in config to enable debug output. All log lines include a timestamp:
```
2026-04-23 14:05:32 [INFO]  Peer connected: 1.2.3.4:5040 (key=deadbeef...)
2026-04-23 14:05:32 [WARN]  Replay detected from 1.2.3.4:5040 (seq=42) — dropping
```

## Build
```
make all                # compile lanecove binary
make test               # run unit tests natively (requires libssl-dev, libyaml-dev)
make test-image         # build cached Docker image for testing (lanecove-tunnel-test:latest)
make test-using-docker  # run unit tests via Docker (no local deps required)
make image              # build Docker image (lanecove-tunnel-peer:latest)
make run-shell          # open a bash shell in a fresh container
make deb                # build .deb package (output: build/lanecove-tunnel_1.0.0_amd64.deb)
make rpm                # build .rpm package (output: build/rpm/RPMS/)
make clean              # remove compiled binary and build artifacts
```

## Running With Docker
```bash
# Setup (once)
make image

# Local testing (all on one Mac — 3 terminals)
./scripts/run-relay-in-docker.sh
./scripts/run-peer-1-in-docker.sh
./scripts/run-peer-2-in-docker.sh
```

## Docker
- `Dockerfile` — multi-stage build (`debian:bookworm-slim`); includes iproute2, nginx, curl, ping, ifconfig, ssh, Envoy proxy, libyaml (~299 MB total); bundles `config/` into the image
- `scripts/docker-entrypoint.sh` — creates TUN, starts nginx, optionally starts Envoy (when `ENVOY_UPSTREAM_HOST` is set), execs `lanecove -c $PEER_CONFIG`
- `scripts/common.sh` — shared helpers: OpenSSL detection (Homebrew on macOS), `extract_pub`, `detect_local_ip` (macOS/Linux)
- `scripts/lanecove-extract-keys-hex.sh <file.key>` — prints private and public key hex from an X25519 `.key` PEM file
- `scripts/lanecove-extract-pubkey-hex.sh <file.crt>` — prints public key hex from an X25519 `.crt` PEM file
- `scripts/lanecove-generate-peer-keys.sh <name> [name2 ...]` — generates X25519 key pairs (`.key` / `.crt`) for each given name
- `envoy.yaml.tmpl` — Envoy static config template; two listeners sharing one upstream cluster:
  - **TCP proxy** on `0.0.0.0:15040` — transparent L4 pass-through, one upstream connection per downstream connection
  - **HTTP proxy** on `0.0.0.0:15050` — L7 with upstream connection pooling (~130 requests/connection); eliminates per-request TCP handshake cost through the tunnel; recommended for HTTP workloads
  - Admin interface on `0.0.0.0:9901`
- `scripts/lanecove-create-tunnel.sh <tunnel> <ip/cidr> [routes...]` — creates TUN interface, assigns overlay IP, disables ICMP redirects
- `scripts/run-relay.sh` — native Linux wrapper: creates TUN (`lanecove0`, `10.9.0.1/24`) and starts relay from `config/relay.yaml`
- `scripts/run-relay-in-docker.sh` — runs relay container from `config/relay.yaml`; mounts key, exposes UDP 5040 and Envoy admin 9901
- `scripts/run-peer-1-in-docker.sh` — runs peer-1 container from `config/peer-1.yaml`; mounts key, exposes ports for UDP tunnel, Envoy TCP/HTTP proxy, and admin
- `scripts/run-peer-2-in-docker.sh` — same as peer-1 but for peer-2
- `scripts/exec-shell-to-relay-container.sh` — open a bash shell in the running relay container
- `scripts/exec-shell-to-peer-1-container.sh` / `scripts/exec-shell-to-peer-2-container.sh` — open a bash shell in a running peer container
- `scripts/test-tunnel-relay.sh` — ping + curl both peers (10.9.0.2, 10.9.0.3) from relay
- `scripts/test-tunnel-using-peer-1.sh [target_ip]` — ping + curl from peer-1 (default target: 10.9.0.3)
- `scripts/test-tunnel-using-peer-2.sh [target_ip]` — ping + curl from peer-2 (default target: 10.9.0.2)
- `scripts/create-tag.sh` — creates a git tag; auto-increments the rc number from the latest tag if `VERSION` env var is not set

## Development Utilities

- `sync-to-anywhere.sh` — watches the project directory on macOS using `fswatch` and rsyncs to a remote Linux machine on every change; edit the `REMOTE` variable to point to your Linux host

## CLI Options

### lanecove binary
```
lanecove [-c <config.yaml>]
```
| Option | Description |
|--------|-------------|
| `-c`   | YAML config file (default: `peer.yaml`) |

## Tunnel Interface
- Interface name: `lanecove0`
- Overlay network: `10.9.0.0/24` (relay=`10.9.0.1`, peer-1=`10.9.0.2`, peer-2=`10.9.0.3`)

## Docker Environment Variables
Consumed by `scripts/docker-entrypoint.sh`:

| Variable | Default | Description |
|----------|---------|-------------|
| `TUNNEL_NAME` | `lanecove0` | TUN interface name |
| `PEER_IP` | `10.9.0.1/24` | This peer's overlay IP/CIDR |
| `PEER_ROUTES` | _(none)_ | Space-separated extra CIDRs to route via TUN |
| `PEER_CONFIG` | `peer.yaml` | Path to YAML config file inside container |
| `ENVOY_UPSTREAM_HOST` | — | Upstream host for Envoy proxy; if unset, Envoy is not started |
| `ENVOY_UPSTREAM_PORT` | `80` | Upstream port for Envoy proxy |

## Platform Notes
- Requires Linux kernel (uses `linux/if_tun.h` and `/dev/net/tun`)
- Does not compile on macOS — use Docker for building and running
- Docker containers require `--cap-add=NET_ADMIN` and `--device=/dev/net/tun`
- Requires libssl-dev (OpenSSL) for AES-256-GCM and X25519, and libyaml-dev for YAML config parsing


## Port Mapping (Docker)
| Service | Container port | relay host port | peer-1 host port | peer-2 host port |
|---------|---------------|-----------------|-----------------|-----------------|
| UDP tunnel | 5040 | 5040 | 5042 | 5043 |
| nginx | 80 | — | — | — |
| Envoy TCP proxy | 15040 | — | 15042 | 15043 |
| Envoy HTTP proxy | 15050 | — | 15052 | 15053 |
| Envoy admin | 9901 | 9901 | 9902 | 9903 |
