## lanecove-tunnel

[![build](https://github.com/jecklgamis/lanecove-tunnel/actions/workflows/build.yaml/badge.svg)](https://github.com/jecklgamis/lanecove-tunnel/actions/workflows/build.yaml)

📖 [User Guide](https://jecklgamis.github.io/lanecove-tunnel/)

A simple Linux **hub-and-spoke layer 3 overlay network** using a TUN virtual interface over UDP. Implements a basic VPN for learning purposes.
Warning: not for production use.

Inspired by [WireGuard](https://www.wireguard.com/), this project explores similar concepts — X25519 key exchange, identity hiding, AllowedIPs routing, and session rekeying — reimplemented from scratch in C as a learning exercise.

It creates a virtual IP network (`10.9.0.0/24`) layered on top of an existing underlay network, with traffic encapsulated inside UDP datagrams. Layer 3 means the tunnel operates at the IP (network) layer — it forwards raw IP packets between peers, not Ethernet frames. Each peer has a TUN interface with an IP address, and routing rules direct traffic through it. Broadcast, multicast, and non-IP traffic are not supported.

The topology is **hub-and-spoke**: peers behind NAT connect outbound to a relay with a public IP, and all traffic between peers transits through the relay. The relay forwards packets between peers in user space — no kernel IP forwarding required. Peers do not connect directly to each other (no NAT hole-punching).

```
                        ┌─────────────────────────┐
                        │  relay (public IP)       │
                        │  overlay: 10.9.0.1       │
                        │  UDP :5040               │
                        └────────────┬────────────┘
                                     │
                    ┌────────────────┴────────────────┐
                    │ UDP (encrypted)                  │ UDP (encrypted)
                    │                                  │
        ┌───────────┴──────────┐          ┌───────────┴──────────┐
        │  peer-1 (behind NAT) │          │  peer-2 (behind NAT) │
        │  overlay: 10.9.0.2   │          │  overlay: 10.9.0.3   │
        └──────────────────────┘          └──────────────────────┘
```

Peers communicate with each other via the relay — traffic from peer-1 to peer-2 travels peer-1 → relay → peer-2.

## Common Use Cases

- **Connecting peers behind NAT** — machines that can't reach each other directly (home networks, cloud VMs, mobile) communicate securely through a relay with a public IP.
- **Secure service access** — a peer runs a service (e.g. a web server or database) accessible only over the overlay IP, keeping it off the public internet.
- **Multi-site connectivity** — linking servers across different cloud providers or regions through a single relay without needing cloud VPN products.
- **Development and testing** — exposing a local dev machine's services to a remote peer (e.g. a CI runner or a colleague's machine) without port forwarding.
- **Learning and experimentation** — the primary goal of this project: understanding how VPN protocols work (DH key exchange, AES-GCM, replay protection, rekeying).

The single-threaded relay is suited for low-to-moderate traffic between a small number of peers, not high-throughput production workloads.

## Features

### Security
- **X25519 Diffie-Hellman key exchange** — ephemeral + static key pairs for forward secrecy and mutual authentication
- **AES-256-GCM encryption** — all tunnel traffic is authenticated and encrypted
- **Identity hiding** — static public keys are encrypted inside the handshake; passive observers cannot identify peers
- **PSK authentication** — optional HMAC-SHA256 over the handshake using a pre-shared key
- **Replay protection** — 2048-bit sliding window per session rejects replayed or reordered packets
- **AllowedIPs routing** — enforces a per-peer IP allowlist; packets with unexpected source IPs are dropped
- **Session rekeying** — peers re-handshake every 3 minutes, rotating the session key automatically
- **DoS mitigations** — 5-second handshake cooldown per address and per public key

### Limitations
- **Linux only** — uses `linux/if_tun.h` and `/dev/net/tun`; does not compile on macOS (use Docker)
- **IPv4 only** — TUN packets are validated as IPv4; IPv6 and non-IP traffic are dropped
- **UDP transport** — no packet ordering guarantees; packet loss is not retransmitted
- **Single-threaded** — one epoll loop handles all I/O; not designed for high throughput
- **Learning project** — not audited, not hardened for production use

## Requirements
Linux (tested on Ubuntu 22.04 LTS), gcc, make, iproute2, libssl-dev, libyaml-dev

```
sudo apt install gcc make iproute2 libssl-dev libyaml-dev
```

## Building
```
make all              # build lanecove binary
make test             # run unit tests natively (requires libssl-dev, libyaml-dev)
make test-image       # build cached Docker image for testing (lanecove-tunnel-test:latest)
make test-using-docker  # run unit tests via Docker (no local deps required)
make image            # build Docker image (lanecove-tunnel-peer:latest)
make deb              # build .deb package (output: build/lanecove-tunnel_1.0.0_amd64.deb)
make rpm              # build .rpm package (output: build/rpm/RPMS/)
make clean            # remove lanecove binary and build artifacts
```

## Configuration

The `lanecove` binary is configured via a YAML file. Sample configs are in `config/`.

**Relay** (`config/relay.yaml`) — inbound-only, no `endpoint`:
```yaml
interface: lanecove0
port: 5040
private_key_file: /lanecove/relay.key
pre_shared_key: some-psk
verbose: false

peers:
  - public_key: <peer-1-pubkey-hex>
    allowed_ips:
      - 10.9.0.2/32
  - public_key: <peer-2-pubkey-hex>
    allowed_ips:
      - 10.9.0.3/32
```

**Peer 1** (`config/peer-1.yaml`) — connects outbound to relay:
```yaml
interface: lanecove0
port: 5040
private_key_file: /lanecove/peer-1.key
pre_shared_key: some-psk
verbose: false

peers:
  - public_key: <relay-pubkey-hex>
    endpoint: <relay-host-or-ip>:5040
    allowed_ips:
      - 10.9.0.0/24
```

**Peer 2** (`config/peer-2.yaml`) — same as peer-1 with its own key:
```yaml
interface: lanecove0
port: 5040
private_key_file: /lanecove/peer-2.key
pre_shared_key: some-psk
verbose: false

peers:
  - public_key: <relay-pubkey-hex>
    endpoint: <relay-host-or-ip>:5040
    allowed_ips:
      - 10.9.0.0/24
```

**Top-level keys:**

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `interface` | Yes | — | TUN interface name (e.g. `lanecove0`) |
| `port` | Yes | — | UDP port to bind |
| `address` | No | `0.0.0.0` | Local IP address to bind the UDP socket to |
| `private_key_file` | Yes | — | Path to this peer's X25519 private key PEM file |
| `pre_shared_key` | No | — | Optional PSK for HMAC authentication of handshakes |
| `verbose` | No | `false` | Set to `true` to enable debug logging |
| `keepalive_interval` | No | `25` | Seconds between keepalive packets |
| `rekey_after` | No | `180` | Seconds before initiating a rekey |
| `reconnect_interval` | No | `30` | Seconds between reconnect attempts to outbound peers |
| `session_expiry` | No | `540` | Seconds before an idle session is considered expired |
| `prev_key_grace` | No | `90` | Seconds the old session key is retained after rekeying |
| `handshake_timeout` | No | `5` | Seconds before a pending handshake is considered failed |
| `handshake_cooldown` | No | `5` | Seconds between handshake attempts to the same peer |
| `peers` | No | — | List of peer entries (omit or leave empty for inbound-only) |

**Per-peer keys (under `peers:`):**

| Key | Required | Description |
|-----|----------|-------------|
| `public_key` | Yes | Peer's X25519 public key (hex-encoded) |
| `endpoint` | No | `host:port` to connect to; omit for inbound-only peers (e.g. relay) |
| `allowed_ips` | Yes | List of CIDR prefixes allowed from this peer (used for routing and source validation) |

The relay uses `/32` per peer because it only accepts packets sourced from each peer's specific overlay IP. Peers use `/24` (the full subnet) because all overlay traffic — including traffic destined for other peers — is routed through the relay as the single gateway.

## Key Generation

```bash
./scripts/lanecove-generate-peer-keys.sh relay peer-1 peer-2
# produces: config/relay.key/.crt, config/peer-1.key/.crt, config/peer-2.key/.crt

# Inspect key hex values (private + public) from a .key file
./scripts/lanecove-extract-keys-hex.sh config/peer-1.key

# Extract just the public key hex from a .crt file
./scripts/lanecove-extract-pubkey-hex.sh config/peer-1.crt
```

Distribute public keys (`.crt` files only — never share `.key` files):

| Machine | Needs |
|---------|-------|
| relay   | `relay.key`, `peer-1.crt`, `peer-2.crt` |
| peer-1  | `peer-1.key`, `relay.crt` |
| peer-2  | `peer-2.key`, `relay.crt` |

## Running With Docker

**Setup (once):**
```bash
make image
```

**Local testing (all on one machine — 3 terminals):**

> Before running, update the `endpoint` in `config/peer-1.yaml` and `config/peer-2.yaml` to point to your relay's host or IP address.

```bash
./scripts/run-relay-in-docker.sh
./scripts/run-peer-1-in-docker.sh
./scripts/run-peer-2-in-docker.sh
```

**Testing the tunnel:**
```bash
./scripts/test-tunnel-using-peer-1.sh       # ping + curl peer-2 from peer-1
./scripts/test-tunnel-using-peer-2.sh       # ping + curl peer-1 from peer-2
./scripts/test-tunnel-relay.sh              # ping + curl both peers from relay
```

**Shell access:**
```bash
./scripts/exec-shell-to-relay-container.sh
./scripts/exec-shell-to-peer-1-container.sh
./scripts/exec-shell-to-peer-2-container.sh
```

### Port Mapping

| Service | Container port | relay host | peer-1 host | peer-2 host |
|---------|---------------|------------|-------------|-------------|
| UDP tunnel | 5040 | 5040 | 5042 | 5043 |
| nginx | 80 | — | — | — |
| Envoy TCP proxy | 15040 | — | 15042 | 15043 |
| Envoy HTTP proxy | 15050 | — | 15052 | 15053 |
| Envoy admin | 9901 | 9901 | 9902 | 9903 |

### Envoy Proxy

Each peer container includes an [Envoy](https://www.envoyproxy.io/) proxy. When `ENVOY_UPSTREAM_HOST` is set, Envoy starts and forwards connections to the configured upstream.

Two listeners:

| Listener | Port | Mode |
|----------|------|------|
| TCP proxy | 15040 | L4 pass-through |
| HTTP proxy | 15050 | L7 with connection pooling (~130 req/connection) |
| Admin | 9901 | HTTP stats |

```bash
curl http://localhost:15052   # HTTP proxy through peer-1 → peer-2's nginx
curl http://localhost:15042   # TCP proxy
curl http://localhost:9902/stats  # Envoy admin
```

### Docker Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TUNNEL_NAME` | `lanecove0` | TUN interface name |
| `PEER_IP` | `10.9.0.1/24` | This peer's overlay IP/CIDR |
| `PEER_ROUTES` | _(none)_ | Space-separated extra CIDRs to route via TUN |
| `PEER_CONFIG` | `peer.yaml` | Path to YAML config file inside container |
| `ENVOY_UPSTREAM_HOST` | — | Upstream host for Envoy; if unset, Envoy is not started |
| `ENVOY_UPSTREAM_PORT` | `80` | Upstream port for Envoy |

## Installing via .deb Package

Build and install the package on each machine:

```bash
make deb
sudo dpkg -i build/lanecove-tunnel_1.0.0_amd64.deb
```

Edit the config for the role this machine will play:
```bash
sudo vi /etc/lanecove/relay.yaml    # on the relay machine
sudo vi /etc/lanecove/peer-1.yaml   # on peer-1 machine
sudo vi /etc/lanecove/peer-2.yaml   # on peer-2 machine
```

Enable and start the appropriate service:
```bash
sudo systemctl enable --now lanecove-relay    # relay machine
sudo systemctl enable --now lanecove-peer-1   # peer-1 machine
sudo systemctl enable --now lanecove-peer-2   # peer-2 machine
```

To uninstall:
```bash
sudo dpkg -r lanecove-tunnel
```

## Installing via .rpm Package (Red Hat / Fedora / CentOS)

Build and install the package on each machine:

```bash
make rpm
sudo rpm -i build/rpm/RPMS/x86_64/lanecove-tunnel-1.0.0-1.x86_64.rpm
```

Edit the config for the role this machine will play:
```bash
sudo vi /etc/lanecove/relay.yaml    # on the relay machine
sudo vi /etc/lanecove/peer-1.yaml   # on peer-1 machine
sudo vi /etc/lanecove/peer-2.yaml   # on peer-2 machine
```

Enable and start the appropriate service:
```bash
sudo systemctl enable --now lanecove-relay    # relay machine
sudo systemctl enable --now lanecove-peer-1   # peer-1 machine
sudo systemctl enable --now lanecove-peer-2   # peer-2 machine
```

To uninstall:
```bash
sudo rpm -e lanecove-tunnel
```

## Running Natively (Linux)

Each peer (relay, peer-1, peer-2) must run on a **separate machine**. Running more than one on the same machine would conflict on the `lanecove0` TUN device name and the UDP port.

The `lanecove` binary can run as a non-root user if the TUN interface is pre-created with the correct owner:

```bash
# Generate keys (once)
./scripts/lanecove-generate-peer-keys.sh relay peer-1 peer-2

# Update the `endpoint` in config/peer-1.yaml and config/peer-2.yaml
# to point to your relay's host or IP address before starting peers.

# Relay
./scripts/run-relay.sh

# peer-1
./scripts/run-peer-1.sh

# peer-2
./scripts/run-peer-2.sh
```

`lanecove-create-tunnel.sh` creates the TUN interface owned by the calling user (`$SUDO_USER`), so `peer` can open it without `CAP_NET_ADMIN`.

---

## Security Details

### Handshake Flow

```
INITIATOR (peer-1)                             RESPONDER (relay)
──────────────────                             ─────────────────

Generate eph_c keypair
Encrypt static_pub_c with
  SHA-256(DH(eph_c, static_pub_s))
Compute HMAC-SHA256(psk, ...)

  ──── HANDSHAKE INIT ────────────────────────────>
       [8 magic]
       [32 eph_pub_c]
       [48 AES-GCM(static_pub_c)]
       [32 HMAC(psk)]  (if PSK)

                                                Verify HMAC (if PSK)
                                                Decrypt static_pub_c
                                                  using DH(eph_c, static_s)
                                                Look up peer config by static_pub_c
                                                Generate eph_s keypair (pre-generated)
                                                Encrypt static_pub_s with
                                                  SHA-256(DH(eph_s, eph_c))
                                                Derive session key (see below)
                                                Save old key as prev_key (90s grace)
                                                Reset replay window
                                                Pre-generate next eph keypair

  <─── HANDSHAKE RESPONSE ────────────────────────
       [8 magic]
       [32 eph_pub_s]
       [48 AES-GCM(static_pub_s)]
       [32 HMAC(psk)]  (if PSK)

Verify HMAC (if PSK)
Decrypt static_pub_s
  using DH(eph_s, eph_c)
Verify static_pub_s matches config
Derive same session key
Save old key as prev_key (90s grace)
Reset replay window, send_seq=0

  ──── DATA (AES-256-GCM, seq=1) ─────────────────>
  <─── DATA (AES-256-GCM, seq=1) ─────────────────
```

Both sides retain the old session key for 90 seconds (`prev_key` grace period) to decrypt in-flight packets during the switchover. Prev-key packets bypass the replay window to prevent old sequence numbers from poisoning the new session.

### Handshake Wire Format

```
[8 magic][32 eph_pub][48 AES-256-GCM(static_pub)][32 HMAC-SHA256(psk,...)]?
```

### Session Key Derivation

```
SHA-256(
  DH(eph_c, eph_s)        ||
  DH(static_c, eph_s)     ||
  DH(eph_c, static_s)     ||
  client_eph_pub          ||
  server_eph_pub          ||
  client_static_pub       ||
  server_static_pub
)
```

### Data Packets

```
[12-byte IV][AES-256-GCM ciphertext of (8-byte magic + 8-byte seq + payload)][16-byte GCM tag]
```

Magic is `0xdeadbeefcafebabe`. Packets with a bad magic header, invalid GCM tag, or replayed sequence number are silently dropped.

## Development Utilities

### sync-on-changes.sh

Watches source files on macOS and rsyncs the project to a remote Linux machine on every change. Useful when developing on a Mac where the lanecove binary cannot be compiled or run natively.

```bash
./sync-on-changes.sh
```

Requires [fswatch](https://github.com/emcrisostomo/fswatch) (`brew install fswatch`) and SSH access to the remote machine. Edit the `REMOTE` variable at the top of the script to point to your Linux machine.

---

## Comparison with Alternatives

| | **lanecove-tunnel** | **WireGuard** | **OpenVPN** | **IPsec (strongSwan)** | **GRE** | **Tinc** |
|---|---|---|---|---|---|---|
| **Layer** | L3 (TUN) | L3 (TUN) | L3/L2 (TUN/TAP) | L3 | L3 | L2/L3 |
| **Transport** | UDP | UDP | UDP/TCP | ESP/UDP | IP proto 47 | UDP/TCP |
| **Topology** | Hub-and-spoke | Mesh or point-to-point | Hub-and-spoke or mesh | Point-to-point or mesh | Point-to-point | Mesh |
| **Key exchange** | X25519 (custom) | X25519 (Noise protocol) | TLS (RSA/ECDSA) | IKEv2 (RSA/ECC) | None | Ed25519 |
| **Encryption** | AES-256-GCM | ChaCha20-Poly1305 | AES-256-GCM | AES-256-GCM | None | AES-256-GCM |
| **Identity hiding** | Yes | Yes | No | No | No | No |
| **NAT traversal** | Yes (outbound peers) | Yes | Yes | Partial (NAT-T) | No | Yes |
| **Replay protection** | Yes (2048-bit window) | Yes | Yes | Yes | No | Yes |
| **PSK support** | Yes | Yes | No | Yes | No | No |
| **Rekeying** | Every 3 min | Every 3 min (180s) | Configurable | IKEv2 rekeying | No | No |
| **Kernel module** | No (userspace) | Yes | No (userspace) | Partial (xfrm) | Yes | No |
| **IPv6 support** | No | Yes | Yes | Yes | Yes | Yes |
| **Platforms** | Linux only | Linux, macOS, Windows, BSD | Cross-platform | Cross-platform | Linux | Cross-platform |
| **Throughput** | Low (single-threaded) | High (kernel) | Medium | High (kernel) | High (kernel) | Medium |
| **Lines of code** | ~1,200 | ~4,000 (kernel) | ~100,000+ | ~500,000+ | — | ~50,000 |
| **Purpose** | Learning | Production | Production | Production | Infrastructure | Mesh VPN |

**vs WireGuard** — Most similar in design (X25519, AES-256-GCM, identity hiding, AllowedIPs, rekeying). WireGuard is production-ready, runs in the kernel, and supports direct peer-to-peer. lanecove-tunnel is relay-only, Linux-only, and single-threaded userspace.

**vs OpenVPN** — OpenVPN supports TCP/UDP, runs on all platforms, and uses TLS for the control channel. Requires a PKI. More configurable and battle-tested but significantly more complex to operate.

**vs IPsec** — Enterprise standard with IKEv2, hardware acceleration, and kernel-level performance. Integrates with existing PKI. Configuration is notoriously complex. No comparison in features or throughput.

**vs GRE** — Pure encapsulation with no encryption or authentication. Extremely fast (kernel), used in data centre and ISP infrastructure where encryption is handled at another layer. Does not handle NAT.

**vs Tinc** — Full mesh routing (peers discover direct paths without a relay) and cross-platform. Lacks the modern cryptographic design (no Noise-style handshake or identity hiding).

| Scenario | Recommendation |
|----------|---------------|
| Production VPN, any scale | WireGuard |
| Enterprise, existing PKI | IPsec (strongSwan) |
| Legacy/cross-platform compatibility | OpenVPN |
| Data centre encapsulation (no encryption needed) | GRE |
| Dynamic mesh between many nodes | Tinc |
| Learning how VPNs work | **lanecove-tunnel** |

---

## Security Review

A security review was conducted against the codebase covering memory safety, injection vulnerabilities, and cryptographic correctness. No high-confidence exploitable vulnerabilities were found.

| Finding | File | Verdict |
|---------|------|---------|
| `strcpy()` after TUNSETIFF ioctl | `src/common.c` | False positive — `ifr_name` is kernel-provided and always null-terminated; Linux enforces a hard 15-char limit on interface names |
| Unquoted `${PEER_ROUTES}` expansion | `scripts/docker-entrypoint.sh` | False positive — intentional word-splitting of a trusted operator-set Docker env var; no untrusted input path |
| `TUNNEL_NAME` in sysctl command | `scripts/lanecove-create-tunnel.sh` | False positive — always hardcoded or set by the container operator who already has root |
| Unbounded `sprintf()` in `bytes_to_hex()` | `src/common.c` | False positive — `len` is always a compile-time constant; no attacker-controlled input reaches this function |

The cryptographic protocol (X25519, AES-256-GCM, replay protection) was reviewed and no bypass paths were identified.

---

## References
* https://www.kernel.org/doc/Documentation/networking/tuntap.txt
* https://www.wireguard.com/papers/wireguard.pdf
