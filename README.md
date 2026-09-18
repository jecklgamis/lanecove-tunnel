## lanecove-tunnel

[![build](https://github.com/jecklgamis/lanecove-tunnel/actions/workflows/build.yaml/badge.svg)](https://github.com/jecklgamis/lanecove-tunnel/actions/workflows/build.yaml)

📖 [User Guide](https://jecklgamis.github.io/lanecove-tunnel/)

A simple Linux **hub-and-spoke layer 3 overlay network** using a TUN virtual interface over UDP. A working VPN implementation with a deliberately small feature set.

Inspired by [WireGuard](https://www.wireguard.com/), this project implements similar concepts — X25519 key exchange, identity hiding, AllowedIPs routing, and session rekeying — reimplemented from scratch in C.

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
- **Not audited** — not hardened for production use

## Requirements
Linux (tested on Ubuntu 22.04 LTS), gcc, make, iproute2, libssl-dev, libyaml-dev

```
sudo apt install gcc make iproute2 libssl-dev libyaml-dev
```

## Running Natively (Linux)

Each peer runs on its own Linux host (or its own network namespace/VM). Running relay + both peers as bare native processes side by side on **one** host does not work: once `10.9.0.2` and `10.9.0.3` are both assigned to interfaces on the same machine, the kernel treats them as local addresses and any reply generated on one TUN device gets routed straight back via `lo` instead of going out that device to be re-encrypted — the tunnel never sees the return traffic, no matter how ports/interfaces/configs are set up. This isn't specific to lanecove-tunnel; the same thing happens with WireGuard or any other TUN-based overlay if you assign multiple overlapping-subnet addresses on one host's routing table. For same-machine local testing, use [Running With Docker](#running-with-docker) below, which gives each peer its own network namespace via a container.

**1. Install dependencies** (all three hosts)
```bash
sudo apt install libssl-dev libyaml-dev iproute2
```

**2. Build** (all three hosts, or build once and copy the `lanecove` binary over)
```bash
make all
```

**3. Copy keys and config, create the TUN interface, and edit `endpoint:` — each host only needs its own peer's files.** Assume the relay's public/reachable address is `203.0.113.10`.

**On the relay host:**
```bash
sudo mkdir -p /etc/lanecove
sudo cp config/relay.key config/relay.yaml /etc/lanecove/
sudo ./scripts/lanecove-create-tunnel.sh lanecove0 10.9.0.1/24
sudo ./lanecove -c /etc/lanecove/relay.yaml
```

**On the peer-1 host:**
```bash
sudo mkdir -p /etc/lanecove
sudo cp config/peer-1.key config/peer-1.yaml /etc/lanecove/
sudo ./scripts/lanecove-create-tunnel.sh lanecove0 10.9.0.2/24 10.9.0.0/24
# edit /etc/lanecove/peer-1.yaml: peers[0].endpoint: 203.0.113.10:5040
sudo ./lanecove -c /etc/lanecove/peer-1.yaml
```

**On the peer-2 host:**
```bash
sudo mkdir -p /etc/lanecove
sudo cp config/peer-2.key config/peer-2.yaml /etc/lanecove/
sudo ./scripts/lanecove-create-tunnel.sh lanecove0 10.9.0.3/24 10.9.0.0/24
# edit /etc/lanecove/peer-2.yaml: peers[0].endpoint: 203.0.113.10:5040
sudo ./lanecove -c /etc/lanecove/peer-2.yaml
```

**4. Test** (from the relay host)
```bash
ping 10.9.0.2   # relay → peer-1
ping 10.9.0.3   # relay → peer-2
```

---

## Running With Docker

**Setup (once):**
```bash
make image
```

**Local testing (all on one machine — 3 terminals):**

All three containers join a shared `lanecove-net` Docker network; the peer scripts resolve the relay by its container name automatically, so no config editing is needed for this local flow.

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
| **Lines of code** | ~1,600 | ~4,000 (kernel) | ~100,000+ | ~500,000+ | — | ~50,000 |
| **Purpose** | Simple/small-scale | Production | Production | Production | Infrastructure | Mesh VPN |

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
