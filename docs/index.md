---
title: lanecove-tunnel
layout: default
---

# lanecove-tunnel

A simple Linux hub-and-spoke layer 3 overlay network using a TUN virtual interface over UDP.

```
                    ┌─────────────────────────┐
                    │  relay (public IP)       │
                    │  overlay: 10.9.0.1       │
                    │  UDP :5040               │
                    └────────────┬────────────┘
                                 │
            ┌────────────────────┴────────────────┐
            │                                      │
┌───────────┴──────────┐              ┌────────────┴─────────┐
│  peer-1 (behind NAT) │              │  peer-2 (behind NAT) │
│  overlay: 10.9.0.2   │              │  overlay: 10.9.0.3   │
└──────────────────────┘              └──────────────────────┘
```

Peers behind NAT connect outbound to a relay with a public IP. All peer-to-peer traffic transits through the relay.

---

## Installation

Download the latest release package from the [releases page](https://github.com/jecklgamis/lanecove-tunnel/releases).

### Debian / Ubuntu

```bash
sudo dpkg -i lanecove-tunnel_<version>_amd64.deb
```

### Red Hat / Fedora / CentOS

```bash
sudo rpm -i lanecove-tunnel-<version>-1.x86_64.rpm
```

Both packages install:

| Path | Description |
|------|-------------|
| `/usr/bin/lanecove-peer` | The tunnel binary |
| `/usr/bin/lanecove-generate-peer-keys.sh` | Key pair generator |
| `/usr/bin/lanecove-extract-keys-hex.sh` | Extract private + public key hex |
| `/usr/bin/lanecove-extract-pubkey-hex.sh` | Extract public key hex from `.crt` |
| `/usr/share/lanecove-tunnel/lanecove-create-tunnel.sh` | TUN interface setup helper |
| `/etc/lanecove/relay.yaml` | Relay config template |
| `/etc/lanecove/peer.yaml` | Generic peer config template |
| `/etc/lanecove/peer-1.yaml` | Peer-1 config template |
| `/etc/lanecove/peer-2.yaml` | Peer-2 config template |

---

## Key Generation

Each node (relay and every peer) needs its own X25519 key pair. Run this once on any machine with the package installed:

```bash
lanecove-generate-peer-keys.sh relay peer-1 peer-2
```

This produces a `.key` (private) and `.crt` (public) file for each name. Copy the files to each machine as follows:

| Machine | Files needed |
|---------|-------------|
| relay   | `relay.key`, `peer-1.crt`, `peer-2.crt` |
| peer-1  | `peer-1.key`, `relay.crt` |
| peer-2  | `peer-2.key`, `relay.crt` |

**Never share `.key` files.** Only distribute `.crt` (public key) files.

Place keys in a secure location, e.g. `/etc/lanecove/`:

```bash
sudo install -m 640 -o root -g root relay.key /etc/lanecove/relay.key
```

To extract the public key hex from a `.crt` file (needed when editing configs):

```bash
lanecove-extract-pubkey-hex.sh relay.crt
```

---

## Configuration

### Relay

The relay has a public IP and accepts inbound connections from peers. It does not have an `endpoint` set — it never initiates outbound connections.

Edit `/etc/lanecove/relay.yaml`:

```yaml
interface: lanecove0
port: 5040
private_key_file: /etc/lanecove/relay.key
pre_shared_key: change-me
verbose: false
keepalive_interval: 25
rekey_after: 180
reconnect_interval: 30
session_expiry: 540
prev_key_grace: 90
handshake_timeout: 5
handshake_cooldown: 5

peers:
  - public_key: <peer-1-public-key-hex>
    allowed_ips:
      - 10.9.0.2/32
  - public_key: <peer-2-public-key-hex>
    allowed_ips:
      - 10.9.0.3/32
```

- `pre_shared_key` — must match on all nodes. Used for HMAC authentication of handshakes.
- `allowed_ips` — the relay uses `/32` per peer, accepting packets only from each peer's specific overlay IP.
- No `endpoint` — the relay never initiates connections.
- All timing fields are optional; values shown are the defaults.

### Peer

Each peer connects outbound to the relay. It must know the relay's public key and address.

Edit `/etc/lanecove/peer.yaml` (or `peer-1.yaml`, `peer-2.yaml`):

```yaml
interface: lanecove0
port: 5040
private_key_file: /etc/lanecove/peer-1.key
pre_shared_key: change-me
verbose: false
keepalive_interval: 25
rekey_after: 180
reconnect_interval: 30
session_expiry: 540
prev_key_grace: 90
handshake_timeout: 5
handshake_cooldown: 5

peers:
  - public_key: <relay-public-key-hex>
    endpoint: <relay-host-or-ip>:5040
    allowed_ips:
      - 10.9.0.0/24
```

- `endpoint` — the relay's public hostname or IP and UDP port. Required on peers; omit on the relay.
- `allowed_ips` — peers use `/24` (the full overlay subnet) so all overlay traffic is routed through the relay.
- `pre_shared_key` — must match the relay and all other peers.
- All timing fields are optional; values shown are the defaults.

### Config Reference

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `interface` | Yes | — | TUN interface name |
| `port` | Yes | — | UDP port to bind |
| `address` | No | `0.0.0.0` | Local IP address to bind the UDP socket to |
| `private_key_file` | Yes | — | Path to this node's X25519 private key PEM file |
| `pre_shared_key` | No | — | PSK for HMAC handshake authentication |
| `verbose` | No | `false` | `true` to enable debug logging |
| `keepalive_interval` | No | `25` | Seconds between keepalive packets |
| `rekey_after` | No | `180` | Seconds before initiating a rekey |
| `reconnect_interval` | No | `30` | Seconds between reconnect attempts to outbound peers |
| `session_expiry` | No | `540` | Seconds before an idle session is considered expired |
| `prev_key_grace` | No | `90` | Seconds the old session key is retained after rekeying |
| `handshake_timeout` | No | `5` | Seconds before a pending handshake is abandoned |
| `handshake_cooldown` | No | `5` | Seconds between handshake attempts to the same peer |
| `peers[].public_key` | Yes | — | Peer's public key (hex) |
| `peers[].endpoint` | No | — | `host:port` to connect to; omit for inbound-only nodes |
| `peers[].allowed_ips` | Yes | — | CIDRs allowed from this peer |

---

## Running as a Service

### Relay

```bash
sudo systemctl enable --now lanecove-relay
```

### Peer

```bash
# Generic peer (uses /etc/lanecove/peer.yaml)
sudo systemctl enable --now lanecove-peer

# Named peers
sudo systemctl enable --now lanecove-peer-1
sudo systemctl enable --now lanecove-peer-2
```

Only enable the service that matches this machine's role. Running more than one service on the same machine will conflict on the `lanecove0` TUN interface and UDP port.

### Stop / Restart

```bash
sudo systemctl restart lanecove-relay
sudo systemctl restart lanecove-peer
sudo systemctl stop lanecove-peer-1
```

### View Logs

```bash
sudo journalctl -u lanecove-relay -f
sudo journalctl -u lanecove-peer -f
```

---

## Firewall

The relay must allow inbound UDP on port 5040:

```bash
# ufw
sudo ufw allow 5040/udp

# firewalld
sudo firewall-cmd --permanent --add-port=5040/udp
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -p udp --dport 5040 -j ACCEPT
```

Peers behind NAT do not need any inbound firewall rules — they connect outbound only.

---

## Verifying the Tunnel

Once relay and peers are running, verify connectivity using overlay IPs:

```bash
# From peer-1, ping the relay and peer-2
ping 10.9.0.1
ping 10.9.0.3

# From the relay, ping both peers
ping 10.9.0.2
ping 10.9.0.3
```

---

## Uninstalling

### Debian / Ubuntu

```bash
sudo dpkg -r lanecove-tunnel
```

### Red Hat / Fedora / CentOS

```bash
sudo rpm -e lanecove-tunnel
```

Configs in `/etc/lanecove/` and keys are preserved on uninstall.
