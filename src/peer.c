#define _GNU_SOURCE
#include <netdb.h>
#include <signal.h>
#include <time.h>
#include <yaml.h>
#include <pthread.h>
#include <unistd.h>
#include "common.h"

#define REKEY_AFTER_SECS          180
#define PREV_KEY_GRACE_SECS        90
#define HANDSHAKE_COOLDOWN_SECS     5
#define HANDSHAKE_TIMEOUT_SECS      5

#define RECONNECT_INTERVAL_SECS    30
#define SESSION_EXPIRY_SECS       (3 * REKEY_AFTER_SECS)
#define KEEPALIVE_INTERVAL_SECS    25
#define MAX_PEERS                  64
#define MAX_ROUTES_PER_PEER        16
#define MAX_WORKER_THREADS         32
#define DEFAULT_WORKER_THREADS      4

/* inet_ntoa() returns a pointer to a static process-wide buffer, so it is
 * not safe to call from multiple threads (or more than once per log
 * statement — argument evaluation order is unspecified, so two inet_ntoa()
 * calls in one printf-style call have always been able to alias each
 * other's output even single-threaded). Every log call site formats into
 * its own stack buffer via this helper instead. */
static inline const char *fmt_addr(const struct sockaddr_in *a, char *buf, size_t buflen) {
    inet_ntop(AF_INET, &a->sin_addr, buf, buflen);
    return buf;
}

typedef struct {
    uint32_t network;
    uint32_t mask;
    int      prefix_len;
} ip_prefix_t;

/* Statically configured peer (from CLI -P/-E/-R flags) */
typedef struct {
    unsigned char      pub[DH_PUBKEY_LEN];
    ip_prefix_t        routes[MAX_ROUTES_PER_PEER];
    int                route_count;
    int                has_endpoint;   /* if set, we initiate to this peer */
    struct sockaddr_in endpoint;
    char               endpoint_host[256]; /* original hostname from -E, for re-resolution */
    int                endpoint_port;
    time_t             last_attempt;
} peer_config_t;

/* Runtime session with a connected peer.
 *
 * Locking: structural membership (active/static_pub/routes/route_count/
 * is_outbound/rekeying/rekey_deadline/last_handshake) is guarded by the
 * global table_lock (taken by the rare handshake/rekey/expiry paths, and
 * held for read across the full lookup+forward/decrypt call on the hot
 * path — see find_session_by_addr/route_lookup callers). The per-packet hot
 * fields (addr, send_seq, recv_seq_highest, recv_seq_window, session_key,
 * prev_session_key, prev_key_active, prev_key_expires, last_seen, last_sent)
 * are additionally guarded by this session's own hot_lock, which is what
 * actually lets packets for different peers proceed in parallel without
 * contending with each other; only concurrent packets for the *same* peer
 * serialize on it, which is required anyway for correct sequence numbering
 * and replay-window checks. addr is included here (not just table_lock)
 * because it's read on literally every packet send in forward_to_peer. */
typedef struct {
    int                active;
    struct sockaddr_in addr;
    unsigned char      static_pub[DH_PUBKEY_LEN];
    unsigned char      session_key[CRYPTO_KEY_LEN];
    unsigned char      prev_session_key[CRYPTO_KEY_LEN];
    int                prev_key_active;
    time_t             prev_key_expires;
    time_t             last_seen;
    time_t             last_sent;
    time_t             last_handshake;
    time_t             rekey_deadline;
    int                rekeying;
    uint64_t           send_seq;
    uint64_t           recv_seq_highest;
    uint64_t           recv_seq_window[REPLAY_WINDOW_WORDS];
    ip_prefix_t        routes[MAX_ROUTES_PER_PEER];
    int                route_count;
    int                is_outbound;
    pthread_mutex_t    hot_lock;
} peer_session_t;

/* Pending outbound handshake — initiated but awaiting response in the epoll loop */
typedef struct {
    int                active;
    int                cfg_idx;
    time_t             sent_at;
    hs_client_state_t  hs_state;
    struct sockaddr_in server_addr;
} pending_hs_t;

static int cfg_rekey_after          = REKEY_AFTER_SECS;
static int cfg_reconnect_interval   = RECONNECT_INTERVAL_SECS;
static int cfg_session_expiry       = SESSION_EXPIRY_SECS;
static int cfg_prev_key_grace       = PREV_KEY_GRACE_SECS;
static int cfg_handshake_timeout    = HANDSHAKE_TIMEOUT_SECS;
static int cfg_handshake_cooldown   = HANDSHAKE_COOLDOWN_SECS;
static int cfg_worker_threads       = 0; /* 0 = auto (min(4, nproc)), resolved in main() */

static peer_config_t  peer_configs[MAX_PEERS];
static int            peer_config_count = 0;
static peer_session_t sessions[MAX_PEERS];
static int            session_slots = 0;
static pending_hs_t   pending_hs[MAX_PEERS];

/* Guards structural session-table state: sessions[]/session_slots,
 * pending_hs[], and peer_configs[] (mutated by the housekeeping thread's
 * resolve_endpoint()/last_attempt). Read-locked for the frequent per-packet
 * lookups (find_session_by_addr/by_pub, route_lookup) so those run fully
 * concurrently across worker threads; write-locked for the rare paths
 * (handshake completion, session expiry, reconnect bookkeeping). Per-packet
 * mutation of an already-found session's hot fields uses that session's own
 * hot_lock instead — see peer_session_t. */
static pthread_rwlock_t table_lock = PTHREAD_RWLOCK_INITIALIZER;

/* Pre-generated ephemeral keypair for the inbound handshake responder.
 * Generated at startup and refreshed immediately after each use so the
 * expensive X25519 keygen never runs on the event-loop hot path. Only
 * touched inside the inbound-handshake branch, which always holds
 * table_lock for writing, so no separate lock is needed here. */
static EVP_PKEY      *precomp_eph_key = NULL;
static unsigned char  precomp_eph_pub[DH_PUBKEY_LEN];

static volatile sig_atomic_t stop_flag          = 0;
static volatile sig_atomic_t print_sessions_flag = 0;

static void handle_signal(int sig) {
    if (sig == SIGUSR1)
        print_sessions_flag = 1;
    else
        stop_flag = 1;
}

/* Resolve (or re-resolve) the endpoint hostname and update cfg->endpoint.
 * Blocking — only called at startup and on rate-limited reconnect attempts. */
static int resolve_endpoint(peer_config_t *cfg) {
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", cfg->endpoint_port);

    struct addrinfo hints = {0};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(cfg->endpoint_host, port_str, &hints, &res);
    if (rc != 0) {
        LOG_WARN("DNS resolution failed for %s: %s", cfg->endpoint_host, gai_strerror(rc));
        return -1;
    }

    struct sockaddr_in new_addr = *(struct sockaddr_in *)res->ai_addr;
    freeaddrinfo(res);

    if (new_addr.sin_addr.s_addr != cfg->endpoint.sin_addr.s_addr) {
        char old_ip[INET_ADDRSTRLEN], new_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cfg->endpoint.sin_addr, old_ip, sizeof(old_ip));
        inet_ntop(AF_INET, &new_addr.sin_addr,      new_ip, sizeof(new_ip));
        LOG_INFO("Endpoint %s re-resolved: %s -> %s:%d",
                 cfg->endpoint_host, old_ip, new_ip, cfg->endpoint_port);
    }
    cfg->endpoint = new_addr;
    return 0;
}

static void refresh_precomp_eph(void) {
    EVP_PKEY *old = precomp_eph_key;
    EVP_PKEY *nk  = NULL;
    if (generate_eph_keypair(&nk, precomp_eph_pub) < 0) {
        LOG_WARN("Failed to pre-generate ephemeral keypair");
        precomp_eph_key = old;
        return;
    }
    precomp_eph_key = nk;
    if (old) EVP_PKEY_free(old);
}

static int parse_cidr(const char *cidr, ip_prefix_t *out) {
    char buf[32];
    strncpy(buf, cidr, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *slash = strchr(buf, '/');
    int prefix_len = 32;
    if (slash) {
        *slash = '\0';
        prefix_len = atoi(slash + 1);
        if (prefix_len < 0 || prefix_len > 32) return -1;
    }
    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1) return -1;
    uint32_t mask = prefix_len == 0 ? 0u : (~0u << (32 - prefix_len));
    out->network    = ntohl(addr.s_addr) & mask;
    out->mask       = mask;
    out->prefix_len = prefix_len;
    return 0;
}

static int load_config(const char *path,
                       char *tunnel, char *address, int *port,
                       int *keepalive_interval, char *keyfile,
                       char *psk, int *has_psk) {
    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_ERROR("Cannot open config file: %s: %s", path, strerror(errno));
        return -1;
    }

    yaml_parser_t parser;
    if (!yaml_parser_initialize(&parser)) {
        fclose(f);
        LOG_ERROR("yaml_parser_initialize failed");
        return -1;
    }
    yaml_parser_set_input_file(&parser, f);

    enum { S_ROOT, S_ROOT_VAL, S_PEERS_SEQ, S_PEER_MAP, S_PEER_VAL, S_ALLOWED_IPS_SEQ };
    int  state    = S_ROOT;
    char key[64]      = {0};
    char peer_key[64] = {0};
    int  ok           = 1;
    yaml_event_t ev;

    while (ok) {
        if (!yaml_parser_parse(&parser, &ev)) {
            LOG_ERROR("YAML parse error in %s (line %zu): %s",
                      path, parser.problem_mark.line + 1, parser.problem);
            ok = 0;
            break;
        }

        switch (state) {

        case S_ROOT:
            if (ev.type == YAML_SCALAR_EVENT) {
                strncpy(key, (char *)ev.data.scalar.value, sizeof(key) - 1);
                state = S_ROOT_VAL;
            }
            break;

        case S_ROOT_VAL:
            if (ev.type == YAML_SCALAR_EVENT) {
                const char *v = (char *)ev.data.scalar.value;
                if      (strcmp(key, "interface")        == 0) strncpy(tunnel,  v, IF_NAMESIZE - 1);
                else if (strcmp(key, "address")          == 0) strncpy(address, v, 63);
                else if (strcmp(key, "port")             == 0) *port = atoi(v);
                else if (strcmp(key, "keepalive_interval")  == 0) *keepalive_interval      = atoi(v);
                else if (strcmp(key, "rekey_after")          == 0) cfg_rekey_after          = atoi(v);
                else if (strcmp(key, "reconnect_interval")  == 0) cfg_reconnect_interval   = atoi(v);
                else if (strcmp(key, "session_expiry")      == 0) cfg_session_expiry       = atoi(v);
                else if (strcmp(key, "prev_key_grace")      == 0) cfg_prev_key_grace       = atoi(v);
                else if (strcmp(key, "handshake_timeout")   == 0) cfg_handshake_timeout    = atoi(v);
                else if (strcmp(key, "handshake_cooldown")  == 0) cfg_handshake_cooldown   = atoi(v);
                else if (strcmp(key, "worker_threads")      == 0) cfg_worker_threads       = atoi(v);
                else if (strcmp(key, "private_key_file") == 0) strncpy(keyfile, v, 255);
                else if (strcmp(key, "verbose")        == 0 && strcmp(v, "true") == 0) log_level = 1;
                else if (strcmp(key, "pre_shared_key") == 0) {
                    strncpy(psk, v, 255);
                    *has_psk = 1;
                }
                state = S_ROOT;
            } else if (ev.type == YAML_SEQUENCE_START_EVENT && strcmp(key, "peers") == 0) {
                state = S_PEERS_SEQ;
            }
            break;

        case S_PEERS_SEQ:
            if (ev.type == YAML_SEQUENCE_END_EVENT) {
                state = S_ROOT;
            } else if (ev.type == YAML_MAPPING_START_EVENT) {
                if (peer_config_count >= MAX_PEERS) {
                    LOG_ERROR("Config: too many peers (max %d)", MAX_PEERS);
                    ok = 0; break;
                }
                memset(&peer_configs[peer_config_count], 0, sizeof(peer_config_t));
                peer_config_count++;
                state = S_PEER_MAP;
            }
            break;

        case S_PEER_MAP:
            if (ev.type == YAML_MAPPING_END_EVENT) {
                state = S_PEERS_SEQ;
            } else if (ev.type == YAML_SCALAR_EVENT) {
                strncpy(peer_key, (char *)ev.data.scalar.value, sizeof(peer_key) - 1);
                state = S_PEER_VAL;
            }
            break;

        case S_PEER_VAL:
            if (ev.type == YAML_SCALAR_EVENT) {
                const char *v     = (char *)ev.data.scalar.value;
                peer_config_t *pc = &peer_configs[peer_config_count - 1];
                if (strcmp(peer_key, "public_key") == 0) {
                    if (hex_to_bytes(v, pc->pub, DH_PUBKEY_LEN) < 0) {
                        LOG_ERROR("Config: invalid public_key hex: %s", v);
                        ok = 0; break;
                    }
                } else if (strcmp(peer_key, "endpoint") == 0) {
                    char buf[256];
                    strncpy(buf, v, sizeof(buf) - 1);
                    char *colon = strrchr(buf, ':');
                    if (!colon || colon == buf) {
                        LOG_ERROR("Config: invalid endpoint (expected host:port): %s", v);
                        ok = 0; break;
                    }
                    *colon = '\0';
                    int eport = atoi(colon + 1);
                    if (eport <= 0 || eport > 65535) {
                        LOG_ERROR("Config: invalid port in endpoint: %s", v);
                        ok = 0; break;
                    }
                    strncpy(pc->endpoint_host, buf, sizeof(pc->endpoint_host));
                    pc->endpoint_host[sizeof(pc->endpoint_host) - 1] = '\0';
                    pc->endpoint_port       = eport;
                    pc->endpoint.sin_family = AF_INET;
                    pc->endpoint.sin_port   = htons(eport);
                    if (resolve_endpoint(pc) < 0) {
                        LOG_ERROR("Config: cannot resolve endpoint host: %s", buf);
                        ok = 0; break;
                    }
                    pc->has_endpoint = 1;
                }
                state = S_PEER_MAP;
            } else if (ev.type == YAML_SEQUENCE_START_EVENT && strcmp(peer_key, "allowed_ips") == 0) {
                state = S_ALLOWED_IPS_SEQ;
            }
            break;

        case S_ALLOWED_IPS_SEQ:
            if (ev.type == YAML_SEQUENCE_END_EVENT) {
                state = S_PEER_MAP;
            } else if (ev.type == YAML_SCALAR_EVENT) {
                peer_config_t *pc = &peer_configs[peer_config_count - 1];
                if (pc->route_count >= MAX_ROUTES_PER_PEER) {
                    LOG_ERROR("Config: too many allowed_ips (max %d)", MAX_ROUTES_PER_PEER);
                    ok = 0; break;
                }
                if (parse_cidr((char *)ev.data.scalar.value,
                               &pc->routes[pc->route_count]) < 0) {
                    LOG_ERROR("Config: invalid CIDR: %s", (char *)ev.data.scalar.value);
                    ok = 0; break;
                }
                pc->route_count++;
            }
            break;
        }

        int done = (ev.type == YAML_STREAM_END_EVENT);
        yaml_event_delete(&ev);
        if (done) break;
    }

    yaml_parser_delete(&parser);
    fclose(f);
    return ok ? 0 : -1;
}

/* find_peer_config: peer_configs[] entries are appended only at startup
 * (load_config, single-threaded) and never removed, so no lock is needed. */
static peer_config_t *find_peer_config(const unsigned char *pub) {
    for (int i = 0; i < peer_config_count; i++)
        if (memcmp(peer_configs[i].pub, pub, DH_PUBKEY_LEN) == 0)
            return &peer_configs[i];
    return NULL;
}

/* The following session-table helpers assume the caller already holds
 * table_lock (read lock for lookups, write lock for alloc_session/
 * session_init) — they do not lock internally so callers can compose
 * multiple lookups under a single critical section. */

static peer_session_t *find_session_by_addr(struct sockaddr_in *addr) {
    for (int i = 0; i < session_slots; i++)
        if (sessions[i].active &&
            sessions[i].addr.sin_addr.s_addr == addr->sin_addr.s_addr &&
            sessions[i].addr.sin_port == addr->sin_port)
            return &sessions[i];
    return NULL;
}

static peer_session_t *find_session_by_pub(const unsigned char *pub) {
    for (int i = 0; i < session_slots; i++)
        if (sessions[i].active && memcmp(sessions[i].static_pub, pub, DH_PUBKEY_LEN) == 0)
            return &sessions[i];
    return NULL;
}

/* Returns an existing slot (by pub first, then addr), falls back to a free slot.
 * Requires table_lock held for writing (may grow session_slots). */
static peer_session_t *alloc_session(const unsigned char *pub, struct sockaddr_in *addr) {
    for (int i = 0; i < session_slots; i++)
        if (sessions[i].active && memcmp(sessions[i].static_pub, pub, DH_PUBKEY_LEN) == 0)
            return &sessions[i];
    peer_session_t *s = find_session_by_addr(addr);
    if (s) return s;
    for (int i = 0; i < session_slots; i++)
        if (!sessions[i].active) return &sessions[i];
    if (session_slots >= MAX_PEERS) return NULL;
    return &sessions[session_slots++];
}

/* Requires table_lock held for reading. */
static peer_session_t *route_lookup(uint32_t dst_ip) {
    peer_session_t *best = NULL;
    int best_prefix = -1;
    for (int i = 0; i < session_slots; i++) {
        if (!sessions[i].active) continue;
        for (int j = 0; j < sessions[i].route_count; j++) {
            if ((dst_ip & sessions[i].routes[j].mask) == sessions[i].routes[j].network &&
                sessions[i].routes[j].prefix_len > best_prefix) {
                best_prefix = sessions[i].routes[j].prefix_len;
                best = &sessions[i];
            }
        }
    }
    return best;
}

/* route_count/routes are only mutated by session_init (under table_lock
 * write lock); requires table_lock held for reading. */
static int check_allowed_src(peer_session_t *s, uint32_t src_ip) {
    if (s->route_count == 0) return 1;
    for (int i = 0; i < s->route_count; i++)
        if ((src_ip & s->routes[i].mask) == s->routes[i].network) return 1;
    return 0;
}

/* Requires table_lock held for writing. */
static void session_init(peer_session_t *s, struct sockaddr_in *addr,
                         const unsigned char *pub, unsigned char *key,
                         peer_config_t *cfg, int is_outbound) {
    int was_active = s->active;
    struct sockaddr_in old_addr = s->addr;

    s->active = 1;
    memcpy(s->static_pub, pub, DH_PUBKEY_LEN);

    /* hot_lock nested inside the caller's table wrlock (consistent lock
     * order: table_lock always acquired before hot_lock) so an in-flight
     * forward_to_peer/decrypt on this same session can't race a rekey that's
     * swapping addr/session_key/send_seq/replay-window state underneath it. */
    pthread_mutex_lock(&s->hot_lock);
    s->addr = *addr;
    if (was_active) {
        memcpy(s->prev_session_key, s->session_key, CRYPTO_KEY_LEN);
        s->prev_key_active = 1;
        s->prev_key_expires = time(NULL) + cfg_prev_key_grace;
    } else {
        s->prev_key_active = 0;
    }
    memcpy(s->session_key, key, CRYPTO_KEY_LEN);
    s->last_seen = 0;
    s->last_sent = time(NULL); /* suppress immediate keepalive after handshake */
    s->send_seq = 0;
    s->recv_seq_highest = 0;
    memset(s->recv_seq_window, 0, sizeof(s->recv_seq_window));
    pthread_mutex_unlock(&s->hot_lock);

    s->last_handshake = time(NULL);
    s->rekey_deadline = time(NULL) + cfg_rekey_after;
    s->rekeying = 0;
    s->is_outbound = is_outbound;
    if (cfg) {
        memcpy(s->routes, cfg->routes, cfg->route_count * sizeof(ip_prefix_t));
        s->route_count = cfg->route_count;
    } else {
        s->route_count = 0;
    }

    char key_hex[17];
    bytes_to_hex(pub, 8, key_hex);
    char ip1[INET_ADDRSTRLEN], ip2[INET_ADDRSTRLEN];
    if (was_active) {
        if (old_addr.sin_addr.s_addr != addr->sin_addr.s_addr ||
            old_addr.sin_port != addr->sin_port)
            LOG_INFO("Peer address changed: %s:%d -> %s:%d (key=%s...)",
                     fmt_addr(&old_addr, ip1, sizeof(ip1)), ntohs(old_addr.sin_port),
                     fmt_addr(addr, ip2, sizeof(ip2)), ntohs(addr->sin_port), key_hex);
        else
            LOG_INFO("Peer re-keyed: %s:%d (key=%s...)",
                     fmt_addr(addr, ip1, sizeof(ip1)), ntohs(addr->sin_port), key_hex);
    } else {
        LOG_INFO("Peer connected: %s:%d (key=%s...)",
                 fmt_addr(addr, ip1, sizeof(ip1)), ntohs(addr->sin_port), key_hex);
    }
}

/* Requires table_lock held (read lock suffices for the structural fields;
 * addr is additionally read under each session's hot_lock since it's a
 * hot-path field). */
static void print_sessions(void) {
    int active = 0;
    for (int i = 0; i < session_slots; i++) active += sessions[i].active ? 1 : 0;
    LOG_INFO("Active peers (%d):", active);
    for (int i = 0; i < session_slots; i++) {
        if (!sessions[i].active) continue;
        peer_session_t *s = &sessions[i];
        char key_hex[17];
        bytes_to_hex(s->static_pub, 8, key_hex);
        pthread_mutex_lock(&s->hot_lock);
        struct sockaddr_in addr = s->addr;
        pthread_mutex_unlock(&s->hot_lock);
        char ip[INET_ADDRSTRLEN];
        LOG_INFO("  [%s] %s:%d key=%s... routes=%d",
                 s->is_outbound ? "out" : "in",
                 fmt_addr(&addr, ip, sizeof(ip)), ntohs(addr.sin_port),
                 key_hex, s->route_count);
    }
}

/* Encrypts and sends a packet to session s. Takes s->hot_lock internally to
 * guard addr/send_seq/session_key/last_sent — callers must NOT be holding
 * it already. Caller must hold table_lock (read lock is enough) across the
 * session lookup and this call, so a concurrent rekey (session_init, which
 * needs table_lock write) can't run at the same time and torn-write/read
 * fields this function doesn't itself lock (e.g. it trusts s to remain the
 * right slot for this peer for the duration of the call). */
static void forward_to_peer(int sock_fd, peer_session_t *s, EVP_CIPHER_CTX *enc_ctx,
                            unsigned char *plain_buf, const unsigned char *payload,
                            int payload_len, unsigned char *wire_buf) {
    int enc_len;
    pthread_mutex_lock(&s->hot_lock);
    uint64_t seq_be = htobe64(s->send_seq++);
    memcpy(plain_buf, pkt_header, HEADER_SIZE);
    memcpy(plain_buf + HEADER_SIZE, &seq_be, SEQ_SIZE);
    if (payload_len > 0)
        memcpy(plain_buf + HEADER_SIZE + SEQ_SIZE, payload, payload_len);
    if (encrypt_packet(enc_ctx, s->session_key, plain_buf, HEADER_SIZE + SEQ_SIZE + payload_len,
                       wire_buf, &enc_len) < 0) {
        char ip[INET_ADDRSTRLEN];
        LOG_ERROR("Encrypt failed for %s:%d",
                  fmt_addr(&s->addr, ip, sizeof(ip)), ntohs(s->addr.sin_port));
        pthread_mutex_unlock(&s->hot_lock);
        return;
    }
    struct sockaddr_in dest = s->addr;
    pthread_mutex_unlock(&s->hot_lock);
    if (sendto(sock_fd, wire_buf, enc_len, 0, (struct sockaddr *)&dest, sizeof(dest)) >= 0) {
        pthread_mutex_lock(&s->hot_lock);
        s->last_sent = time(NULL);
        pthread_mutex_unlock(&s->hot_lock);
    }
}

/* Send a handshake initiation to an outbound peer and register a pending entry.
 * Returns immediately — the response is handled asynchronously by a worker
 * thread. The old session (if any) stays active and keeps forwarding until
 * the response arrives and session_init atomically replaces the key.
 * Requires table_lock held for writing (mutates cfg->last_attempt and
 * pending_hs[]). */
static int initiate_outbound_handshake(int sock_fd, int cfg_idx,
                                       EVP_PKEY *static_key, const unsigned char *static_pub,
                                       const unsigned char *psk_key) {
    peer_config_t *cfg = &peer_configs[cfg_idx];
    cfg->last_attempt = time(NULL);

    int slot = -1;
    for (int i = 0; i < MAX_PEERS; i++) {
        if (!pending_hs[i].active) { slot = i; break; }
    }
    if (slot < 0) {
        LOG_WARN("No pending handshake slots available");
        return -1;
    }

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &cfg->endpoint.sin_addr, ip_str, sizeof(ip_str));
    LOG_INFO("Initiating handshake to %s:%d", ip_str, ntohs(cfg->endpoint.sin_port));

    pending_hs_t *p = &pending_hs[slot];
    if (handshake_client_send(sock_fd, &cfg->endpoint, psk_key,
                               static_key, static_pub, cfg->pub, &p->hs_state) < 0) {
        LOG_WARN("Handshake initiation to %s:%d failed", ip_str, ntohs(cfg->endpoint.sin_port));
        return -1;
    }
    p->active     = 1;
    p->cfg_idx    = cfg_idx;
    p->sent_at    = time(NULL);
    p->server_addr = cfg->endpoint;
    return 0;
}

/* Shared, read-only-after-init context handed to every worker thread and
 * the housekeeping thread. */
typedef struct {
    int                  tun_fd;
    int                  sock_fd;
    EVP_PKEY            *static_key;
    const unsigned char *static_pub;
    const unsigned char *psk_key;
    int                  keepalive_interval;
} loop_ctx_t;

/* Runs on a dedicated thread. Owns the periodic housekeeping that used to
 * run inline in the single-threaded event loop every 10s: outbound
 * (re)connect/rekey checks (including the blocking resolve_endpoint() DNS
 * call — isolated here so it never stalls a packet-processing worker),
 * pending-handshake timeout, session expiry, and keepalives. Also handles
 * the SIGUSR1 print_sessions_flag so only one thread ever calls
 * print_sessions(). Runs its own housekeeping-only EVP_CIPHER_CTX for the
 * keepalive sends via forward_to_peer(). */
static void *housekeeping_loop(void *arg) {
    loop_ctx_t *ctx = arg;
    unsigned char plain_buf[HEADER_SIZE + SEQ_SIZE + BUFFER_SIZE];
    unsigned char wire_buf[BUFFER_SIZE + WIRE_OVERHEAD];
    time_t last_check = 0;

    EVP_CIPHER_CTX *enc_ctx = EVP_CIPHER_CTX_new();
    if (!enc_ctx) {
        LOG_ERROR("Housekeeping: failed to allocate cipher context");
        return NULL;
    }

    while (!stop_flag) {
        if (print_sessions_flag) {
            print_sessions_flag = 0;
            pthread_rwlock_rdlock(&table_lock);
            print_sessions();
            pthread_rwlock_unlock(&table_lock);
        }

        time_t now = time(NULL);
        if (now - last_check >= 10) {
            last_check = now;
            pthread_rwlock_wrlock(&table_lock);

            for (int i = 0; i < peer_config_count; i++) {
                peer_config_t *cfg = &peer_configs[i];
                if (!cfg->has_endpoint) continue;
                peer_session_t *s = find_session_by_pub(cfg->pub);
                int needs = !s || (now >= s->last_handshake + cfg_rekey_after * 4 / 5 && !s->rekeying);
                int ready  = now - cfg->last_attempt >= cfg_reconnect_interval;
                if (needs && ready) {
                    resolve_endpoint(cfg); /* blocking DNS — safe here, off the packet path */
                    if (s) s->rekeying = 1;
                    if (initiate_outbound_handshake(ctx->sock_fd, i, ctx->static_key,
                                                    ctx->static_pub, ctx->psk_key) < 0)
                        if (s) s->rekeying = 0;
                }
            }
            /* Expire timed-out pending handshakes */
            for (int j = 0; j < MAX_PEERS; j++) {
                pending_hs_t *p = &pending_hs[j];
                if (!p->active || now - p->sent_at < cfg_handshake_timeout) continue;
                char ip_str[INET_ADDRSTRLEN];
                LOG_WARN("Handshake to %s:%d timed out — will retry in %ds",
                         fmt_addr(&peer_configs[p->cfg_idx].endpoint, ip_str, sizeof(ip_str)),
                         ntohs(peer_configs[p->cfg_idx].endpoint.sin_port),
                         cfg_reconnect_interval);
                EVP_PKEY_free(p->hs_state.eph_key);
                p->hs_state.eph_key = NULL;
                p->active = 0;
                peer_session_t *ts = find_session_by_pub(peer_configs[p->cfg_idx].pub);
                if (ts) ts->rekeying = 0;
            }
            /* Expire sessions that have been silent for too long */
            for (int j = 0; j < session_slots; j++) {
                peer_session_t *s = &sessions[j];
                if (!s->active) continue;
                time_t ref = s->last_seen > 0 ? s->last_seen : s->last_handshake;
                if (now - ref <= cfg_session_expiry) continue;
                char key_hex[17], ip[INET_ADDRSTRLEN];
                bytes_to_hex(s->static_pub, 8, key_hex);
                pthread_mutex_lock(&s->hot_lock);
                struct sockaddr_in addr = s->addr;
                pthread_mutex_unlock(&s->hot_lock);
                LOG_INFO("Session expired (no traffic for %ds): %s:%d key=%s...",
                         (int)(now - ref),
                         fmt_addr(&addr, ip, sizeof(ip)), ntohs(addr.sin_port), key_hex);
                s->active = 0;
            }
            /* Send keepalive to sessions that have had no outbound traffic recently */
            for (int j = 0; j < session_slots; j++) {
                peer_session_t *s = &sessions[j];
                if (!s->active) continue;
                pthread_mutex_lock(&s->hot_lock);
                int due = now - s->last_sent >= ctx->keepalive_interval;
                struct sockaddr_in addr = s->addr;
                pthread_mutex_unlock(&s->hot_lock);
                if (!due) continue;
                char ip[INET_ADDRSTRLEN];
                LOG_DEBUG("Keepalive -> %s:%d", fmt_addr(&addr, ip, sizeof(ip)), ntohs(addr.sin_port));
                forward_to_peer(ctx->sock_fd, s, enc_ctx, plain_buf, NULL, 0, wire_buf);
            }

            pthread_rwlock_unlock(&table_lock);
        }

        sleep(1);
    }

    EVP_CIPHER_CTX_free(enc_ctx);
    LOG_INFO("Housekeeping thread terminated");
    return NULL;
}

/* Runs on each of N worker threads. Owns per-packet I/O: TUN<->UDP,
 * handshake dispatch, encrypt/decrypt, routing. Each worker has its own
 * epoll instance (registered with EPOLLEXCLUSIVE on the shared tun_fd/
 * sock_fd so the kernel wakes exactly one worker per ready event) and its
 * own EVP_CIPHER_CTX pair and stack buffers — no per-worker state is
 * shared except through the locked session table (table_lock / per-session
 * hot_lock, see peer_session_t and the helpers above). */
static void *worker_loop(void *arg) {
    loop_ctx_t *ctx = arg;
    int tun_fd = ctx->tun_fd, sock_fd = ctx->sock_fd;
    EVP_PKEY *static_key = ctx->static_key;
    const unsigned char *static_pub = ctx->static_pub;
    const unsigned char *psk_key = ctx->psk_key;

    unsigned char buffer[BUFFER_SIZE];
    unsigned char plain_buf[HEADER_SIZE + SEQ_SIZE + BUFFER_SIZE];
    unsigned char wire_buf[BUFFER_SIZE + WIRE_OVERHEAD];
    ssize_t nr;
    struct sockaddr_in src_addr;
    socklen_t src_addr_len;
    int hs_size = HEADER_SIZE + DH_PUBKEY_LEN + HS_ENCRYPTED_PUB_LEN + (psk_key ? HMAC_LEN : 0);

    EVP_CIPHER_CTX *enc_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *dec_ctx = EVP_CIPHER_CTX_new();
    if (!enc_ctx || !dec_ctx) {
        LOG_ERROR("Failed to allocate cipher contexts");
        EVP_CIPHER_CTX_free(enc_ctx);
        EVP_CIPHER_CTX_free(dec_ctx);
        return NULL;
    }

    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        LOG_ERROR("epoll_create1: %s", strerror(errno));
        EVP_CIPHER_CTX_free(enc_ctx);
        EVP_CIPHER_CTX_free(dec_ctx);
        return NULL;
    }

    struct epoll_event ev, events[2];
    ev.events = EPOLLIN | EPOLLEXCLUSIVE;
    ev.data.fd = tun_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tun_fd, &ev);
    ev.data.fd = sock_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_fd, &ev);

    while (!stop_flag) {
        int nfds = epoll_wait(epoll_fd, events, 2, 5000);
        if (nfds < 0) {
            if (errno == EINTR) continue; /* signal interrupted — recheck stop_flag */
            LOG_ERROR("epoll_wait: %s", strerror(errno)); break;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                LOG_ERROR("Error/hangup on fd=%d", events[i].data.fd);
                goto done;
            }

            /* TUN -> UDP */
            if (events[i].data.fd == tun_fd) {
                nr = read(tun_fd, buffer, BUFFER_SIZE);
                if (nr <= 0) { LOG_ERROR("TUN read: %s", strerror(errno)); goto done; }
                if (nr >= 20 && (buffer[0] >> 4) == 4) {
                    uint32_t dst_ip = ntohl(*(uint32_t *)(buffer + 16));
                    struct in_addr da = { htonl(dst_ip) };
                    char da_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &da, da_str, sizeof(da_str));
                    pthread_rwlock_rdlock(&table_lock);
                    peer_session_t *s = route_lookup(dst_ip);
                    if (s) {
                        LOG_DEBUG("TUN->UDP: forwarding (dst=%s)", da_str);
                        forward_to_peer(sock_fd, s, enc_ctx, plain_buf, buffer, (int)nr, wire_buf);
                    } else {
                        LOG_DEBUG("No route for %s — dropping", da_str);
                    }
                    pthread_rwlock_unlock(&table_lock);
                }
                continue;
            }

            /* UDP -> TUN or handshake */
            src_addr_len = sizeof(src_addr);
            nr = recvfrom(sock_fd, wire_buf, sizeof(wire_buf), 0,
                          (struct sockaddr *)&src_addr, &src_addr_len);
            if (nr < 0) { LOG_ERROR("recvfrom: %s", strerror(errno)); goto done; }

            time_t now = time(NULL);
            char src_ip_str[INET_ADDRSTRLEN];
            fmt_addr(&src_addr, src_ip_str, sizeof(src_ip_str));

            /* Handshake packets (both the outbound-response and inbound-initiation
             * branches) mutate pending_hs[]/sessions[] structurally, so the whole
             * branch runs under table_lock held for writing. */
            if (nr == hs_size && memcmp(wire_buf, pkt_header, HEADER_SIZE) == 0) {
                pthread_rwlock_wrlock(&table_lock);

                /* Response to a pending outbound handshake — check before inbound path */
                int handled = 0;
                for (int j = 0; j < MAX_PEERS; j++) {
                    pending_hs_t *p = &pending_hs[j];
                    if (!p->active) continue;
                    if (p->server_addr.sin_addr.s_addr != src_addr.sin_addr.s_addr ||
                        p->server_addr.sin_port        != src_addr.sin_port) continue;
                    peer_config_t *cfg = &peer_configs[p->cfg_idx];
                    unsigned char session_key[CRYPTO_KEY_LEN];
                    p->active = 0;
                    if (handshake_client_recv(wire_buf, (int)nr, psk_key,
                                              static_key, static_pub, cfg->pub,
                                              &p->hs_state, session_key) == 0) {
                        peer_session_t *s = alloc_session(cfg->pub, &src_addr);
                        if (s) {
                            session_init(s, &src_addr, cfg->pub, session_key, cfg, 1);
                            print_sessions();
                        }
                    } else {
                        peer_session_t *s = find_session_by_pub(cfg->pub);
                        if (s) s->rekeying = 0;
                    }
                    handled = 1;
                    break;
                }
                if (handled) { pthread_rwlock_unlock(&table_lock); continue; }

                /* Inbound handshake.
                 * Tie-breaking: if we have a pending outbound to this peer, the side
                 * with the higher pub key wins and ignores the inbound initiation. */
                int skip = 0;
                for (int j = 0; j < MAX_PEERS; j++) {
                    pending_hs_t *p = &pending_hs[j];
                    if (!p->active) continue;
                    if (p->server_addr.sin_addr.s_addr != src_addr.sin_addr.s_addr ||
                        p->server_addr.sin_port        != src_addr.sin_port) continue;
                    if (memcmp(static_pub, peer_configs[p->cfg_idx].pub, DH_PUBKEY_LEN) > 0) {
                        LOG_DEBUG("Rekey collision from %s:%d — ignoring (we have higher pub key)",
                                  src_ip_str, ntohs(src_addr.sin_port));
                        skip = 1;
                    } else {
                        LOG_INFO("Rekey collision from %s:%d — yielding (we have lower pub key)",
                                 src_ip_str, ntohs(src_addr.sin_port));
                        EVP_PKEY_free(p->hs_state.eph_key);
                        p->hs_state.eph_key = NULL;
                        p->active = 0;
                        peer_session_t *s = find_session_by_pub(peer_configs[p->cfg_idx].pub);
                        if (s) s->rekeying = 0;
                    }
                    break;
                }
                if (skip) { pthread_rwlock_unlock(&table_lock); continue; }

                peer_session_t *existing = find_session_by_addr(&src_addr);
                if (existing && now - existing->last_handshake < cfg_handshake_cooldown) {
                    LOG_WARN("Handshake cooldown for %s:%d — ignoring", src_ip_str, ntohs(src_addr.sin_port));
                    pthread_rwlock_unlock(&table_lock);
                    continue;
                }
                LOG_INFO("Inbound handshake from %s:%d", src_ip_str, ntohs(src_addr.sin_port));
                unsigned char session_key[CRYPTO_KEY_LEN];
                unsigned char peer_pub[DH_PUBKEY_LEN];
                if (handshake_server_respond(sock_fd, wire_buf, (int)nr, &src_addr,
                                             psk_key, static_key, static_pub,
                                             precomp_eph_key, precomp_eph_pub,
                                             peer_pub, session_key) < 0) {
                    pthread_rwlock_unlock(&table_lock);
                    continue;
                }
                refresh_precomp_eph();
                peer_config_t *cfg = find_peer_config(peer_pub);
                if (!cfg) {
                    char hex[DH_PUBKEY_LEN * 2 + 1];
                    bytes_to_hex(peer_pub, DH_PUBKEY_LEN, hex);
                    LOG_WARN("Unknown peer public key: %s — rejecting", hex);
                    pthread_rwlock_unlock(&table_lock);
                    continue;
                }
                peer_session_t *by_pub = find_session_by_pub(peer_pub);
                if (by_pub && now - by_pub->last_handshake < cfg_handshake_cooldown) {
                    LOG_WARN("Handshake cooldown for peer key — ignoring");
                    pthread_rwlock_unlock(&table_lock);
                    continue;
                }
                peer_session_t *s = alloc_session(peer_pub, &src_addr);
                if (!s) {
                    LOG_WARN("Session table full — rejecting %s:%d", src_ip_str, ntohs(src_addr.sin_port));
                    pthread_rwlock_unlock(&table_lock);
                    continue;
                }
                session_init(s, &src_addr, peer_pub, session_key, cfg, 0);
                print_sessions();
                pthread_rwlock_unlock(&table_lock);
                continue;
            }

            /* Data packet — held under table_lock (read) for the whole handling
             * span so the session can't be rekeyed/expired out from under us;
             * the actual crypto/seq/replay-window state is additionally guarded
             * by the session's own hot_lock (see decrypt_packet calls below and
             * forward_to_peer/check_replay usage). */
            pthread_rwlock_rdlock(&table_lock);
            peer_session_t *s = find_session_by_addr(&src_addr);
            if (!s) {
                pthread_rwlock_unlock(&table_lock);
                LOG_WARN("Packet from unknown peer %s:%d — dropping", src_ip_str, ntohs(src_addr.sin_port));
                continue;
            }

            int plain_len;
            int dec_ok = 0;
            int used_prev_key = 0;
            uint64_t seq = 0;
            int replay = 0;

            pthread_mutex_lock(&s->hot_lock);
            s->last_seen = now;
            if (decrypt_packet(dec_ctx, s->session_key, wire_buf, (int)nr, plain_buf, &plain_len) == 0) {
                dec_ok = 1;
                s->prev_key_active = 0;
            } else if (s->prev_key_active && now <= s->prev_key_expires) {
                if (decrypt_packet(dec_ctx, s->prev_session_key, wire_buf, (int)nr, plain_buf, &plain_len) == 0) {
                    dec_ok = 1;
                    used_prev_key = 1;
                }
            }
            if (dec_ok && plain_len >= HEADER_SIZE + SEQ_SIZE &&
                memcmp(plain_buf, pkt_header, HEADER_SIZE) == 0) {
                uint64_t seq_be;
                memcpy(&seq_be, plain_buf + HEADER_SIZE, SEQ_SIZE);
                seq = be64toh(seq_be);
                /* Skip replay check for prev-key packets: their old sequence numbers
                 * would advance recv_seq_highest and cause the new session's seq=1,2,...
                 * to be rejected as replays once the initiator switches to the new key. */
                if (!used_prev_key && check_replay(seq, &s->recv_seq_highest, s->recv_seq_window) < 0)
                    replay = 1;
            }
            pthread_mutex_unlock(&s->hot_lock);

            if (!dec_ok) {
                LOG_WARN("Decrypt failed from %s:%d — dropping", src_ip_str, ntohs(src_addr.sin_port));
                pthread_rwlock_unlock(&table_lock);
                continue;
            }
            if (plain_len < HEADER_SIZE + SEQ_SIZE || memcmp(plain_buf, pkt_header, HEADER_SIZE) != 0) {
                LOG_WARN("Bad header from %s:%d — dropping", src_ip_str, ntohs(src_addr.sin_port));
                pthread_rwlock_unlock(&table_lock);
                continue;
            }
            if (replay) {
                LOG_WARN("Replay from %s:%d (seq=%lu) — dropping",
                         src_ip_str, ntohs(src_addr.sin_port), (unsigned long)seq);
                pthread_rwlock_unlock(&table_lock);
                continue;
            }
            int payload_len = plain_len - HEADER_SIZE - SEQ_SIZE;
            if (payload_len == 0) { pthread_rwlock_unlock(&table_lock); continue; }
            const unsigned char *payload = plain_buf + HEADER_SIZE + SEQ_SIZE;
            if (s->route_count > 0 && payload_len >= 20 && (payload[0] >> 4) == 4) {
                uint32_t src_ip = ntohl(*(uint32_t *)(payload + 12));
                if (!check_allowed_src(s, src_ip)) {
                    struct in_addr a = { htonl(src_ip) };
                    char a_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &a, a_str, sizeof(a_str));
                    LOG_WARN("Source IP %s not in AllowedIPs for %s:%d — dropping",
                             a_str, src_ip_str, ntohs(src_addr.sin_port));
                    pthread_rwlock_unlock(&table_lock);
                    continue;
                }
            }
            /* Relay shortcut: if dst belongs to another peer, forward directly
             * without writing to TUN (avoids same-interface kernel routing). */
            if (payload_len >= 20 && (payload[0] >> 4) == 4) {
                uint32_t dst_ip = ntohl(*(uint32_t *)(payload + 16));
                peer_session_t *fwd = route_lookup(dst_ip);
                if (fwd && fwd != s) {
                    struct in_addr da = { htonl(dst_ip) };
                    char da_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &da, da_str, sizeof(da_str));
                    LOG_DEBUG("Relay: %s:%d -> (dst=%s)", src_ip_str, ntohs(src_addr.sin_port), da_str);
                    forward_to_peer(sock_fd, fwd, enc_ctx, plain_buf, payload, payload_len, wire_buf);
                    pthread_rwlock_unlock(&table_lock);
                    continue;
                }
            }
            pthread_rwlock_unlock(&table_lock);
            ssize_t nw = write(tun_fd, payload, payload_len);
            if (nw < 0) { LOG_WARN("TUN write: %s", strerror(errno)); continue; }
        }
    }
done:
    EVP_CIPHER_CTX_free(enc_ctx);
    EVP_CIPHER_CTX_free(dec_ctx);
    close(epoll_fd);
    if (stop_flag)
        LOG_INFO("Worker thread caught shutdown signal");
    else
        LOG_INFO("Worker thread terminated");
    return NULL;
}

static void start_peer(char *tunnel, const char *address, int port,
                       int keepalive_interval, const unsigned char *psk_key,
                       EVP_PKEY *static_key, const unsigned char *static_pub,
                       int worker_threads) {
    int sock_fd, tun_fd;

    if ((tun_fd = open_tunnel(tunnel)) < 0)
        exit(EXIT_FAILURE);

    if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        LOG_ERROR("socket: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    int opt = 1;
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    int bufsize = 4 * 1024 * 1024;
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    struct sockaddr_in bind_addr = {0};
    bind_addr.sin_family = AF_INET;
    if (*address) {
        if (inet_pton(AF_INET, address, &bind_addr.sin_addr) != 1) {
            LOG_ERROR("Config: invalid address: %s", address);
            exit(EXIT_FAILURE);
        }
    } else {
        bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    bind_addr.sin_port = htons(port);
    if (bind(sock_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        LOG_ERROR("bind: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    LOG_INFO("Listening on UDP %s:%d", *address ? address : "0.0.0.0", port);

    signal(SIGTERM, handle_signal);
    signal(SIGINT,  handle_signal);
    signal(SIGUSR1, handle_signal);

    refresh_precomp_eph();

    /* All sessions[] slots exist statically for the process lifetime, so
     * their hot_locks are initialized once, up front, before any thread
     * (including the ones we're about to spawn) can touch them. */
    for (int i = 0; i < MAX_PEERS; i++)
        pthread_mutex_init(&sessions[i].hot_lock, NULL);

    loop_ctx_t ctx = {
        .tun_fd             = tun_fd,
        .sock_fd            = sock_fd,
        .static_key         = static_key,
        .static_pub         = static_pub,
        .psk_key            = psk_key,
        .keepalive_interval = keepalive_interval,
    };

    LOG_INFO("Starting %d worker thread(s) + 1 housekeeping thread", worker_threads);
    pthread_t workers[MAX_WORKER_THREADS];
    for (int i = 0; i < worker_threads; i++) {
        if (pthread_create(&workers[i], NULL, worker_loop, &ctx) != 0) {
            LOG_ERROR("Failed to spawn worker thread %d: %s", i, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
    pthread_t housekeeping;
    if (pthread_create(&housekeeping, NULL, housekeeping_loop, &ctx) != 0) {
        LOG_ERROR("Failed to spawn housekeeping thread: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < worker_threads; i++)
        pthread_join(workers[i], NULL);
    pthread_join(housekeeping, NULL);

    if (stop_flag)
        LOG_INFO("Caught signal — shutting down");

    close(sock_fd);
    close(tun_fd);
}

int main(int argc, char *argv[]) {  
    const char *config_path = "peer.yaml";
    int opt;
    while ((opt = getopt(argc, argv, "c:")) > 0) {
        if (opt == 'c') config_path = optarg;
        else { fprintf(stderr, "Usage: %s [-c <config.yaml>]\n", argv[0]); exit(1); }
    }
    int port = 5040;
    int keepalive_interval = KEEPALIVE_INTERVAL_SECS;
    char tunnel[IF_NAMESIZE] = {0};
    char address[64] = {0};
    char keyfile[256] = "peer.key";
    char psk[256] = {0};
    int has_psk = 0;

    LOG_INFO("Loading config: %s", config_path);
    if (load_config(config_path, tunnel, address, &port, &keepalive_interval, keyfile, psk, &has_psk) < 0)
        exit(EXIT_FAILURE);

    if (*tunnel == '\0') { LOG_ERROR("Config: interface is required"); exit(EXIT_FAILURE); }
    if (peer_config_count == 0) { LOG_ERROR("Config: at least one peer is required"); exit(EXIT_FAILURE); }
    if (port <= 0 || port > 65535)           { LOG_ERROR("Config: port must be 1-65535 (got %d)", port); exit(EXIT_FAILURE); }
    if (keepalive_interval <= 0)             { LOG_ERROR("Config: keepalive_interval must be > 0 (got %d)", keepalive_interval); exit(EXIT_FAILURE); }
    if (cfg_rekey_after <= 0)                { LOG_ERROR("Config: rekey_after must be > 0 (got %d)", cfg_rekey_after); exit(EXIT_FAILURE); }
    if (cfg_reconnect_interval <= 0)         { LOG_ERROR("Config: reconnect_interval must be > 0 (got %d)", cfg_reconnect_interval); exit(EXIT_FAILURE); }
    if (cfg_session_expiry <= cfg_rekey_after) { LOG_ERROR("Config: session_expiry (%d) must be greater than rekey_after (%d)", cfg_session_expiry, cfg_rekey_after); exit(EXIT_FAILURE); }
    if (cfg_prev_key_grace <= 0)             { LOG_ERROR("Config: prev_key_grace must be > 0 (got %d)", cfg_prev_key_grace); exit(EXIT_FAILURE); }
    if (cfg_handshake_timeout <= 0)          { LOG_ERROR("Config: handshake_timeout must be > 0 (got %d)", cfg_handshake_timeout); exit(EXIT_FAILURE); }
    if (cfg_handshake_cooldown <= 0)         { LOG_ERROR("Config: handshake_cooldown must be > 0 (got %d)", cfg_handshake_cooldown); exit(EXIT_FAILURE); }
    if (cfg_worker_threads < 0)              { LOG_ERROR("Config: worker_threads must be >= 0 (got %d)", cfg_worker_threads); exit(EXIT_FAILURE); }
    if (cfg_worker_threads > MAX_WORKER_THREADS) {
        LOG_ERROR("Config: worker_threads must be <= %d (got %d)", MAX_WORKER_THREADS, cfg_worker_threads);
        exit(EXIT_FAILURE);
    }
    if (cfg_worker_threads == 0) {
        long nproc = sysconf(_SC_NPROCESSORS_ONLN);
        cfg_worker_threads = (nproc > 0 && nproc < DEFAULT_WORKER_THREADS) ? (int)nproc : DEFAULT_WORKER_THREADS;
    }

    LOG_INFO("Config: interface=%s port=%d%s%s", tunnel, port, *address ? " address=" : "", address);
    LOG_INFO("Config: keepalive_interval=%ds rekey_after=%ds reconnect_interval=%ds",
             keepalive_interval, cfg_rekey_after, cfg_reconnect_interval);
    LOG_INFO("Config: session_expiry=%ds prev_key_grace=%ds handshake_timeout=%ds handshake_cooldown=%ds",
             cfg_session_expiry, cfg_prev_key_grace, cfg_handshake_timeout, cfg_handshake_cooldown);
    LOG_INFO("Config: worker_threads=%d", cfg_worker_threads);

    EVP_PKEY *static_key = NULL;
    unsigned char static_pub[DH_PUBKEY_LEN];
    if (load_static_key(keyfile, &static_key, static_pub) < 0)
        exit(EXIT_FAILURE);

    char pub_hex[DH_PUBKEY_LEN * 2 + 1];
    bytes_to_hex(static_pub, DH_PUBKEY_LEN, pub_hex);
    LOG_INFO("Peer public key: %s", pub_hex);

    for (int i = 0; i < peer_config_count; i++) {
        char hex[DH_PUBKEY_LEN * 2 + 1];
        bytes_to_hex(peer_configs[i].pub, DH_PUBKEY_LEN, hex);
        LOG_INFO("Known peer: %s (%d route(s))%s", hex, peer_configs[i].route_count,
                 peer_configs[i].has_endpoint ? " [outbound]" : " [inbound-only]");
    }

    unsigned char psk_key[CRYPTO_KEY_LEN];
    if (has_psk) {
        derive_key(psk, psk_key);
        LOG_INFO("PSK set — handshake will be authenticated");
    } else {
        LOG_WARN("No PSK — handshake unauthenticated (MITM-vulnerable)");
    }

    start_peer(tunnel, address, port, keepalive_interval, has_psk ? psk_key : NULL, static_key, static_pub,
               cfg_worker_threads);
    EVP_PKEY_free(static_key);
    return 0;
}




