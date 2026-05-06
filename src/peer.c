#include <netdb.h>
#include <signal.h>
#include <time.h>
#include <yaml.h>
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

/* Runtime session with a connected peer */
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
} peer_session_t;

/* Pending outbound handshake — initiated but awaiting response in the epoll loop */
typedef struct {
    int                active;
    int                cfg_idx;
    time_t             sent_at;
    hs_client_state_t  hs_state;
    struct sockaddr_in server_addr;
} pending_hs_t;

static int cfg_rekey_after        = REKEY_AFTER_SECS;
static int cfg_reconnect_interval = RECONNECT_INTERVAL_SECS;
static int cfg_session_expiry     = SESSION_EXPIRY_SECS;

static peer_config_t  peer_configs[MAX_PEERS];
static int            peer_config_count = 0;
static peer_session_t sessions[MAX_PEERS];
static int            session_slots = 0;
static pending_hs_t   pending_hs[MAX_PEERS];

/* Pre-generated ephemeral keypair for the inbound handshake responder.
 * Generated at startup and refreshed immediately after each use so the
 * expensive X25519 keygen never runs on the event-loop hot path. */
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
                else if (strcmp(key, "rekey_after")         == 0) cfg_rekey_after            = atoi(v);
                else if (strcmp(key, "reconnect_interval")  == 0) cfg_reconnect_interval     = atoi(v);
                else if (strcmp(key, "session_expiry")      == 0) cfg_session_expiry         = atoi(v);
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
                    strncpy(pc->endpoint_host, buf, sizeof(pc->endpoint_host) - 1);
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

static peer_config_t *find_peer_config(const unsigned char *pub) {
    for (int i = 0; i < peer_config_count; i++)
        if (memcmp(peer_configs[i].pub, pub, DH_PUBKEY_LEN) == 0)
            return &peer_configs[i];
    return NULL;
}

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

/* Returns an existing slot (by pub first, then addr), falls back to a free slot */
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

static int check_allowed_src(peer_session_t *s, uint32_t src_ip) {
    if (s->route_count == 0) return 1;
    for (int i = 0; i < s->route_count; i++)
        if ((src_ip & s->routes[i].mask) == s->routes[i].network) return 1;
    return 0;
}

static void session_init(peer_session_t *s, struct sockaddr_in *addr,
                         const unsigned char *pub, unsigned char *key,
                         peer_config_t *cfg, int is_outbound) {
    int was_active = s->active;
    struct sockaddr_in old_addr = s->addr;

    s->active = 1;
    s->addr = *addr;
    memcpy(s->static_pub, pub, DH_PUBKEY_LEN);
    if (was_active) {
        memcpy(s->prev_session_key, s->session_key, CRYPTO_KEY_LEN);
        s->prev_key_active = 1;
        s->prev_key_expires = time(NULL) + PREV_KEY_GRACE_SECS;
    } else {
        s->prev_key_active = 0;
    }
    memcpy(s->session_key, key, CRYPTO_KEY_LEN);
    s->last_seen = 0;
    s->last_sent = time(NULL); /* suppress immediate keepalive after handshake */
    s->last_handshake = time(NULL);
    s->rekey_deadline = time(NULL) + cfg_rekey_after;
    s->rekeying = 0;
    s->send_seq = 0;
    s->recv_seq_highest = 0;
    memset(s->recv_seq_window, 0, sizeof(s->recv_seq_window));
    s->is_outbound = is_outbound;
    if (cfg) {
        memcpy(s->routes, cfg->routes, cfg->route_count * sizeof(ip_prefix_t));
        s->route_count = cfg->route_count;
    } else {
        s->route_count = 0;
    }

    char key_hex[17];
    bytes_to_hex(pub, 8, key_hex);
    if (was_active) {
        if (old_addr.sin_addr.s_addr != addr->sin_addr.s_addr ||
            old_addr.sin_port != addr->sin_port)
            LOG_INFO("Peer address changed: %s:%d -> %s:%d (key=%s...)",
                     inet_ntoa(old_addr.sin_addr), ntohs(old_addr.sin_port),
                     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port), key_hex);
        else
            LOG_INFO("Peer re-keyed: %s:%d (key=%s...)",
                     inet_ntoa(addr->sin_addr), ntohs(addr->sin_port), key_hex);
    } else {
        LOG_INFO("Peer connected: %s:%d (key=%s...)",
                 inet_ntoa(addr->sin_addr), ntohs(addr->sin_port), key_hex);
    }
}

static void print_sessions(void) {
    int active = 0;
    for (int i = 0; i < session_slots; i++) active += sessions[i].active ? 1 : 0;
    LOG_INFO("Active peers (%d):", active);
    for (int i = 0; i < session_slots; i++) {
        if (!sessions[i].active) continue;
        peer_session_t *s = &sessions[i];
        char key_hex[17];
        bytes_to_hex(s->static_pub, 8, key_hex);
        LOG_INFO("  [%s] %s:%d key=%s... routes=%d",
                 s->is_outbound ? "out" : "in",
                 inet_ntoa(s->addr.sin_addr), ntohs(s->addr.sin_port),
                 key_hex, s->route_count);
    }
}

static void forward_to_peer(int sock_fd, peer_session_t *s, EVP_CIPHER_CTX *enc_ctx,
                            unsigned char *plain_buf, const unsigned char *payload,
                            int payload_len, unsigned char *wire_buf) {
    int enc_len;
    uint64_t seq_be = htobe64(s->send_seq++);
    memcpy(plain_buf, pkt_header, HEADER_SIZE);
    memcpy(plain_buf + HEADER_SIZE, &seq_be, SEQ_SIZE);
    if (payload_len > 0)
        memcpy(plain_buf + HEADER_SIZE + SEQ_SIZE, payload, payload_len);
    if (encrypt_packet(enc_ctx, s->session_key, plain_buf, HEADER_SIZE + SEQ_SIZE + payload_len,
                       wire_buf, &enc_len) < 0) {
        LOG_ERROR("Encrypt failed for %s:%d",
                  inet_ntoa(s->addr.sin_addr), ntohs(s->addr.sin_port));
        return;
    }
    if (sendto(sock_fd, wire_buf, enc_len, 0, (struct sockaddr *)&s->addr, sizeof(s->addr)) >= 0)
        s->last_sent = time(NULL);
}

/* Send a handshake initiation to an outbound peer and register a pending entry.
 * Returns immediately — the response is handled asynchronously in the epoll loop.
 * The old session (if any) stays active and keeps forwarding until the response
 * arrives and session_init atomically replaces the key. */
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

static void event_loop(int tun_fd, int sock_fd, EVP_PKEY *static_key,
                       const unsigned char *static_pub, const unsigned char *psk_key,
                       int keepalive_interval) {
    unsigned char buffer[BUFFER_SIZE];
    unsigned char plain_buf[HEADER_SIZE + SEQ_SIZE + BUFFER_SIZE];
    unsigned char wire_buf[BUFFER_SIZE + WIRE_OVERHEAD];
    ssize_t nr;
    struct sockaddr_in src_addr;
    socklen_t src_addr_len;
    time_t last_rekey_check = 0;
    int hs_size = HEADER_SIZE + DH_PUBKEY_LEN + HS_ENCRYPTED_PUB_LEN + (psk_key ? HMAC_LEN : 0);

    EVP_CIPHER_CTX *enc_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *dec_ctx = EVP_CIPHER_CTX_new();
    if (!enc_ctx || !dec_ctx) {
        LOG_ERROR("Failed to allocate cipher contexts");
        EVP_CIPHER_CTX_free(enc_ctx);
        EVP_CIPHER_CTX_free(dec_ctx);
        return;
    }

    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) { LOG_ERROR("epoll_create1: %s", strerror(errno)); return; }

    struct epoll_event ev, events[2];
    ev.events = EPOLLIN;
    ev.data.fd = tun_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tun_fd, &ev);
    ev.data.fd = sock_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_fd, &ev);

    while (!stop_flag) {
        /* Periodically check whether outbound peers need (re)connecting */
        time_t now = time(NULL);
        if (now - last_rekey_check >= 10) {
            last_rekey_check = now;
            for (int i = 0; i < peer_config_count; i++) {
                peer_config_t *cfg = &peer_configs[i];
                if (!cfg->has_endpoint) continue;
                peer_session_t *s = find_session_by_pub(cfg->pub);
                int needs = !s || (now >= s->last_handshake + cfg_rekey_after * 4 / 5 && !s->rekeying);
                int ready  = now - cfg->last_attempt >= cfg_reconnect_interval;
                if (needs && ready) {
                    resolve_endpoint(cfg); /* refresh DNS; blocking but rate-limited to cfg_reconnect_interval */
                    if (s) s->rekeying = 1;
                    if (initiate_outbound_handshake(sock_fd, i, static_key, static_pub, psk_key) < 0)
                        if (s) s->rekeying = 0;
                }
            }
            /* Expire timed-out pending handshakes */
            for (int j = 0; j < MAX_PEERS; j++) {
                pending_hs_t *p = &pending_hs[j];
                if (!p->active || now - p->sent_at < HANDSHAKE_TIMEOUT_SECS) continue;
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &peer_configs[p->cfg_idx].endpoint.sin_addr, ip_str, sizeof(ip_str));
                LOG_WARN("Handshake to %s:%d timed out — will retry in %ds",
                         ip_str, ntohs(peer_configs[p->cfg_idx].endpoint.sin_port),
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
                char key_hex[17];
                bytes_to_hex(s->static_pub, 8, key_hex);
                LOG_INFO("Session expired (no traffic for %ds): %s:%d key=%s...",
                         (int)(now - ref),
                         inet_ntoa(s->addr.sin_addr), ntohs(s->addr.sin_port), key_hex);
                s->active = 0;
            }
            /* Send keepalive to sessions that have had no outbound traffic recently */
            for (int j = 0; j < session_slots; j++) {
                peer_session_t *s = &sessions[j];
                if (!s->active || now - s->last_sent < keepalive_interval) continue;
                LOG_DEBUG("Keepalive -> %s:%d",
                          inet_ntoa(s->addr.sin_addr), ntohs(s->addr.sin_port));
                forward_to_peer(sock_fd, s, enc_ctx, plain_buf, NULL, 0, wire_buf);
            }
        }

        int nfds = epoll_wait(epoll_fd, events, 2, 5000);
        if (nfds < 0) {
            if (errno == EINTR) continue; /* signal interrupted — recheck stop_flag/print_sessions_flag */
            LOG_ERROR("epoll_wait: %s", strerror(errno)); break;
        }

        if (print_sessions_flag) {
            print_sessions_flag = 0;
            print_sessions();
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
                    peer_session_t *s = route_lookup(dst_ip);
                    if (s) {
                        LOG_DEBUG("TUN->UDP: forwarding to %s:%d (dst=%s)",
                                  inet_ntoa(s->addr.sin_addr), ntohs(s->addr.sin_port),
                                  inet_ntoa(da));
                        forward_to_peer(sock_fd, s, enc_ctx, plain_buf, buffer, (int)nr, wire_buf);
                    } else {
                        LOG_DEBUG("No route for %s — dropping", inet_ntoa(da));
                    }
                }
                continue;
            }

            /* UDP -> TUN or handshake */
            src_addr_len = sizeof(src_addr);
            nr = recvfrom(sock_fd, wire_buf, sizeof(wire_buf), 0,
                          (struct sockaddr *)&src_addr, &src_addr_len);
            if (nr < 0) { LOG_ERROR("recvfrom: %s", strerror(errno)); goto done; }

            now = time(NULL);

            /* Response to a pending outbound handshake — check before inbound path */
            if (nr == hs_size && memcmp(wire_buf, pkt_header, HEADER_SIZE) == 0) {
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
                if (handled) continue;
            }

            /* Inbound handshake */
            if (nr == hs_size && memcmp(wire_buf, pkt_header, HEADER_SIZE) == 0) {
                /* Tie-breaking: if we have a pending outbound to this peer, the side
                 * with the higher pub key wins and ignores the inbound initiation. */
                int skip = 0;
                for (int j = 0; j < MAX_PEERS; j++) {
                    pending_hs_t *p = &pending_hs[j];
                    if (!p->active) continue;
                    if (p->server_addr.sin_addr.s_addr != src_addr.sin_addr.s_addr ||
                        p->server_addr.sin_port        != src_addr.sin_port) continue;
                    if (memcmp(static_pub, peer_configs[p->cfg_idx].pub, DH_PUBKEY_LEN) > 0) {
                        LOG_DEBUG("Rekey collision from %s:%d — ignoring (we have higher pub key)",
                                  inet_ntoa(src_addr.sin_addr), ntohs(src_addr.sin_port));
                        skip = 1;
                    } else {
                        LOG_INFO("Rekey collision from %s:%d — yielding (we have lower pub key)",
                                 inet_ntoa(src_addr.sin_addr), ntohs(src_addr.sin_port));
                        EVP_PKEY_free(p->hs_state.eph_key);
                        p->hs_state.eph_key = NULL;
                        p->active = 0;
                        peer_session_t *s = find_session_by_pub(peer_configs[p->cfg_idx].pub);
                        if (s) s->rekeying = 0;
                    }
                    break;
                }
                if (skip) continue;

                peer_session_t *existing = find_session_by_addr(&src_addr);
                if (existing && now - existing->last_handshake < HANDSHAKE_COOLDOWN_SECS) {
                    LOG_WARN("Handshake cooldown for %s:%d — ignoring",
                             inet_ntoa(src_addr.sin_addr), ntohs(src_addr.sin_port));
                    continue;
                }
                LOG_INFO("Inbound handshake from %s:%d",
                         inet_ntoa(src_addr.sin_addr), ntohs(src_addr.sin_port));
                unsigned char session_key[CRYPTO_KEY_LEN];
                unsigned char peer_pub[DH_PUBKEY_LEN];
                if (handshake_server_respond(sock_fd, wire_buf, (int)nr, &src_addr,
                                             psk_key, static_key, static_pub,
                                             precomp_eph_key, precomp_eph_pub,
                                             peer_pub, session_key) < 0)
                    continue;
                refresh_precomp_eph();
                peer_config_t *cfg = find_peer_config(peer_pub);
                if (!cfg) {
                    char hex[DH_PUBKEY_LEN * 2 + 1];
                    bytes_to_hex(peer_pub, DH_PUBKEY_LEN, hex);
                    LOG_WARN("Unknown peer public key: %s — rejecting", hex);
                    continue;
                }
                peer_session_t *by_pub = find_session_by_pub(peer_pub);
                if (by_pub && now - by_pub->last_handshake < HANDSHAKE_COOLDOWN_SECS) {
                    LOG_WARN("Handshake cooldown for peer key — ignoring");
                    continue;
                }
                peer_session_t *s = alloc_session(peer_pub, &src_addr);
                if (!s) {
                    LOG_WARN("Session table full — rejecting %s:%d",
                             inet_ntoa(src_addr.sin_addr), ntohs(src_addr.sin_port));
                    continue;
                }
                session_init(s, &src_addr, peer_pub, session_key, cfg, 0);
                print_sessions();
                continue;
            }

            /* Data packet */
            peer_session_t *s = find_session_by_addr(&src_addr);
            if (!s) {
                LOG_WARN("Packet from unknown peer %s:%d — dropping",
                         inet_ntoa(src_addr.sin_addr), ntohs(src_addr.sin_port));
                continue;
            }
            s->last_seen = now;
            int plain_len;
            int dec_ok = 0;
            int used_prev_key = 0;
            if (decrypt_packet(dec_ctx, s->session_key, wire_buf, (int)nr, plain_buf, &plain_len) == 0) {
                dec_ok = 1;
                s->prev_key_active = 0;
            } else if (s->prev_key_active && now <= s->prev_key_expires) {
                if (decrypt_packet(dec_ctx, s->prev_session_key, wire_buf, (int)nr, plain_buf, &plain_len) == 0) {
                    dec_ok = 1;
                    used_prev_key = 1;
                }
            }
            if (!dec_ok) {
                LOG_WARN("Decrypt failed from %s:%d — dropping",
                         inet_ntoa(s->addr.sin_addr), ntohs(s->addr.sin_port));
                continue;
            }
            if (plain_len < HEADER_SIZE + SEQ_SIZE ||
                memcmp(plain_buf, pkt_header, HEADER_SIZE) != 0) {
                LOG_WARN("Bad header from %s:%d — dropping",
                         inet_ntoa(s->addr.sin_addr), ntohs(s->addr.sin_port));
                continue;
            }
            uint64_t seq_be;
            memcpy(&seq_be, plain_buf + HEADER_SIZE, SEQ_SIZE);
            uint64_t seq = be64toh(seq_be);
            /* Skip replay check for prev-key packets: their old sequence numbers
             * would advance recv_seq_highest and cause the new session's seq=1,2,...
             * to be rejected as replays once the initiator switches to the new key. */
            if (!used_prev_key && check_replay(seq, &s->recv_seq_highest, s->recv_seq_window) < 0) {
                LOG_WARN("Replay from %s:%d (seq=%lu) — dropping",
                         inet_ntoa(s->addr.sin_addr), ntohs(s->addr.sin_port), (unsigned long)seq);
                continue;
            }
            int payload_len = plain_len - HEADER_SIZE - SEQ_SIZE;
            if (payload_len == 0) continue;
            const unsigned char *payload = plain_buf + HEADER_SIZE + SEQ_SIZE;
            if (s->route_count > 0 && payload_len >= 20 && (payload[0] >> 4) == 4) {
                uint32_t src_ip = ntohl(*(uint32_t *)(payload + 12));
                if (!check_allowed_src(s, src_ip)) {
                    struct in_addr a = { htonl(src_ip) };
                    LOG_WARN("Source IP %s not in AllowedIPs for %s:%d — dropping",
                             inet_ntoa(a),
                             inet_ntoa(s->addr.sin_addr), ntohs(s->addr.sin_port));
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
                    LOG_DEBUG("Relay: %s:%d -> %s:%d (dst=%s)",
                              inet_ntoa(s->addr.sin_addr), ntohs(s->addr.sin_port),
                              inet_ntoa(fwd->addr.sin_addr), ntohs(fwd->addr.sin_port),
                              inet_ntoa(da));
                    forward_to_peer(sock_fd, fwd, enc_ctx, plain_buf, payload, payload_len, wire_buf);
                    continue;
                }
            }
            ssize_t nw = write(tun_fd, payload, payload_len);
            if (nw < 0) { LOG_WARN("TUN write: %s", strerror(errno)); continue; }
        }
    }
done:
    EVP_CIPHER_CTX_free(enc_ctx);
    EVP_CIPHER_CTX_free(dec_ctx);
    close(epoll_fd);
    if (stop_flag)
        LOG_INFO("Caught signal — shutting down");
    else
        LOG_INFO("Event loop terminated");
}

static void start_peer(char *tunnel, const char *address, int port,
                       int keepalive_interval, const unsigned char *psk_key,
                       EVP_PKEY *static_key, const unsigned char *static_pub) {
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
    event_loop(tun_fd, sock_fd, static_key, static_pub, psk_key, keepalive_interval);

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

    start_peer(tunnel, address, port, keepalive_interval, has_psk ? psk_key : NULL, static_key, static_pub);
    EVP_PKEY_free(static_key);
    return 0;
}




