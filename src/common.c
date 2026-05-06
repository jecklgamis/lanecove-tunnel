#include "common.h"

int log_level = 0;

const unsigned char pkt_header[HEADER_SIZE] = {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe};

void derive_key(const char *psk, unsigned char *key) {
    SHA256((const unsigned char *) psk, strlen(psk), key);
}

void bytes_to_hex(const unsigned char *bytes, int len, char *hex_out) {
    for (int i = 0; i < len; i++)
        sprintf(hex_out + i * 2, "%02x", bytes[i]);
    hex_out[len * 2] = '\0';
}

int hex_to_bytes(const char *hex, unsigned char *bytes_out, int expected_len) {
    if ((int) strlen(hex) != expected_len * 2) return -1;
    for (int i = 0; i < expected_len; i++) {
        unsigned int byte;
        int n = 0;
        if (sscanf(hex + i * 2, "%02x%n", &byte, &n) != 1 || n != 2) return -1;
        bytes_out[i] = (unsigned char) byte;
    }
    return 0;
}

int encrypt_packet(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                   const unsigned char *plain, int plain_len,
                   unsigned char *out, int *out_len) {
    unsigned char iv[CRYPTO_IV_LEN];
    if (RAND_bytes(iv, CRYPTO_IV_LEN) != 1)
        return -1;

    int len, ciphertext_len;
    unsigned char *ciphertext = out + CRYPTO_IV_LEN;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) goto err;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plain, plain_len) != 1) goto err;
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) goto err;
    ciphertext_len += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, CRYPTO_TAG_LEN,
                             out + CRYPTO_IV_LEN + ciphertext_len) != 1) goto err;

    memcpy(out, iv, CRYPTO_IV_LEN);
    *out_len = CRYPTO_IV_LEN + ciphertext_len + CRYPTO_TAG_LEN;
    return 0;
err:
    EVP_CIPHER_CTX_reset(ctx);
    return -1;
}

int decrypt_packet(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                   const unsigned char *in, int in_len,
                   unsigned char *out, int *out_len) {
    if (in_len < CRYPTO_OVERHEAD)
        return -1;

    const unsigned char *iv = in;
    const unsigned char *ciphertext = in + CRYPTO_IV_LEN;
    int ciphertext_len = in_len - CRYPTO_OVERHEAD;
    unsigned char tag[CRYPTO_TAG_LEN];
    memcpy(tag, in + in_len - CRYPTO_TAG_LEN, CRYPTO_TAG_LEN);

    int len, plain_len;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) goto err;
    if (EVP_DecryptUpdate(ctx, out, &len, ciphertext, ciphertext_len) != 1) goto err;
    plain_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, CRYPTO_TAG_LEN, tag) != 1) goto err;
    if (EVP_DecryptFinal_ex(ctx, out + len, &len) != 1) goto err;
    plain_len += len;

    *out_len = plain_len;
    return 0;
err:
    EVP_CIPHER_CTX_reset(ctx);
    return -1;
}

static int alloc_tunnel(char *dev, int flags) {
    struct ifreq ifr;
    int tun_fd, ret_val;

    if ((tun_fd = open("/dev/net/tun", O_RDWR)) < 0) {
        LOG_ERROR("Unable to open tunnel : %s", strerror(errno));
        return tun_fd;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags;
    if (*dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if ((ret_val = ioctl(tun_fd, TUNSETIFF, (void *) &ifr)) < 0) {
        LOG_ERROR("Unable to issue ioctl on %d : %s", tun_fd, strerror(errno));
        close(tun_fd);
        return ret_val;
    }
    strcpy(dev, ifr.ifr_name);
    return tun_fd;
}

int open_tunnel(char *tunnel) {
    int tun_fd;
    if ((tun_fd = alloc_tunnel(tunnel, IFF_TUN | IFF_NO_PI)) < 0) {
        LOG_ERROR("Unable to connect to tunnel %s", tunnel);
        return tun_fd;
    }

    LOG_INFO("Opened tunnel %s", tunnel);
    return tun_fd;
}

int generate_eph_keypair(EVP_PKEY **pkey_out, unsigned char *pub_out) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) return -1;
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(pctx) != 1 || EVP_PKEY_keygen(pctx, &pkey) != 1) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    EVP_PKEY_CTX_free(pctx);
    size_t pub_len = DH_PUBKEY_LEN;
    if (EVP_PKEY_get_raw_public_key(pkey, pub_out, &pub_len) != 1) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    *pkey_out = pkey;
    return 0;
}

int load_or_generate_static_key(const char *path, EVP_PKEY **pkey_out, unsigned char *pub_out) {
    FILE *f = fopen(path, "rb");
    if (f) {
        unsigned char priv[DH_PUBKEY_LEN];
        size_t n = fread(priv, 1, DH_PUBKEY_LEN, f);
        fclose(f);
        if (n == DH_PUBKEY_LEN) {
            EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, DH_PUBKEY_LEN);
            if (pkey) {
                size_t pub_len = DH_PUBKEY_LEN;
                if (EVP_PKEY_get_raw_public_key(pkey, pub_out, &pub_len) == 1) {
                    *pkey_out = pkey;
                    LOG_INFO("Loaded static key from %s", path);
                    return 0;
                }
                EVP_PKEY_free(pkey);
            }
        }
        LOG_ERROR("Failed to parse static key from %s", path);
        return -1;
    }
    if (generate_eph_keypair(pkey_out, pub_out) < 0) {
        LOG_ERROR("Failed to generate static key");
        return -1;
    }
    unsigned char priv[DH_PUBKEY_LEN];
    size_t priv_len = DH_PUBKEY_LEN;
    if (EVP_PKEY_get_raw_private_key(*pkey_out, priv, &priv_len) != 1) {
        EVP_PKEY_free(*pkey_out);
        *pkey_out = NULL;
        return -1;
    }
    f = fopen(path, "wb");
    if (!f) {
        LOG_ERROR("Failed to save static key to %s : %s", path, strerror(errno));
        EVP_PKEY_free(*pkey_out);
        *pkey_out = NULL;
        return -1;
    }
    fwrite(priv, 1, DH_PUBKEY_LEN, f);
    fclose(f);
    LOG_INFO("Generated and saved static key to %s", path);
    return 0;
}

int load_public_key(const char *path, unsigned char *pub_out) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        LOG_ERROR("Server public key file not found: %s", path);
        return -1;
    }
    EVP_PKEY *pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    if (!pkey) {
        LOG_ERROR("Failed to parse PEM public key from %s", path);
        return -1;
    }
    size_t pub_len = DH_PUBKEY_LEN;
    int rc = EVP_PKEY_get_raw_public_key(pkey, pub_out, &pub_len) == 1 ? 0 : -1;
    if (rc < 0)
        LOG_ERROR("Failed to extract raw public key from %s", path);
    EVP_PKEY_free(pkey);
    return rc;
}

int load_static_key(const char *path, EVP_PKEY **pkey_out, unsigned char *pub_out) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        LOG_ERROR("Static key file not found: %s", path);
        return -1;
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!pkey) {
        LOG_ERROR("Failed to parse PEM private key from %s", path);
        return -1;
    }
    size_t pub_len = DH_PUBKEY_LEN;
    if (EVP_PKEY_get_raw_public_key(pkey, pub_out, &pub_len) != 1) {
        LOG_ERROR("Failed to extract public key from %s", path);
        EVP_PKEY_free(pkey);
        return -1;
    }
    *pkey_out = pkey;
    LOG_INFO("Loaded static key from %s", path);
    return 0;
}

static int x25519_shared_secret(EVP_PKEY *my_key, const unsigned char *peer_pub,
                                unsigned char *secret_out) {
    EVP_PKEY *peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, DH_PUBKEY_LEN);
    if (!peer_key) return -1;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(my_key, NULL);
    if (!ctx) { EVP_PKEY_free(peer_key); return -1; }
    size_t secret_len = DH_PUBKEY_LEN;
    int rc = -1;
    if (EVP_PKEY_derive_init(ctx) == 1 &&
        EVP_PKEY_derive_set_peer(ctx, peer_key) == 1 &&
        EVP_PKEY_derive(ctx, secret_out, &secret_len) == 1)
        rc = 0;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_key);
    return rc;
}

/*
 * Session key = SHA-256(ecdh_eph || ecdh_static_c_eph_s || ecdh_eph_c_static_s
 *                       || client_eph_pub || server_eph_pub
 *                       || client_static_pub || server_static_pub)
 *
 * All three ECDH values are computable by both parties:
 *   ecdh_eph          = ECDH(eph_c, eph_s)
 *   ecdh_static_c_eph_s = ECDH(static_c, eph_s)  [client: static_c_priv x eph_s_pub]
 *                                                  [server: eph_s_priv x static_c_pub]
 *   ecdh_eph_c_static_s = ECDH(eph_c, static_s)  [client: eph_c_priv x static_s_pub]
 *                                                  [server: static_s_priv x eph_c_pub]
 */
static void derive_session_key(const unsigned char *ecdh_eph,
                               const unsigned char *ecdh_sc_es,
                               const unsigned char *ecdh_ec_ss,
                               const unsigned char *client_eph_pub,
                               const unsigned char *server_eph_pub,
                               const unsigned char *client_static_pub,
                               const unsigned char *server_static_pub,
                               unsigned char *session_key) {
    unsigned char input[DH_PUBKEY_LEN * 7];
    memcpy(input,                       ecdh_eph,          DH_PUBKEY_LEN);
    memcpy(input + DH_PUBKEY_LEN,       ecdh_sc_es,        DH_PUBKEY_LEN);
    memcpy(input + DH_PUBKEY_LEN * 2,   ecdh_ec_ss,        DH_PUBKEY_LEN);
    memcpy(input + DH_PUBKEY_LEN * 3,   client_eph_pub,    DH_PUBKEY_LEN);
    memcpy(input + DH_PUBKEY_LEN * 4,   server_eph_pub,    DH_PUBKEY_LEN);
    memcpy(input + DH_PUBKEY_LEN * 5,   client_static_pub, DH_PUBKEY_LEN);
    memcpy(input + DH_PUBKEY_LEN * 6,   server_static_pub, DH_PUBKEY_LEN);
    SHA256(input, sizeof(input), session_key);
}

static int compute_hmac(const unsigned char *psk_key,
                        const unsigned char *msg, int msg_len,
                        unsigned char *hmac_out) {
    unsigned int hlen = HMAC_LEN;
    return HMAC(EVP_sha256(), psk_key, CRYPTO_KEY_LEN, msg, msg_len,
                hmac_out, &hlen) ? 0 : -1;
}

/* Encrypt a 32-byte public key for identity hiding.
 * key_material: 32-byte DH shared secret (unique per handshake — zero IV is safe).
 * out: DH_PUBKEY_LEN + CRYPTO_TAG_LEN = 48 bytes. */
static int encrypt_identity(const unsigned char *key_material,
                             const unsigned char *pub, unsigned char *out) {
    unsigned char key[CRYPTO_KEY_LEN];
    SHA256(key_material, DH_PUBKEY_LEN, key);
    unsigned char iv[CRYPTO_IV_LEN] = {0};
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) goto err;
    if (EVP_EncryptUpdate(ctx, out, &len, pub, DH_PUBKEY_LEN) != 1) goto err;
    if (EVP_EncryptFinal_ex(ctx, out + len, &len) != 1) goto err;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, CRYPTO_TAG_LEN,
                             out + DH_PUBKEY_LEN) != 1) goto err;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

/* Decrypt a 48-byte encrypted public key. Returns 0 on success, -1 on auth failure. */
static int decrypt_identity(const unsigned char *key_material,
                             const unsigned char *in, unsigned char *pub_out) {
    unsigned char key[CRYPTO_KEY_LEN];
    SHA256(key_material, DH_PUBKEY_LEN, key);
    unsigned char iv[CRYPTO_IV_LEN] = {0};
    unsigned char tag[CRYPTO_TAG_LEN];
    memcpy(tag, in + DH_PUBKEY_LEN, CRYPTO_TAG_LEN);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) goto err;
    if (EVP_DecryptUpdate(ctx, pub_out, &len, in, DH_PUBKEY_LEN) != 1) goto err;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, CRYPTO_TAG_LEN, tag) != 1) goto err;
    if (EVP_DecryptFinal_ex(ctx, pub_out + len, &len) != 1) goto err;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int handshake_client_send(int sock_fd, struct sockaddr_in *server_addr,
                          const unsigned char *psk_key,
                          EVP_PKEY *static_key, const unsigned char *static_pub,
                          const unsigned char *server_static_pub,
                          hs_client_state_t *state_out) {
    (void)static_key;
    if (!server_static_pub) {
        LOG_ERROR("Server static public key required for identity hiding");
        return -1;
    }

    EVP_PKEY *eph_key = NULL;
    unsigned char eph_pub[DH_PUBKEY_LEN];
    if (generate_eph_keypair(&eph_key, eph_pub) < 0) {
        LOG_ERROR("Failed to generate ephemeral key pair");
        return -1;
    }

    /* ecdh_ec_ss = DH(eph_c, server_static) — also used as identity encryption key */
    unsigned char ecdh_ec_ss[DH_PUBKEY_LEN];
    if (x25519_shared_secret(eph_key, server_static_pub, ecdh_ec_ss) < 0) {
        LOG_ERROR("X25519 key derivation failed");
        EVP_PKEY_free(eph_key);
        return -1;
    }

    /* Encrypt client static pub: AES-256-GCM(SHA-256(DH(eph_c, server_static)), static_pub) */
    unsigned char enc_static[HS_ENCRYPTED_PUB_LEN];
    if (encrypt_identity(ecdh_ec_ss, static_pub, enc_static) < 0) {
        LOG_ERROR("Failed to encrypt client identity");
        EVP_PKEY_free(eph_key);
        return -1;
    }

    /* [magic][eph_pub][enc_static(48)][HMAC(psk, eph_pub||enc_static)]? */
    unsigned char pkt[HEADER_SIZE + DH_PUBKEY_LEN + HS_ENCRYPTED_PUB_LEN + HMAC_LEN];
    int pkt_len = HEADER_SIZE + DH_PUBKEY_LEN + HS_ENCRYPTED_PUB_LEN;
    memcpy(pkt, pkt_header, HEADER_SIZE);
    memcpy(pkt + HEADER_SIZE, eph_pub, DH_PUBKEY_LEN);
    memcpy(pkt + HEADER_SIZE + DH_PUBKEY_LEN, enc_static, HS_ENCRYPTED_PUB_LEN);
    if (psk_key) {
        if (compute_hmac(psk_key, pkt + HEADER_SIZE, DH_PUBKEY_LEN + HS_ENCRYPTED_PUB_LEN,
                         pkt + pkt_len) < 0) {
            LOG_ERROR("HMAC computation failed");
            EVP_PKEY_free(eph_key);
            return -1;
        }
        pkt_len += HMAC_LEN;
    }
    if (sendto(sock_fd, pkt, pkt_len, 0,
               (struct sockaddr *) server_addr, sizeof(*server_addr)) < 0) {
        LOG_ERROR("sendto() handshake failed : %s", strerror(errno));
        EVP_PKEY_free(eph_key);
        return -1;
    }

    state_out->eph_key = eph_key;
    memcpy(state_out->eph_pub, eph_pub, DH_PUBKEY_LEN);
    memcpy(state_out->ecdh_ec_ss, ecdh_ec_ss, DH_PUBKEY_LEN);
    return 0;
}

int handshake_client_recv(const unsigned char *resp, int resp_len,
                          const unsigned char *psk_key,
                          EVP_PKEY *static_key, const unsigned char *static_pub,
                          const unsigned char *server_static_pub,
                          hs_client_state_t *state,
                          unsigned char *session_key_out) {
    int expected = HEADER_SIZE + DH_PUBKEY_LEN + HS_ENCRYPTED_PUB_LEN + (psk_key ? HMAC_LEN : 0);
    if (resp_len != expected) {
        LOG_ERROR("Handshake response size mismatch: got %d, expected %d", resp_len, expected);
        return -1;
    }
    if (memcmp(resp, pkt_header, HEADER_SIZE) != 0) {
        LOG_ERROR("Handshake response has bad magic");
        return -1;
    }

    const unsigned char *server_eph_pub    = resp + HEADER_SIZE;
    const unsigned char *enc_server_static = resp + HEADER_SIZE + DH_PUBKEY_LEN;

    if (psk_key) {
        unsigned char expected_hmac[HMAC_LEN];
        if (compute_hmac(psk_key, resp + HEADER_SIZE, DH_PUBKEY_LEN + HS_ENCRYPTED_PUB_LEN,
                         expected_hmac) < 0 ||
            CRYPTO_memcmp(resp + HEADER_SIZE + DH_PUBKEY_LEN + HS_ENCRYPTED_PUB_LEN,
                          expected_hmac, HMAC_LEN) != 0) {
            LOG_ERROR("Server handshake HMAC verification failed — possible MITM");
            return -1;
        }
    }

    /* ecdh_eph = DH(eph_c, eph_s) — also used as server identity decryption key */
    unsigned char ecdh_eph[DH_PUBKEY_LEN];
    if (x25519_shared_secret(state->eph_key, server_eph_pub, ecdh_eph) < 0) {
        LOG_ERROR("X25519 key derivation failed");
        return -1;
    }

    /* Decrypt server static pub: AES-256-GCM(SHA-256(DH(eph_c, eph_s)), enc_server_static) */
    unsigned char server_static_pub_recv[DH_PUBKEY_LEN];
    if (decrypt_identity(ecdh_eph, enc_server_static, server_static_pub_recv) < 0) {
        LOG_ERROR("Failed to decrypt server identity — possible MITM");
        return -1;
    }

    if (memcmp(server_static_pub_recv, server_static_pub, DH_PUBKEY_LEN) != 0) {
        LOG_ERROR("Server static public key mismatch — possible MITM");
        return -1;
    }

    unsigned char ecdh_sc_es[DH_PUBKEY_LEN];
    if (x25519_shared_secret(static_key, server_eph_pub, ecdh_sc_es) < 0) {
        LOG_ERROR("X25519 key derivation failed");
        return -1;
    }

    derive_session_key(ecdh_eph, ecdh_sc_es, state->ecdh_ec_ss,
                       state->eph_pub, server_eph_pub,
                       static_pub, server_static_pub_recv,
                       session_key_out);

    EVP_PKEY_free(state->eph_key);
    state->eph_key = NULL;

    char pub_hex[DH_PUBKEY_LEN * 2 + 1];
    bytes_to_hex(server_static_pub_recv, 8, pub_hex);
    LOG_INFO("Handshake complete — server identity: %s...", pub_hex);
    return 0;
}

int handshake_server_respond(int sock_fd, const unsigned char *pkt, int pkt_len,
                             struct sockaddr_in *peer_addr,
                             const unsigned char *psk_key,
                             EVP_PKEY *static_key, const unsigned char *static_pub,
                             EVP_PKEY *precomp_eph_key, const unsigned char *precomp_eph_pub,
                             unsigned char *client_static_pub_out,
                             unsigned char *session_key) {
    int expected = HEADER_SIZE + DH_PUBKEY_LEN + HS_ENCRYPTED_PUB_LEN + (psk_key ? HMAC_LEN : 0);
    if (pkt_len != expected) {
        LOG_ERROR("Client handshake size mismatch: got %d, expected %d", pkt_len, expected);
        return -1;
    }
    if (memcmp(pkt, pkt_header, HEADER_SIZE) != 0) {
        LOG_ERROR("Client handshake has bad magic");
        return -1;
    }

    const unsigned char *client_eph_pub  = pkt + HEADER_SIZE;
    const unsigned char *enc_client_static = pkt + HEADER_SIZE + DH_PUBKEY_LEN;

    if (psk_key) {
        unsigned char expected_hmac[HMAC_LEN];
        if (compute_hmac(psk_key, pkt + HEADER_SIZE, DH_PUBKEY_LEN + HS_ENCRYPTED_PUB_LEN,
                         expected_hmac) < 0 ||
            CRYPTO_memcmp(pkt + HEADER_SIZE + DH_PUBKEY_LEN + HS_ENCRYPTED_PUB_LEN,
                          expected_hmac, HMAC_LEN) != 0) {
            LOG_ERROR("Client handshake HMAC verification failed — rejecting");
            return -1;
        }
    }

    /* ecdh_ec_ss = DH(server_static, eph_c) — also decrypts client identity */
    unsigned char ecdh_ec_ss[DH_PUBKEY_LEN];
    if (x25519_shared_secret(static_key, client_eph_pub, ecdh_ec_ss) < 0) {
        LOG_ERROR("X25519 key derivation failed");
        return -1;
    }

    unsigned char client_static_pub[DH_PUBKEY_LEN];
    if (decrypt_identity(ecdh_ec_ss, enc_client_static, client_static_pub) < 0) {
        LOG_ERROR("Failed to decrypt client identity — invalid key or tampered packet");
        return -1;
    }
    memcpy(client_static_pub_out, client_static_pub, DH_PUBKEY_LEN);

    EVP_PKEY *eph_key = precomp_eph_key;
    unsigned char eph_pub[DH_PUBKEY_LEN];
    memcpy(eph_pub, precomp_eph_pub, DH_PUBKEY_LEN);

    /* ecdh_eph = DH(eph_s, eph_c) — also encrypts server identity */
    unsigned char ecdh_eph[DH_PUBKEY_LEN];
    if (x25519_shared_secret(eph_key, client_eph_pub, ecdh_eph) < 0) {
        LOG_ERROR("X25519 key derivation failed");
        return -1;
    }

    /* Encrypt server static pub: AES-256-GCM(SHA-256(DH(eph_s, eph_c)), static_pub) */
    unsigned char enc_server_static[HS_ENCRYPTED_PUB_LEN];
    if (encrypt_identity(ecdh_eph, static_pub, enc_server_static) < 0) {
        LOG_ERROR("Failed to encrypt server identity");
        return -1;
    }

    /* [magic][eph_s_pub][enc_server_static(48)][HMAC(psk, eph_s_pub||enc_server_static)]? */
    unsigned char resp[HEADER_SIZE + DH_PUBKEY_LEN + HS_ENCRYPTED_PUB_LEN + HMAC_LEN];
    int resp_len = HEADER_SIZE + DH_PUBKEY_LEN + HS_ENCRYPTED_PUB_LEN;
    memcpy(resp, pkt_header, HEADER_SIZE);
    memcpy(resp + HEADER_SIZE, eph_pub, DH_PUBKEY_LEN);
    memcpy(resp + HEADER_SIZE + DH_PUBKEY_LEN, enc_server_static, HS_ENCRYPTED_PUB_LEN);
    if (psk_key) {
        if (compute_hmac(psk_key, resp + HEADER_SIZE, DH_PUBKEY_LEN + HS_ENCRYPTED_PUB_LEN,
                         resp + resp_len) < 0) {
            LOG_ERROR("HMAC computation failed");
            return -1;
        }
        resp_len += HMAC_LEN;
    }
    if (sendto(sock_fd, resp, resp_len, 0,
               (struct sockaddr *) peer_addr, sizeof(*peer_addr)) < 0) {
        LOG_ERROR("sendto() handshake response failed : %s", strerror(errno));
        return -1;
    }

    unsigned char ecdh_sc_es[DH_PUBKEY_LEN];
    if (x25519_shared_secret(eph_key, client_static_pub, ecdh_sc_es) < 0) {
        LOG_ERROR("X25519 key derivation failed");
        return -1;
    }

    derive_session_key(ecdh_eph, ecdh_sc_es, ecdh_ec_ss,
                       client_eph_pub, eph_pub,
                       client_static_pub, static_pub,
                       session_key);
    return 0;
}
