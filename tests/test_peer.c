/* Unit tests for the static session-table/routing/CIDR logic in src/peer.c.
 *
 * peer.c has no header of its own — everything interesting is `static` and
 * lives inside one translation unit together with main(). Rather than
 * carving out a separate library (which would ripple through the Makefile
 * and the single-binary packaging), we #include the .c file directly so
 * these tests share the same translation unit and can see its statics,
 * exactly like a "unity build" test. main() is renamed out of the way so it
 * doesn't collide with this file's own main().
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "rcunit.h"

#define main peer_binary_main_unused
#include "../src/peer.c"
#undef main

#define add_test(fn) rcu_add_test_func(NULL, fn, NULL, NULL, #fn)

/* Resets all module-global state that tests mutate, so each test starts
 * from a clean slate regardless of run order. */
static void reset_state(void) {
    memset(sessions, 0, sizeof(sessions));
    session_slots = 0;
    memset(peer_configs, 0, sizeof(peer_configs));
    peer_config_count = 0;
    memset(pending_hs, 0, sizeof(pending_hs));
    cfg_prev_key_grace = PREV_KEY_GRACE_SECS;
    cfg_rekey_after = REKEY_AFTER_SECS;
}

static struct sockaddr_in make_addr(const char *ip, int port) {
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, ip, &a.sin_addr);
    return a;
}

static void fill(unsigned char *buf, int len, unsigned char v) {
    memset(buf, v, len);
}

/* --- parse_cidr ------------------------------------------------------ */

RCU_TEST(test_parse_cidr_basic) {
    ip_prefix_t p;
    RCU_ASSERT_EQUAL(0, parse_cidr("10.9.0.0/24", &p));
    RCU_ASSERT_EQUAL(24, p.prefix_len);
    RCU_ASSERT_EQUAL(0x0A090000u, p.network);
    RCU_ASSERT_EQUAL(0xFFFFFF00u, p.mask);
}

RCU_TEST(test_parse_cidr_no_prefix_defaults_to_32) {
    ip_prefix_t p;
    RCU_ASSERT_EQUAL(0, parse_cidr("10.9.0.5", &p));
    RCU_ASSERT_EQUAL(32, p.prefix_len);
    RCU_ASSERT_EQUAL(0xFFFFFFFFu, p.mask);
    RCU_ASSERT_EQUAL(0x0A090005u, p.network);
}

RCU_TEST(test_parse_cidr_zero_prefix) {
    ip_prefix_t p;
    RCU_ASSERT_EQUAL(0, parse_cidr("0.0.0.0/0", &p));
    RCU_ASSERT_EQUAL(0, p.prefix_len);
    RCU_ASSERT_EQUAL(0u, p.mask);
    RCU_ASSERT_EQUAL(0u, p.network);
}

RCU_TEST(test_parse_cidr_masks_host_bits) {
    ip_prefix_t p;
    /* .5 is outside the /24 network boundary — network must be truncated */
    RCU_ASSERT_EQUAL(0, parse_cidr("10.9.0.5/24", &p));
    RCU_ASSERT_EQUAL(0x0A090000u, p.network);
}

RCU_TEST(test_parse_cidr_invalid_address_rejected) {
    ip_prefix_t p;
    RCU_ASSERT_EQUAL(-1, parse_cidr("not-an-ip/24", &p));
}

RCU_TEST(test_parse_cidr_prefix_too_large_rejected) {
    ip_prefix_t p;
    RCU_ASSERT_EQUAL(-1, parse_cidr("10.9.0.0/33", &p));
}

RCU_TEST(test_parse_cidr_negative_prefix_rejected) {
    ip_prefix_t p;
    RCU_ASSERT_EQUAL(-1, parse_cidr("10.9.0.0/-1", &p));
}

/* --- check_allowed_src ------------------------------------------------ */

RCU_TEST(test_check_allowed_src_no_routes_allows_anything) {
    peer_session_t s = {0};
    s.route_count = 0;
    RCU_ASSERT_TRUE(check_allowed_src(&s, 0x0A090005u));
}

RCU_TEST(test_check_allowed_src_matching_route_allowed) {
    peer_session_t s = {0};
    parse_cidr("10.9.0.0/24", &s.routes[0]);
    s.route_count = 1;
    RCU_ASSERT_TRUE(check_allowed_src(&s, 0x0A090005u)); /* 10.9.0.5 */
}

RCU_TEST(test_check_allowed_src_non_matching_route_rejected) {
    peer_session_t s = {0};
    parse_cidr("10.9.0.0/24", &s.routes[0]);
    s.route_count = 1;
    RCU_ASSERT_FALSE(check_allowed_src(&s, 0x0A0A0005u)); /* 10.10.0.5 */
}

RCU_TEST(test_check_allowed_src_checks_all_configured_routes) {
    peer_session_t s = {0};
    parse_cidr("10.9.0.0/24", &s.routes[0]);
    parse_cidr("192.168.1.0/24", &s.routes[1]);
    s.route_count = 2;
    RCU_ASSERT_TRUE(check_allowed_src(&s, 0xC0A80105u)); /* 192.168.1.5 */
}

/* --- route_lookup (longest-prefix match) ------------------------------ */

RCU_TEST(test_route_lookup_picks_longest_prefix) {
    reset_state();
    session_slots = 2;
    sessions[0].active = 1;
    parse_cidr("10.9.0.0/16", &sessions[0].routes[0]);
    sessions[0].route_count = 1;

    sessions[1].active = 1;
    parse_cidr("10.9.0.0/24", &sessions[1].routes[0]);
    sessions[1].route_count = 1;

    peer_session_t *r = route_lookup(0x0A090005u); /* 10.9.0.5 */
    RCU_ASSERT_EQUAL_PTRS(&sessions[1], r);
}

RCU_TEST(test_route_lookup_ignores_inactive_sessions) {
    reset_state();
    session_slots = 1;
    sessions[0].active = 0;
    parse_cidr("10.9.0.0/24", &sessions[0].routes[0]);
    sessions[0].route_count = 1;

    RCU_ASSERT_NULL(route_lookup(0x0A090005u));
}

RCU_TEST(test_route_lookup_no_match_returns_null) {
    reset_state();
    session_slots = 1;
    sessions[0].active = 1;
    parse_cidr("192.168.1.0/24", &sessions[0].routes[0]);
    sessions[0].route_count = 1;

    RCU_ASSERT_NULL(route_lookup(0x0A090005u));
}

/* --- find_session_by_addr / find_session_by_pub ----------------------- */

RCU_TEST(test_find_session_by_addr_match) {
    reset_state();
    session_slots = 1;
    sessions[0].active = 1;
    sessions[0].addr = make_addr("1.2.3.4", 5040);

    struct sockaddr_in q = make_addr("1.2.3.4", 5040);
    RCU_ASSERT_EQUAL_PTRS(&sessions[0], find_session_by_addr(&q));
}

RCU_TEST(test_find_session_by_addr_port_mismatch_not_found) {
    reset_state();
    session_slots = 1;
    sessions[0].active = 1;
    sessions[0].addr = make_addr("1.2.3.4", 5040);

    struct sockaddr_in q = make_addr("1.2.3.4", 9999);
    RCU_ASSERT_NULL(find_session_by_addr(&q));
}

RCU_TEST(test_find_session_by_addr_skips_inactive) {
    reset_state();
    session_slots = 1;
    sessions[0].active = 0;
    sessions[0].addr = make_addr("1.2.3.4", 5040);

    struct sockaddr_in q = make_addr("1.2.3.4", 5040);
    RCU_ASSERT_NULL(find_session_by_addr(&q));
}

RCU_TEST(test_find_session_by_pub_match) {
    reset_state();
    session_slots = 1;
    sessions[0].active = 1;
    fill(sessions[0].static_pub, DH_PUBKEY_LEN, 0xAB);

    unsigned char pub[DH_PUBKEY_LEN];
    fill(pub, DH_PUBKEY_LEN, 0xAB);
    RCU_ASSERT_EQUAL_PTRS(&sessions[0], find_session_by_pub(pub));
}

RCU_TEST(test_find_session_by_pub_no_match) {
    reset_state();
    session_slots = 1;
    sessions[0].active = 1;
    fill(sessions[0].static_pub, DH_PUBKEY_LEN, 0xAB);

    unsigned char pub[DH_PUBKEY_LEN];
    fill(pub, DH_PUBKEY_LEN, 0xCD);
    RCU_ASSERT_NULL(find_session_by_pub(pub));
}

/* --- find_peer_config --------------------------------------------------- */

RCU_TEST(test_find_peer_config_match) {
    reset_state();
    peer_config_count = 1;
    fill(peer_configs[0].pub, DH_PUBKEY_LEN, 0x11);

    unsigned char pub[DH_PUBKEY_LEN];
    fill(pub, DH_PUBKEY_LEN, 0x11);
    RCU_ASSERT_EQUAL_PTRS(&peer_configs[0], find_peer_config(pub));
}

RCU_TEST(test_find_peer_config_no_match) {
    reset_state();
    peer_config_count = 1;
    fill(peer_configs[0].pub, DH_PUBKEY_LEN, 0x11);

    unsigned char pub[DH_PUBKEY_LEN];
    fill(pub, DH_PUBKEY_LEN, 0x22);
    RCU_ASSERT_NULL(find_peer_config(pub));
}

/* --- alloc_session ------------------------------------------------------ */

RCU_TEST(test_alloc_session_reuses_slot_by_pubkey) {
    reset_state();
    session_slots = 1;
    sessions[0].active = 1;
    fill(sessions[0].static_pub, DH_PUBKEY_LEN, 0xAA);

    unsigned char pub[DH_PUBKEY_LEN];
    fill(pub, DH_PUBKEY_LEN, 0xAA);
    struct sockaddr_in addr = make_addr("5.6.7.8", 5040);

    peer_session_t *s = alloc_session(pub, &addr);
    RCU_ASSERT_EQUAL_PTRS(&sessions[0], s);
    RCU_ASSERT_EQUAL(1, session_slots); /* no new slot created */
}

RCU_TEST(test_alloc_session_reuses_slot_by_addr_when_pub_unknown) {
    reset_state();
    session_slots = 1;
    sessions[0].active = 1;
    fill(sessions[0].static_pub, DH_PUBKEY_LEN, 0xAA);
    sessions[0].addr = make_addr("5.6.7.8", 5040);

    unsigned char new_pub[DH_PUBKEY_LEN];
    fill(new_pub, DH_PUBKEY_LEN, 0xBB); /* different key, e.g. peer restarted */
    struct sockaddr_in addr = make_addr("5.6.7.8", 5040);

    peer_session_t *s = alloc_session(new_pub, &addr);
    RCU_ASSERT_EQUAL_PTRS(&sessions[0], s);
}

RCU_TEST(test_alloc_session_reuses_free_slot_before_growing) {
    reset_state();
    session_slots = 2;
    sessions[0].active = 0; /* freed by a prior expiry */
    sessions[1].active = 1;
    fill(sessions[1].static_pub, DH_PUBKEY_LEN, 0xAA);
    sessions[1].addr = make_addr("9.9.9.9", 1);

    unsigned char pub[DH_PUBKEY_LEN];
    fill(pub, DH_PUBKEY_LEN, 0xCC);
    struct sockaddr_in addr = make_addr("1.1.1.1", 5040);

    peer_session_t *s = alloc_session(pub, &addr);
    RCU_ASSERT_EQUAL_PTRS(&sessions[0], s);
    RCU_ASSERT_EQUAL(2, session_slots); /* did not grow */
}

RCU_TEST(test_alloc_session_grows_table_when_no_free_slot) {
    reset_state();
    session_slots = 1;
    sessions[0].active = 1;
    fill(sessions[0].static_pub, DH_PUBKEY_LEN, 0xAA);
    sessions[0].addr = make_addr("9.9.9.9", 1);

    unsigned char pub[DH_PUBKEY_LEN];
    fill(pub, DH_PUBKEY_LEN, 0xCC);
    struct sockaddr_in addr = make_addr("1.1.1.1", 5040);

    peer_session_t *s = alloc_session(pub, &addr);
    RCU_ASSERT_EQUAL_PTRS(&sessions[1], s);
    RCU_ASSERT_EQUAL(2, session_slots);
}

RCU_TEST(test_alloc_session_table_full_returns_null) {
    reset_state();
    session_slots = MAX_PEERS;
    for (int i = 0; i < MAX_PEERS; i++) {
        sessions[i].active = 1;
        fill(sessions[i].static_pub, DH_PUBKEY_LEN, (unsigned char)i);
        sessions[i].addr = make_addr("9.9.9.9", (int)(1000 + i));
    }

    unsigned char pub[DH_PUBKEY_LEN];
    fill(pub, DH_PUBKEY_LEN, 0xFF);
    struct sockaddr_in addr = make_addr("1.1.1.1", 5040);

    RCU_ASSERT_NULL(alloc_session(pub, &addr));
}

/* --- session_init -------------------------------------------------------- */

RCU_TEST(test_session_init_new_session_has_clean_state) {
    reset_state();
    peer_session_t s;
    memset(&s, 0, sizeof(s));
    pthread_mutex_init(&s.hot_lock, NULL);

    unsigned char pub[DH_PUBKEY_LEN], key[CRYPTO_KEY_LEN];
    fill(pub, DH_PUBKEY_LEN, 0x11);
    fill(key, CRYPTO_KEY_LEN, 0x22);
    struct sockaddr_in addr = make_addr("10.0.0.1", 5040);

    peer_config_t cfg = {0};
    parse_cidr("10.9.0.0/24", &cfg.routes[0]);
    cfg.route_count = 1;

    session_init(&s, &addr, pub, key, &cfg, 1 /* outbound */);

    RCU_ASSERT_TRUE(s.active);
    RCU_ASSERT_FALSE(s.prev_key_active);
    RCU_ASSERT_EQUAL(0, (int)s.send_seq);
    RCU_ASSERT_EQUAL(0, (int)s.recv_seq_highest);
    RCU_ASSERT_FALSE(s.rekeying);
    RCU_ASSERT_TRUE(s.is_outbound);
    RCU_ASSERT_EQUAL(1, s.route_count);
    RCU_ASSERT_SAME_BYTE_ARRAY(pub, s.static_pub, DH_PUBKEY_LEN);
    RCU_ASSERT_SAME_BYTE_ARRAY(key, s.session_key, CRYPTO_KEY_LEN);

    pthread_mutex_destroy(&s.hot_lock);
}

RCU_TEST(test_session_init_rekey_preserves_previous_key) {
    reset_state();
    peer_session_t s;
    memset(&s, 0, sizeof(s));
    pthread_mutex_init(&s.hot_lock, NULL);

    unsigned char pub[DH_PUBKEY_LEN], key1[CRYPTO_KEY_LEN], key2[CRYPTO_KEY_LEN];
    fill(pub, DH_PUBKEY_LEN, 0x11);
    fill(key1, CRYPTO_KEY_LEN, 0xAA);
    fill(key2, CRYPTO_KEY_LEN, 0xBB);
    struct sockaddr_in addr = make_addr("10.0.0.1", 5040);

    session_init(&s, &addr, pub, key1, NULL, 0);
    s.send_seq = 42; /* simulate traffic before rekey */

    session_init(&s, &addr, pub, key2, NULL, 0);

    RCU_ASSERT_TRUE(s.prev_key_active);
    RCU_ASSERT_SAME_BYTE_ARRAY(key1, s.prev_session_key, CRYPTO_KEY_LEN);
    RCU_ASSERT_SAME_BYTE_ARRAY(key2, s.session_key, CRYPTO_KEY_LEN);
    RCU_ASSERT_EQUAL(0, (int)s.send_seq); /* sequence counters reset on rekey */

    pthread_mutex_destroy(&s.hot_lock);
}

RCU_TEST(test_session_init_no_cfg_clears_routes) {
    reset_state();
    peer_session_t s;
    memset(&s, 0, sizeof(s));
    pthread_mutex_init(&s.hot_lock, NULL);

    unsigned char pub[DH_PUBKEY_LEN], key[CRYPTO_KEY_LEN];
    fill(pub, DH_PUBKEY_LEN, 0x11);
    fill(key, CRYPTO_KEY_LEN, 0x22);
    struct sockaddr_in addr = make_addr("10.0.0.1", 5040);

    session_init(&s, &addr, pub, key, NULL, 0);
    RCU_ASSERT_EQUAL(0, s.route_count);

    pthread_mutex_destroy(&s.hot_lock);
}

/* --- main ----------------------------------------------------------------- */

int main(void) {
    add_test(test_parse_cidr_basic);
    add_test(test_parse_cidr_no_prefix_defaults_to_32);
    add_test(test_parse_cidr_zero_prefix);
    add_test(test_parse_cidr_masks_host_bits);
    add_test(test_parse_cidr_invalid_address_rejected);
    add_test(test_parse_cidr_prefix_too_large_rejected);
    add_test(test_parse_cidr_negative_prefix_rejected);

    add_test(test_check_allowed_src_no_routes_allows_anything);
    add_test(test_check_allowed_src_matching_route_allowed);
    add_test(test_check_allowed_src_non_matching_route_rejected);
    add_test(test_check_allowed_src_checks_all_configured_routes);

    add_test(test_route_lookup_picks_longest_prefix);
    add_test(test_route_lookup_ignores_inactive_sessions);
    add_test(test_route_lookup_no_match_returns_null);

    add_test(test_find_session_by_addr_match);
    add_test(test_find_session_by_addr_port_mismatch_not_found);
    add_test(test_find_session_by_addr_skips_inactive);
    add_test(test_find_session_by_pub_match);
    add_test(test_find_session_by_pub_no_match);

    add_test(test_find_peer_config_match);
    add_test(test_find_peer_config_no_match);

    add_test(test_alloc_session_reuses_slot_by_pubkey);
    add_test(test_alloc_session_reuses_slot_by_addr_when_pub_unknown);
    add_test(test_alloc_session_reuses_free_slot_before_growing);
    add_test(test_alloc_session_grows_table_when_no_free_slot);
    add_test(test_alloc_session_table_full_returns_null);

    add_test(test_session_init_new_session_has_clean_state);
    add_test(test_session_init_rekey_preserves_previous_key);
    add_test(test_session_init_no_cfg_clears_routes);

    return rcu_run_tests();
}
