#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "rcunit.h"

#include "../src/common.h"

/* --- bytes_to_hex -------------------------------------------------------- */

RCU_TEST(test_bytes_to_hex_zeros) {
    unsigned char bytes[4] = {0, 0, 0, 0};
    char hex[9];
    bytes_to_hex(bytes, 4, hex);
    RCU_ASSERT_EQUAL_STRING("00000000", hex);
}

RCU_TEST(test_bytes_to_hex_all_ff) {
    unsigned char bytes[4] = {0xff, 0xff, 0xff, 0xff};
    char hex[9];
    bytes_to_hex(bytes, 4, hex);
    RCU_ASSERT_EQUAL_STRING("ffffffff", hex);
}

RCU_TEST(test_bytes_to_hex_known_value) {
    unsigned char bytes[] = {0xde, 0xad, 0xbe, 0xef};
    char hex[9];
    bytes_to_hex(bytes, 4, hex);
    RCU_ASSERT_EQUAL_STRING("deadbeef", hex);
}

RCU_TEST(test_bytes_to_hex_single_byte) {
    unsigned char bytes[] = {0x0a};
    char hex[3];
    bytes_to_hex(bytes, 1, hex);
    RCU_ASSERT_EQUAL_STRING("0a", hex);
}

/* --- hex_to_bytes -------------------------------------------------------- */

RCU_TEST(test_hex_to_bytes_known_value) {
    unsigned char bytes[4];
    int rc = hex_to_bytes("deadbeef", bytes, 4);
    RCU_ASSERT_EQUAL(0, rc);
    RCU_ASSERT_EQUAL(0xde, bytes[0]);
    RCU_ASSERT_EQUAL(0xad, bytes[1]);
    RCU_ASSERT_EQUAL(0xbe, bytes[2]);
    RCU_ASSERT_EQUAL(0xef, bytes[3]);
}

RCU_TEST(test_hex_to_bytes_wrong_length) {
    unsigned char bytes[4];
    int rc = hex_to_bytes("dead", bytes, 4);
    RCU_ASSERT_EQUAL(-1, rc);
}

RCU_TEST(test_hex_to_bytes_uppercase) {
    unsigned char bytes[4];
    int rc = hex_to_bytes("DEADBEEF", bytes, 4);
    RCU_ASSERT_EQUAL(0, rc);
    RCU_ASSERT_EQUAL(0xde, bytes[0]);
    RCU_ASSERT_EQUAL(0xad, bytes[1]);
    RCU_ASSERT_EQUAL(0xbe, bytes[2]);
    RCU_ASSERT_EQUAL(0xef, bytes[3]);
}

RCU_TEST(test_hex_to_bytes_roundtrip) {
    unsigned char original[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    char hex[17];
    unsigned char recovered[8];
    bytes_to_hex(original, 8, hex);
    int rc = hex_to_bytes(hex, recovered, 8);
    RCU_ASSERT_EQUAL(0, rc);
    RCU_ASSERT_SAME_BYTE_ARRAY(original, recovered, 8);
}

/* --- derive_key ---------------------------------------------------------- */

RCU_TEST(test_derive_key_is_deterministic) {
    unsigned char key1[CRYPTO_KEY_LEN], key2[CRYPTO_KEY_LEN];
    derive_key("test-psk", key1);
    derive_key("test-psk", key2);
    RCU_ASSERT_SAME_BYTE_ARRAY(key1, key2, CRYPTO_KEY_LEN);
}

RCU_TEST(test_derive_key_different_psks_produce_different_keys) {
    unsigned char key1[CRYPTO_KEY_LEN], key2[CRYPTO_KEY_LEN];
    derive_key("psk-alpha", key1);
    derive_key("psk-beta", key2);
    RCU_ASSERT_NOT_SAME_BYTE_ARRAY(key1, key2, CRYPTO_KEY_LEN);
}

RCU_TEST(test_derive_key_output_is_not_zero) {
    unsigned char key[CRYPTO_KEY_LEN];
    unsigned char zeros[CRYPTO_KEY_LEN];
    memset(zeros, 0, CRYPTO_KEY_LEN);
    derive_key("any-psk", key);
    RCU_ASSERT_NOT_SAME_BYTE_ARRAY(key, zeros, CRYPTO_KEY_LEN);
}

/* --- check_replay -------------------------------------------------------- */

RCU_TEST(test_replay_sequential_packets_accepted) {
    uint64_t highest = 0;
    uint64_t window[REPLAY_WINDOW_WORDS];
    memset(window, 0, sizeof(window));
    RCU_ASSERT_EQUAL(0, check_replay(1, &highest, window));
    RCU_ASSERT_EQUAL(0, check_replay(2, &highest, window));
    RCU_ASSERT_EQUAL(0, check_replay(3, &highest, window));
    RCU_ASSERT_EQUAL(3, (int)highest);
}

RCU_TEST(test_replay_duplicate_rejected) {
    uint64_t highest = 0;
    uint64_t window[REPLAY_WINDOW_WORDS];
    memset(window, 0, sizeof(window));
    RCU_ASSERT_EQUAL(0, check_replay(5, &highest, window));
    RCU_ASSERT_EQUAL(-1, check_replay(5, &highest, window));
}

RCU_TEST(test_replay_out_of_order_within_window_accepted) {
    uint64_t highest = 0;
    uint64_t window[REPLAY_WINDOW_WORDS];
    memset(window, 0, sizeof(window));
    RCU_ASSERT_EQUAL(0, check_replay(100, &highest, window));
    RCU_ASSERT_EQUAL(0, check_replay(50, &highest, window));
    RCU_ASSERT_EQUAL(-1, check_replay(50, &highest, window));
}

RCU_TEST(test_replay_too_old_rejected) {
    uint64_t highest = 0;
    uint64_t window[REPLAY_WINDOW_WORDS];
    memset(window, 0, sizeof(window));
    /* advance well past the window (window is 2048 wide) */
    check_replay(3000, &highest, window);
    RCU_ASSERT_EQUAL(-1, check_replay(1, &highest, window));
}

RCU_TEST(test_replay_boundary_just_inside_window) {
    uint64_t highest = 0;
    uint64_t window[REPLAY_WINDOW_WORDS];
    memset(window, 0, sizeof(window));
    check_replay(2048, &highest, window);
    /* seq 1: diff = 2047, which is < 2048, so inside window */
    RCU_ASSERT_EQUAL(0, check_replay(1, &highest, window));
}

RCU_TEST(test_replay_boundary_just_outside_window) {
    uint64_t highest = 0;
    uint64_t window[REPLAY_WINDOW_WORDS];
    memset(window, 0, sizeof(window));
    check_replay(2048, &highest, window);
    /* seq 0: diff = 2048, which equals window size, so too old */
    RCU_ASSERT_EQUAL(-1, check_replay(0, &highest, window));
}

RCU_TEST(test_replay_large_gap_resets_window) {
    uint64_t highest = 0;
    uint64_t window[REPLAY_WINDOW_WORDS];
    memset(window, 0, sizeof(window));
    check_replay(1, &highest, window);
    /* jump far ahead — old entries should be gone */
    RCU_ASSERT_EQUAL(0, check_replay(100000, &highest, window));
    RCU_ASSERT_EQUAL(100000, (int)highest);
    /* seq 1 is now far outside the window */
    RCU_ASSERT_EQUAL(-1, check_replay(1, &highest, window));
}

/* --- encrypt_packet / decrypt_packet ------------------------------------- */

RCU_TEST(test_encrypt_decrypt_roundtrip) {
    unsigned char key[CRYPTO_KEY_LEN];
    derive_key("test-session-key", key);

    EVP_CIPHER_CTX *enc_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *dec_ctx = EVP_CIPHER_CTX_new();
    RCU_ASSERT_NOT_NULL(enc_ctx);
    RCU_ASSERT_NOT_NULL(dec_ctx);

    const char *plaintext = "Hello, lanecove!";
    int plain_len = (int)strlen(plaintext);
    unsigned char encrypted[512];
    int enc_len = 0;

    int rc = encrypt_packet(enc_ctx, key, (const unsigned char *)plaintext, plain_len,
                            encrypted, &enc_len);
    RCU_ASSERT_EQUAL(0, rc);
    RCU_ASSERT_TRUE(enc_len == plain_len + CRYPTO_OVERHEAD);

    unsigned char decrypted[512];
    int dec_len = 0;
    rc = decrypt_packet(dec_ctx, key, encrypted, enc_len, decrypted, &dec_len);
    RCU_ASSERT_EQUAL(0, rc);
    RCU_ASSERT_EQUAL(plain_len, dec_len);
    RCU_ASSERT_SAME_BYTE_ARRAY(plaintext, decrypted, plain_len);

    EVP_CIPHER_CTX_free(enc_ctx);
    EVP_CIPHER_CTX_free(dec_ctx);
}

RCU_TEST(test_encrypt_wrong_key_fails_decrypt) {
    unsigned char key_a[CRYPTO_KEY_LEN], key_b[CRYPTO_KEY_LEN];
    derive_key("key-a", key_a);
    derive_key("key-b", key_b);

    EVP_CIPHER_CTX *enc_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *dec_ctx = EVP_CIPHER_CTX_new();

    const char *plaintext = "secret message";
    unsigned char encrypted[512];
    int enc_len = 0;
    encrypt_packet(enc_ctx, key_a, (const unsigned char *)plaintext,
                   (int)strlen(plaintext), encrypted, &enc_len);

    unsigned char decrypted[512];
    int dec_len = 0;
    int rc = decrypt_packet(dec_ctx, key_b, encrypted, enc_len, decrypted, &dec_len);
    RCU_ASSERT_EQUAL(-1, rc);

    EVP_CIPHER_CTX_free(enc_ctx);
    EVP_CIPHER_CTX_free(dec_ctx);
}

RCU_TEST(test_decrypt_tampered_ciphertext_fails) {
    unsigned char key[CRYPTO_KEY_LEN];
    derive_key("test-key", key);

    EVP_CIPHER_CTX *enc_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *dec_ctx = EVP_CIPHER_CTX_new();

    const char *plaintext = "tamper me";
    unsigned char encrypted[512];
    int enc_len = 0;
    encrypt_packet(enc_ctx, key, (const unsigned char *)plaintext,
                   (int)strlen(plaintext), encrypted, &enc_len);

    /* flip a byte in the ciphertext (after the IV) */
    encrypted[CRYPTO_IV_LEN] ^= 0xff;

    unsigned char decrypted[512];
    int dec_len = 0;
    int rc = decrypt_packet(dec_ctx, key, encrypted, enc_len, decrypted, &dec_len);
    RCU_ASSERT_EQUAL(-1, rc);

    EVP_CIPHER_CTX_free(enc_ctx);
    EVP_CIPHER_CTX_free(dec_ctx);
}

RCU_TEST(test_decrypt_truncated_input_fails) {
    unsigned char key[CRYPTO_KEY_LEN];
    derive_key("test-key", key);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char buf[CRYPTO_OVERHEAD - 1];
    memset(buf, 0, sizeof(buf));
    int out_len = 0;
    int rc = decrypt_packet(ctx, key, buf, (int)sizeof(buf), buf, &out_len);
    RCU_ASSERT_EQUAL(-1, rc);

    EVP_CIPHER_CTX_free(ctx);
}

RCU_TEST(test_encrypt_produces_different_ciphertext_each_time) {
    unsigned char key[CRYPTO_KEY_LEN];
    derive_key("test-key", key);

    EVP_CIPHER_CTX *ctx1 = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *ctx2 = EVP_CIPHER_CTX_new();

    const char *plaintext = "same plaintext";
    int plain_len = (int)strlen(plaintext);
    unsigned char enc1[512], enc2[512];
    int len1 = 0, len2 = 0;

    encrypt_packet(ctx1, key, (const unsigned char *)plaintext, plain_len, enc1, &len1);
    encrypt_packet(ctx2, key, (const unsigned char *)plaintext, plain_len, enc2, &len2);

    RCU_ASSERT_EQUAL(len1, len2);
    /* random IV means ciphertexts differ (with overwhelming probability) */
    RCU_ASSERT_NOT_SAME_BYTE_ARRAY(enc1, enc2, len1);

    EVP_CIPHER_CTX_free(ctx1);
    EVP_CIPHER_CTX_free(ctx2);
}

/* --- main ---------------------------------------------------------------- */

int main(int argc, char *argv[]) {
    /* bytes_to_hex */
    rcu_add_test(test_bytes_to_hex_zeros);
    rcu_add_test(test_bytes_to_hex_all_ff);
    rcu_add_test(test_bytes_to_hex_known_value);
    rcu_add_test(test_bytes_to_hex_single_byte);

    /* hex_to_bytes */
    rcu_add_test(test_hex_to_bytes_known_value);
    rcu_add_test(test_hex_to_bytes_wrong_length);
    rcu_add_test(test_hex_to_bytes_uppercase);
    rcu_add_test(test_hex_to_bytes_roundtrip);

    /* derive_key */
    rcu_add_test(test_derive_key_is_deterministic);
    rcu_add_test(test_derive_key_different_psks_produce_different_keys);
    rcu_add_test(test_derive_key_output_is_not_zero);

    /* check_replay */
    rcu_add_test(test_replay_sequential_packets_accepted);
    rcu_add_test(test_replay_duplicate_rejected);
    rcu_add_test(test_replay_out_of_order_within_window_accepted);
    rcu_add_test(test_replay_too_old_rejected);
    rcu_add_test(test_replay_boundary_just_inside_window);
    rcu_add_test(test_replay_boundary_just_outside_window);
    rcu_add_test(test_replay_large_gap_resets_window);

    /* encrypt_packet / decrypt_packet */
    rcu_add_test(test_encrypt_decrypt_roundtrip);
    rcu_add_test(test_encrypt_wrong_key_fails_decrypt);
    rcu_add_test(test_decrypt_tampered_ciphertext_fails);
    rcu_add_test(test_decrypt_truncated_input_fails);
    rcu_add_test(test_encrypt_produces_different_ciphertext_each_time);

    return rcu_run_tests();
}
