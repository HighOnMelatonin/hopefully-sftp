/**
 * tests/unit/test_pss.c
 *
 * Unit tests for sign_message_pss() / verify_message_pss() in
 * source/libs/common.c. Uses the project's real key + cert pair,
 * so this also doubles as a sanity check that auth material is set up.
 */

#include "unity.h"
#include "libs/common.h"
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

void test_pss_sign_and_verify_roundtrip(void)
{
    EVP_PKEY *key = load_private_key("auth/private_key.pem");
    TEST_ASSERT_NOT_NULL(key);

    X509 *cert = load_cert_file("auth/server_signed.crt");
    TEST_ASSERT_NOT_NULL(cert);

    const unsigned char msg[] = "test nonce 12345";
    size_t sig_len = 0;
    unsigned char *sig = sign_message_pss(key, msg, sizeof(msg), &sig_len);
    TEST_ASSERT_NOT_NULL(sig);
    TEST_ASSERT_TRUE(sig_len > 0);

    TEST_ASSERT_EQUAL_INT(1, verify_message_pss(cert, sig, sig_len, msg, sizeof(msg)));

    free(sig);
    X509_free(cert);
    EVP_PKEY_free(key);
}

void test_pss_verify_rejects_tampered_signature(void)
{
    EVP_PKEY *key = load_private_key("auth/private_key.pem");
    X509 *cert = load_cert_file("auth/server_signed.crt");

    const unsigned char msg[] = "test nonce 12345";
    size_t sig_len = 0;
    unsigned char *sig = sign_message_pss(key, msg, sizeof(msg), &sig_len);
    TEST_ASSERT_NOT_NULL(sig);

    sig[0] ^= 0x01;  /* flip a bit */

    TEST_ASSERT_EQUAL_INT(0, verify_message_pss(cert, sig, sig_len, msg, sizeof(msg)));

    free(sig);
    X509_free(cert);
    EVP_PKEY_free(key);
}

void test_pss_verify_rejects_wrong_message(void)
{
    EVP_PKEY *key = load_private_key("auth/private_key.pem");
    X509 *cert = load_cert_file("auth/server_signed.crt");

    const unsigned char msg[] = "test nonce 12345";
    const unsigned char wrong[] = "different message";
    size_t sig_len = 0;
    unsigned char *sig = sign_message_pss(key, msg, sizeof(msg), &sig_len);
    TEST_ASSERT_NOT_NULL(sig);

    TEST_ASSERT_EQUAL_INT(0, verify_message_pss(cert, sig, sig_len, wrong, sizeof(wrong)));

    free(sig);
    X509_free(cert);
    EVP_PKEY_free(key);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_pss_sign_and_verify_roundtrip);
    RUN_TEST(test_pss_verify_rejects_tampered_signature);
    RUN_TEST(test_pss_verify_rejects_wrong_message);
    return UNITY_END();
}