/**
 * tests/unit/test_x509.c
 *
 * Unit tests for verify_server_cert() in source/libs/common.c.
 *
 * Fixtures (checked into tests/fixtures/, no private keys committed):
 *   tests/fixtures/server_signed.crt      - real cert, signed by our CA
 *   tests/fixtures/server_selfsigned.crt  - self-signed, must be rejected
 */

#include "unity.h"
#include "libs/common.h"

void setUp(void) {}
void tearDown(void) {}

void test_verify_server_cert_accepts_ca_signed(void)
{
    X509 *cert = load_cert_file("tests/fixtures/server_signed.crt");
    TEST_ASSERT_NOT_NULL(cert);
    TEST_ASSERT_EQUAL_INT(1, verify_server_cert(cert, "auth/cacsertificate.crt"));
    X509_free(cert);
}

void test_verify_server_cert_rejects_self_signed(void)
{
    X509 *cert = load_cert_file("tests/fixtures/server_selfsigned.crt");
    TEST_ASSERT_NOT_NULL(cert);
    TEST_ASSERT_EQUAL_INT(0, verify_server_cert(cert, "auth/cacsertificate.crt"));
    X509_free(cert);
}

void test_verify_server_cert_rejects_missing_ca_path(void)
{
    X509 *cert = load_cert_file("tests/fixtures/server_signed.crt");
    TEST_ASSERT_NOT_NULL(cert);
    TEST_ASSERT_EQUAL_INT(0, verify_server_cert(cert, "auth/does_not_exist.crt"));
    X509_free(cert);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_verify_server_cert_accepts_ca_signed);
    RUN_TEST(test_verify_server_cert_rejects_self_signed);
    RUN_TEST(test_verify_server_cert_rejects_missing_ca_path);
    return UNITY_END();
}