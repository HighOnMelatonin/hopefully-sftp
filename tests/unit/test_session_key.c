/**
 * tests/unit/test_session_key.c
 *
 * Unit tests for Session Key generation and Symmetric Encryption.
 */

#include "unity.h"
#include "libs/common.h"
#include <string.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

void setUp(void) {}
void tearDown(void) {}

static EVP_PKEY *load_pubkey_from_cert(const char *cert_path)
{
    FILE *fp = fopen(cert_path, "rb");
    if (!fp) return NULL;
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!cert) return NULL;
    EVP_PKEY *pkey = X509_get_pubkey(cert); /*[cite: 1, 2] */
    X509_free(cert);
    return pkey;
}

static void test_symmetric_encryption_roundtrip(void)
{
    unsigned char session_key[32];
    generate_session_key(session_key); /* Generate random session key[cite: 2] */
    
    const unsigned char original_data[] = "Super secret file chunk!";
    size_t data_len = strlen((char *)original_data);
    
    size_t enc_len = 0;
    unsigned char *encrypted = session_encrypt(session_key, original_data, data_len, &enc_len); /* Encrypt[cite: 2] */
    TEST_ASSERT_NOT_NULL(encrypted);
    
    size_t dec_len = 0;
    unsigned char *decrypted = session_decrypt(session_key, encrypted, enc_len, &dec_len); /* Decrypt[cite: 4] */
    TEST_ASSERT_NOT_NULL(decrypted);
    
    TEST_ASSERT_EQUAL_INT((int)data_len, (int)dec_len);
    TEST_ASSERT_EQUAL_MEMORY(original_data, decrypted, data_len);
    
    free(encrypted);
    free(decrypted);
    OPENSSL_cleanse(session_key, 32); /* Clean up key[cite: 2, 4] */
}

static void test_rsa_wrapped_session_key(void)
{
    EVP_PKEY *priv_key = load_private_key("auth/private_key.pem"); /*[cite: 3, 4] */
    EVP_PKEY *pub_key = load_pubkey_from_cert("auth/server_signed.crt");
    
    TEST_ASSERT_NOT_NULL_MESSAGE(priv_key, "Private key failed to load");
    TEST_ASSERT_NOT_NULL_MESSAGE(pub_key, "Public key failed to load");

    unsigned char original_key[32];
    generate_session_key(original_key);
    
    size_t enc_len = 0;
    unsigned char *enc_key = rsa_encrypt_block(pub_key, original_key, 32, &enc_len, 1); /* Encrypt key[cite: 2] */
    TEST_ASSERT_NOT_NULL(enc_key);
    
    size_t dec_len = 0;
    unsigned char *decrypted_key = rsa_decrypt_block(priv_key, enc_key, enc_len, &dec_len, 1); /* Decrypt key[cite: 4] */
    TEST_ASSERT_NOT_NULL(decrypted_key);
    
    TEST_ASSERT_EQUAL_INT(32, (int)dec_len);
    TEST_ASSERT_EQUAL_MEMORY(original_key, decrypted_key, 32);
    
    free(enc_key);
    free(decrypted_key);
    EVP_PKEY_free(pub_key);
    EVP_PKEY_free(priv_key);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_symmetric_encryption_roundtrip);
    RUN_TEST(test_rsa_wrapped_session_key);
    return UNITY_END();
}