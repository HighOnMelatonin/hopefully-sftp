/**
 * tests/unit/test_rsa_encrypt.c
 *
 * Unit tests for RSA encryption/decryption round-trip.
 */

#include "unity.h"
#include "libs/common.h"
#include <string.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

EVP_PKEY *pub_key = NULL;
EVP_PKEY *priv_key = NULL;

/* Helper function to extract public key directly from a PEM cert file */
static EVP_PKEY *load_pubkey_from_cert(const char *cert_path)
{
    FILE *fp = fopen(cert_path, "rb");
    if (!fp) return NULL;
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!cert) return NULL;
    EVP_PKEY *pkey = X509_get_pubkey(cert); /* Extract public key[cite: 1, 2] */
    X509_free(cert);
    return pkey;
}

void setUp(void)
{
    /* Load keys before each test */
    priv_key = load_private_key("auth/private_key.pem"); /*[cite: 3, 4] */
    pub_key = load_pubkey_from_cert("auth/server_signed.crt");
}

void tearDown(void)
{
    if (pub_key) EVP_PKEY_free(pub_key);
    if (priv_key) EVP_PKEY_free(priv_key);
}

static void test_rsa_roundtrip_small_data(void)
{
    TEST_ASSERT_NOT_NULL_MESSAGE(priv_key, "Private key failed to load from auth/private_key.pem");
    TEST_ASSERT_NOT_NULL_MESSAGE(pub_key, "Public key failed to load from auth/server_signed.crt");

    const unsigned char original_data[] = "Hello RSA!";
    size_t data_len = strlen((char *)original_data);
    
    size_t enc_len = 0;
    /* Encrypt block[cite: 1] */
    unsigned char *encrypted = rsa_encrypt_block(pub_key, original_data, data_len, &enc_len, 1);
    TEST_ASSERT_NOT_NULL(encrypted);
    
    size_t dec_len = 0;
    /* Decrypt block[cite: 3] */
    unsigned char *decrypted = rsa_decrypt_block(priv_key, encrypted, enc_len, &dec_len, 1);
    TEST_ASSERT_NOT_NULL(decrypted);
    
    TEST_ASSERT_EQUAL_INT((int)data_len, (int)dec_len);
    TEST_ASSERT_EQUAL_MEMORY(original_data, decrypted, data_len);
    
    free(encrypted);
    free(decrypted);
}

static void test_rsa_roundtrip_max_block(void)
{
    TEST_ASSERT_NOT_NULL_MESSAGE(priv_key, "Private key failed to load");
    TEST_ASSERT_NOT_NULL_MESSAGE(pub_key, "Public key failed to load");

    /* Max block for OAEP with SHA-256 is typically 62 bytes[cite: 1, 3] */
    unsigned char original_data[62];
    memset(original_data, 'A', 62);
    
    size_t enc_len = 0;
    unsigned char *encrypted = rsa_encrypt_block(pub_key, original_data, 62, &enc_len, 1);
    TEST_ASSERT_NOT_NULL(encrypted);
    
    size_t dec_len = 0;
    unsigned char *decrypted = rsa_decrypt_block(priv_key, encrypted, enc_len, &dec_len, 1);
    TEST_ASSERT_NOT_NULL(decrypted);
    
    TEST_ASSERT_EQUAL_INT(62, (int)dec_len);
    TEST_ASSERT_EQUAL_MEMORY(original_data, decrypted, 62);
    
    free(encrypted);
    free(decrypted);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_rsa_roundtrip_small_data);
    RUN_TEST(test_rsa_roundtrip_max_block);
    return UNITY_END();
}