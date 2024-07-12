/*
 * @Author: Weili
 * @Date: 2023-12-13
 * @LastEditTime: 2024-01-07
 * @FilePath: /sgxbraft_006/src/attest_utils/crypto.h
 * @Description: Revised based on crypto.h used in the attestation sample in oe sdk, but we use openssl instead of mbedtls
 */

#ifndef OE_SAMPLES_ATTESTATION_ENC_OPENSSL_CRYPTO_H
#define OE_SAMPLES_ATTESTATION_ENC_OPENSSL_CRYPTO_H

#include <openenclave/enclave.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/x509_vfy.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include "log.h"

#define PUBLIC_KEY_SIZE 512


class Crypto
{
  private:
    RSA* m_private_key = nullptr;
    uint8_t m_public_key[512];
    bool m_initialized;

    // Public key of another enclave, i.e., the KV enclave
    uint8_t m_other_enclave_pubkey[PUBLIC_KEY_SIZE];

  public:
    Crypto();
    ~Crypto();

    /**
     * Get this enclave's own public key
     */
    void retrieve_public_key(uint8_t pem_public_key[512]);

    /**
     * encrypts the given data using the given public key.
     * Used to encrypt data using the public key of another enclave.
     */
    bool encrypt(
        const uint8_t* pem_public_key,
        const uint8_t* data,
        size_t size,
        uint8_t* encrypted_data,
        size_t* encrypted_data_size);
    
    bool encrypt2(
        const uint8_t* pem_public_key,
        const uint8_t* data,
        size_t size,
        uint8_t* encrypted_data,
        size_t* encrypted_data_size);

    /**
     * decrypt decrypts the given data using current enclave's private key.
     * Used to receive encrypted data from another enclave.
     */
    bool decrypt(
        const uint8_t* encrypted_data,
        size_t encrypted_data_size,
        uint8_t* data,
        size_t* data_size);

    bool decrypt2(
        const uint8_t* encrypted_data,
        size_t encrypted_data_size,
        uint8_t* data,
        size_t* data_size);

    // Public key of another enclave.
    uint8_t* get_the_other_enclave_public_key()
    {
        return m_other_enclave_pubkey;
    }

    /**
     * Compute the sha256 hash of given data.
     */
    int sha256_fn(const uint8_t* data, size_t data_size, uint8_t sha256[32]);

    void test_crypto();

    // The maximum bytes of data that can be encrypted in one chunk
    int chunk_plaintext_limit;
    // How many bytes in one chunk
    int chunk_bytes;


  private:

    /**  
     * Initialize the crypto module, which will generate a key pair for the enclave
     */
    bool init_openssl(void);

    void cleanup_openssl(void);
};



#endif /* OE_SAMPLES_ATTESTATION_ENC_OPENSSL_CRYPTO_H */