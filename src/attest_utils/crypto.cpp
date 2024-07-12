/*
 * @Author: Weili
 * @Date: 2023-12-13
 * @LastEditTime: 2024-01-07
 * @FilePath: /sgxbraft_006/src/attest_utils/crypto.cpp
 * @Description: Similar to crypto.cpp used in the attestation sample in oe sdk, but we use openssl instead of mbedtls
 */

#include "crypto.h"
#include <string.h>

Crypto::Crypto()
{
    m_initialized = init_openssl();
    chunk_plaintext_limit = RSA_size(m_private_key) - RSA_PKCS1_PADDING_SIZE;
    chunk_bytes = RSA_size(m_private_key);
}

Crypto::~Crypto()
{
    cleanup_openssl();
}

// Get this enclave's own key pair
bool Crypto::init_openssl(void) {
    bool ret = false;

    BIO* publicKeyBio = BIO_new(BIO_s_mem());
    RSA* rsa = RSA_new();
    BIGNUM* bne = BN_new();
    int bits = 2048;
    // 65537 = 0x10001L = RSA_F4
    unsigned long exponent = RSA_F4;
    BN_set_word(bne, exponent);

    // Generate RSA key pair
    if (RSA_generate_key_ex(rsa, bits, bne, nullptr) != 1) {
        // Error occurred while generating key pair
        // Add error handling code here
        goto exit;
    }

    // Store the public key in the byte array
    PEM_write_bio_RSA_PUBKEY(publicKeyBio, rsa);
    BIO_read(publicKeyBio, m_public_key, sizeof(m_public_key));

    // Store the private key
    m_private_key = rsa;

exit: 
    BIO_free(publicKeyBio);
    return ret;
}

void Crypto::cleanup_openssl(void)
{
    if (m_private_key != nullptr) {
        RSA_free(m_private_key);
    }
}

// Get the public key for this enclave.
void Crypto::retrieve_public_key(uint8_t pem_public_key[512]) {
    memcpy(pem_public_key, m_public_key, sizeof(m_public_key));
}

// Compute the sha256 hash of given data.
int Crypto::sha256_fn(const uint8_t* data, size_t data_size, uint8_t sha256[32]) {
    // Create a SHA-256 context
    SHA256_CTX sha256Context;
    if (!SHA256_Init(&sha256Context)) {
        // Failed to initialize the SHA-256 context
        return -1;
    }

    // Update the context with the input data
    if (!SHA256_Update(&sha256Context, data, data_size)) {
        // Failed to update the SHA-256 context
        return -1;
    }

    // Finalize the hash computation and obtain the hash value
    if (!SHA256_Final(sha256, &sha256Context)) {
        // Failed to finalize the SHA-256 context
        return -1;
    }
    
    return 0;
}

// encrypts the given data using the given public key. Used to encrypt data using the public key of another enclave.
bool Crypto::encrypt(const uint8_t* pem_public_key, const uint8_t* data, size_t size, uint8_t* encrypted_data, size_t* encrypted_data_size) {
    RSA* rsa = RSA_new();
    BIO* publicKeyBio = BIO_new_mem_buf(pem_public_key, -1);

    if (!PEM_read_bio_RSA_PUBKEY(publicKeyBio, &rsa, nullptr, nullptr)) {
        // Error occurred while reading the public key
        BIO_free(publicKeyBio);
        RSA_free(rsa);
        return false;
    }

    int encrypted_size = RSA_public_encrypt(size, data, encrypted_data, rsa, RSA_PKCS1_PADDING);
    if (encrypted_size == -1) {
        // Error occurred while encrypting
        // Add error handling code here
        BIO_free(publicKeyBio);
        RSA_free(rsa);
        return false;
    }

    *encrypted_data_size = static_cast<size_t>(encrypted_size);

    BIO_free(publicKeyBio);
    RSA_free(rsa);
    return true;
}

// Decrypt decrypts the given data using current enclave's private key. Used to receive encrypted data from another enclave.
bool Crypto::decrypt(const uint8_t* encrypted_data, size_t encrypted_data_size, uint8_t* data, size_t* data_size) {
    // print pub key for debugging
    // TRACE_ENCLAVE("print pub key");
    // for (int i = 0; i < 512; i++) {
    //     printf("%02x", m_public_key[i]);
    // }
    // printf("\n");

    if (m_private_key == nullptr) {
        // Private key is not available
        TRACE_ENCLAVE("Private key is not available");
        return false;
    }

    int decrypted_size = RSA_private_decrypt(encrypted_data_size, encrypted_data, data, m_private_key, RSA_PKCS1_PADDING);
    if (decrypted_size == -1) {
        // Error occurred while decrypting
        TRACE_ENCLAVE("Error occurred while decrypting");
        return false;
    }

    *data_size = static_cast<size_t>(decrypted_size);
    return true;
}

bool Crypto::encrypt2(const uint8_t* pem_public_key, const uint8_t* data, size_t size, uint8_t* encrypted_data, size_t* encrypted_data_size) {
    RSA* rsa = RSA_new();
    BIO* publicKeyBio = BIO_new_mem_buf(pem_public_key, -1);

    if (!PEM_read_bio_RSA_PUBKEY(publicKeyBio, &rsa, nullptr, nullptr)) {
        // Error occurred while reading the public key
        BIO_free(publicKeyBio);
        RSA_free(rsa);
        return false;
    }

    // Calculate the maximum chunk size using the key size and padding scheme
    int encrypted_size = 0;
    int total_encrypted_size = 0;
    int total_encrypted_plaintext_size = 0;
    int chunk_plaintext_size = 0;
    int loop_cnt = 0;
    while (total_encrypted_plaintext_size < size) {
        // printf("Enc loop#%d\n", loop_cnt++);
        chunk_plaintext_size = size - total_encrypted_plaintext_size;
        if (chunk_plaintext_size > chunk_plaintext_limit) {
            chunk_plaintext_size = chunk_plaintext_limit;
        }

        encrypted_size = RSA_public_encrypt(chunk_plaintext_size, data + total_encrypted_plaintext_size, encrypted_data + total_encrypted_size, rsa, RSA_PKCS1_PADDING);
        if (encrypted_size == -1) {
            // Error occurred while encrypting
            // Add error handling code here
            BIO_free(publicKeyBio);
            RSA_free(rsa);
            return false;
        }

        total_encrypted_plaintext_size += chunk_plaintext_size;
        total_encrypted_size += encrypted_size;
    }
    // Calculate the total encrypted size
    *encrypted_data_size = static_cast<size_t>(total_encrypted_size);
    BIO_free(publicKeyBio);
    RSA_free(rsa);
    return true;
}

// Corresponding to encrypt2
bool Crypto::decrypt2(
        const uint8_t* encrypted_data,
        size_t encrypted_data_size,
        uint8_t* data,
        size_t* data_size){
    if (m_private_key == nullptr) {
        // Private key is not available
        return false;
    }            
    int decrypted_size = 0;
    int total_decrypted_plain_text_size = 0;
    int total_decrypted_size = 0;
    int chunk_size = 0;
    int loop_cnt = 0;
    while (total_decrypted_size < encrypted_data_size) {
        // printf("Dec loop#%d\n", loop_cnt++);
        decrypted_size = RSA_private_decrypt(chunk_bytes, encrypted_data + total_decrypted_size, data + total_decrypted_plain_text_size, m_private_key, RSA_PKCS1_PADDING);
        if (decrypted_size == -1) {
            // Error occurred while decrypting, get openssl error
            printf("Error: loop = %d, %s\n", loop_cnt, ERR_error_string(ERR_get_error(), NULL));
            return false;
        }
        total_decrypted_size += chunk_bytes;
        total_decrypted_plain_text_size += decrypted_size;
    }
    *data_size = static_cast<size_t>(total_decrypted_plain_text_size);
    return true;
}

// Test the crypto functions
void Crypto::test_crypto() {
    // Test sha256
    uint8_t data[] = "Hello World!";
    uint8_t sha256_ary[32];
    sha256_fn(data, sizeof(data), sha256_ary);

    // Test encrypt and decrypt
    uint8_t encrypted_data[512];
    size_t encrypted_data_size = 0;
    encrypt(m_public_key, data, sizeof(data), encrypted_data, &encrypted_data_size);

    uint8_t decrypted_data[512];
    size_t decrypted_data_size = 0;
    decrypt(encrypted_data, encrypted_data_size, decrypted_data, &decrypted_data_size);
    decrypted_data[decrypted_data_size] = '\0';
    printf("Decrypted data: %s\n", decrypted_data);
}