// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "dispatcher.h"
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/report.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/enclave.h>
#include <sgxbutil/logging.h>

ecall_dispatcher::ecall_dispatcher(
    const char* name,
    enclave_config_data_t* enclave_config)
    : m_crypto(nullptr), m_attestation(nullptr)
{
    m_enclave_config = enclave_config;
    m_initialized = initialize(name);
}

ecall_dispatcher::~ecall_dispatcher()
{
    if (m_crypto)
        delete m_crypto;

    if (m_attestation)
        delete m_attestation;
}

bool ecall_dispatcher::initialize(const char* name)
{
    bool ret = false;

    m_name = name;
    m_crypto = new Crypto();
    if (m_crypto == nullptr)
    {
        goto exit;
    }

    {
        size_t other_enclave_signer_id_size = sizeof(m_other_enclave_signer_id);
        // TODO: the following call is not TEE-agnostic.
        if (oe_sgx_get_signer_id_from_public_key(
                m_enclave_config->other_enclave_public_key_pem,
                m_enclave_config->other_enclave_public_key_pem_size,
                m_other_enclave_signer_id,
                &other_enclave_signer_id_size) != OE_OK)
        {
            goto exit;
        }
    }

    m_attestation = new Attestation(m_crypto, m_other_enclave_signer_id);
    if (m_attestation == nullptr)
    {
        goto exit;
    }
    ret = true;

exit:
    return ret;
}

int ecall_dispatcher::get_enclave_format_settings(
    const oe_uuid_t* format_id,
    uint8_t** format_settings_buffer,
    size_t* format_settings_buffer_size)
{
    uint8_t* format_settings = nullptr;
    size_t format_settings_size = 0;
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
        goto exit;
    }

    // Generate a format settings so that the enclave that receives this format
    // settings can attest this enclave.
    TRACE_ENCLAVE("get_enclave_format_settings");
    if (m_attestation->get_format_settings(
            format_id, &format_settings, &format_settings_size) == false)
    {
        TRACE_ENCLAVE("get_enclave_format_settings failed");
        goto exit;
    }

    if (format_settings && format_settings_size)
    {
        // Allocate memory on the host and copy the format settings over.
        // TODO: the following code is not TEE-agnostic, as it assumes the
        // enclave can directly write into host memory
        *format_settings_buffer =
            (uint8_t*)oe_host_malloc(format_settings_size);
        if (*format_settings_buffer == nullptr)
        {
            ret = OE_OUT_OF_MEMORY;
            TRACE_ENCLAVE("copying format_settings failed, out of memory");
            goto exit;
        }
        memcpy(*format_settings_buffer, format_settings, format_settings_size);
        *format_settings_buffer_size = format_settings_size;
        oe_verifier_free_format_settings(format_settings);
    }
    else
    {
        *format_settings_buffer = nullptr;
        *format_settings_buffer_size = 0;
    }
    ret = 0;

exit:

    if (ret != 0)
        TRACE_ENCLAVE("get_enclave_format_settings failed.");
    return ret;
}

/**
 * Return the public key of this enclave along with the enclave's
 * evidence. The enclave that receives the key will use the evidence to
 * attest this enclave.
 */
int ecall_dispatcher::get_evidence_with_public_key(
    const oe_uuid_t* format_id,
    uint8_t* format_settings,
    size_t format_settings_size,
    uint8_t** pem_key,
    size_t* pem_key_size,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size)
{
    uint8_t pem_public_key[512];
    uint8_t* evidence = nullptr;
    size_t evidence_size = 0;
    uint8_t* key_buffer = nullptr;
    int ret = 1;

    TRACE_ENCLAVE("get_evidence_with_public_key");
    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    m_crypto->retrieve_public_key(pem_public_key);

    // Generate evidence for the public key so that the enclave that
    // receives the key can attest this enclave.
    if (m_attestation->generate_attestation_evidence(
            format_id,
            format_settings,
            format_settings_size,
            pem_public_key,
            sizeof(pem_public_key),
            &evidence,
            &evidence_size) == false)
    {
        TRACE_ENCLAVE("get_evidence_with_public_key failed");
        goto exit;
    }

    // Allocate memory on the host and copy the evidence over.
    // TODO: the following code is not TEE-agnostic, as it assumes the
    // enclave can directly write into host memory
    *evidence_buffer = (uint8_t*)oe_host_malloc(evidence_size);
    if (*evidence_buffer == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("copying evidence_buffer failed, out of memory");
        goto exit;
    }
    memcpy(*evidence_buffer, evidence, evidence_size);
    *evidence_buffer_size = evidence_size;
    oe_free_evidence(evidence);

    key_buffer = (uint8_t*)oe_host_malloc(512);
    if (key_buffer == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("copying key_buffer failed, out of memory");
        goto exit;
    }
    memcpy(key_buffer, pem_public_key, sizeof(pem_public_key));

    *pem_key = key_buffer;
    *pem_key_size = sizeof(pem_public_key);

    ret = 0;
    TRACE_ENCLAVE("get_evidence_with_public_key succeeded");

exit:
    if (ret != 0)
    {
        if (evidence)
            oe_free_evidence(evidence);
        if (key_buffer)
            oe_host_free(key_buffer);
        if (*evidence_buffer)
            oe_host_free(*evidence_buffer);
    }
    return ret;
}

int ecall_dispatcher::verify_evidence_and_set_public_key(
    const oe_uuid_t* format_id,
    uint8_t* pem_key,
    size_t pem_key_size,
    uint8_t* evidence,
    size_t evidence_size)
{
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    // Attest the evidence and accompanying key.
    if (m_attestation->attest_attestation_evidence(
            format_id, evidence, evidence_size, pem_key, pem_key_size) == false)
    {
        TRACE_ENCLAVE("verify_evidence_and_set_public_key failed.");
        goto exit;
    }

    memcpy(m_crypto->get_the_other_enclave_public_key(), pem_key, pem_key_size);

    ret = 0;
    TRACE_ENCLAVE("verify_evidence_and_set_public_key succeeded.");

exit:
    return ret;
}

void ecall_dispatcher::test_dispatcher()
{
    m_crypto->test_crypto();
}

int ecall_dispatcher::encrypt_data_to_akme(uint8_t* data,
                                        size_t data_size,
                                        uint8_t** encrypted_data,
                                        size_t* encrypted_data_size) {
    int ret = 1;
    size_t guess_encrypted_data_size = (data_size / m_crypto->chunk_plaintext_limit + 1) * m_crypto->chunk_bytes;
    uint8_t* encrypted_data_buffer = (uint8_t*)malloc(guess_encrypted_data_size);

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
        goto exit;
    }
    
    if (m_crypto->encrypt2(
            m_crypto->get_the_other_enclave_public_key(),
            data,
            data_size,
            encrypted_data_buffer,
            encrypted_data_size) == false)
    {
        TRACE_ENCLAVE("enclave: generate encrypted message failed");
        goto exit;
    }

    if (*encrypted_data_size > guess_encrypted_data_size) {
        TRACE_ENCLAVE("enclave: generate encrypted message failed, encrypted_data_size > guess_encrypted_data_size");
        goto exit;
    }
    ret = 0;
    *encrypted_data = encrypted_data_buffer;
exit:
    return ret;
}

int ecall_dispatcher::decrypt_data_from_akme(uint8_t* encrypted_data,
                                          size_t encrypted_data_size,
                                          uint8_t** data,
                                          size_t* data_size) {
    int ret = 1;
    size_t guess_decrypted_data_size = encrypted_data_size;
    uint8_t* decrypted_data_buffer = (uint8_t*)malloc(guess_decrypted_data_size);
    if (m_initialized == false) {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
        goto exit;
    }
    if (m_crypto->decrypt2(
            encrypted_data, encrypted_data_size, decrypted_data_buffer, data_size) == false) {
        TRACE_ENCLAVE("Encalve:ecall_dispatcher::process_encrypted_msg failed");
        goto exit;
    }
    if (*data_size > guess_decrypted_data_size) {
        TRACE_ENCLAVE("Encalve:ecall_dispatcher::process_encrypted_msg failed, data_size > guess_decrypted_data_size");
        goto exit;
    }
    ret = 0;
    *data = decrypted_data_buffer;
exit:
    return ret;
}

void debug_util_print_buffer(const char* file, const char* func, int line, void* buffer, size_t size) {
    VLOG(78) << "\n\ndebug_util_print_buffer: size = " << size << " invoked from " << file << ":" << line << " " << func;
    uint8_t* data = (uint8_t*)buffer;
    for (int i = 0; i < size; i++) {
        printf("%X", data[i]);
    }
    printf("\n\n");
}