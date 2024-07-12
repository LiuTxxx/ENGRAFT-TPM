#ifndef HOST_HOST_TPM_UTILS_H
#define HOST_HOST_TPM_UTILS_H
#ifdef SGX_USE_TPM_COUNTER
#include <tss2_common.h>
#include <tss2_esys.h>
#include <tss2_sys.h>
#include <tss2_mu.h>
#include <tss2_rc.h>
#include <tss2_tpm2_types.h>
#endif 
#include <string>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

typedef int CounterID;
#ifdef SGX_USE_TPM_COUNTER
#define goto_if_error(r,msg,label) \
    if (r != TSS2_RC_SUCCESS) { \
        LOG(ERROR) << msg << " Error detail: " << Tss2_RC_Decode(uint32_t(r)); \
        goto label;  \
    }
#endif

#if RUN_OUTSIDE_SGX
void ocall_create_counter(uint32_t* index);
void ocall_start_auth_session(void* nonce_buffer, int nonce_buf_size, 
    void* encrypted_salt_buffer, int salt_buf_size, 
    void* nonce_tpm_buffer, uint32_t* session_handle);

void ocall_add_counter(uint32_t session_handle, uint32_t nv_handle,
    void* nonce_buffer, int nonce_buf_size,
    uint8_t* hmac_in_buffer, int hmac_size,
    uint8_t* nonce_tpm_buffer,
    uint8_t* hmac_out_buffer);

void ocall_read_counter(uint32_t session_handle, uint32_t nv_handle,
    void* nonce_buffer, int nonce_buf_size,
    uint8_t* hmac_in_buffer, int hmac_size,
    uint8_t* nonce_tpm_buffer,
    uint8_t* hmac_out_buffer, 
    void* read_data, int read_data_size);

#else
#include "interface_u.h"

#endif

#ifdef SGX_USE_TPM_COUNTER
TSS2_SYS_CONTEXT* sys_init_from_tcti_ctx(TSS2_TCTI_CONTEXT * tcti_ctx);
TSS2_TCTI_CONTEXT* tcti_device_init(char const *device_path);
int initialize_tpm2();
int initialize_tpm2_mssim();
#endif

#endif