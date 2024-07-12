#include "host/host_tpm_utils.h"
#include <unistd.h>
#ifdef SGX_USE_TPM_COUNTER
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tcti_device.h>
#include <tss2_tcti_mssim.h>
#include <assert.h>
#endif
#include <iostream>
#include "duplicated_things.h"

#ifdef SGX_USE_TPM_COUNTER
TSS2_SYS_CONTEXT *sys_ctx;
TPMI_DH_OBJECT ek_nv_handle = 0x81000008;
extern int node_num;
int cnt = 0;

/* From TSS2 v3.1.0 :
 * Initialize a TSS2_TCTI_CONTEXT for the device TCTI.
 */
TSS2_TCTI_CONTEXT* tcti_device_init(char const *device_path) {
    size_t size;
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti_ctx;

    rc = Tss2_Tcti_Device_Init(NULL, &size, 0);
    if (rc != TSS2_RC_SUCCESS) {
        LOG(ERROR) << "Func: " << __FUNCTION__ 
            << "Failed to get allocation size for device tcti context: ";
        return NULL;
    }
    tcti_ctx = (TSS2_TCTI_CONTEXT *) calloc(1, size);
    if (tcti_ctx == NULL) {
        LOG(ERROR) << "Func: " << __FUNCTION__ 
            << "Allocation for device TCTI context failed. " << strerror(errno);
        return NULL;
    }
    rc = Tss2_Tcti_Device_Init(tcti_ctx, &size, device_path);
    if (rc != TSS2_RC_SUCCESS) {
        LOG(ERROR) << "Func: " << __FUNCTION__ 
            << "Failed to initialize device TCTI context.";
        free(tcti_ctx);
        return NULL;
    }
    return tcti_ctx;
}

/* From TSS2 v3.1.0 :
 * Initialize a SYS context using the TCTI context provided by the caller.
 * This function allocates memory for the SYS context and returns it to the
 * caller. This memory must be freed by the caller.
 */
TSS2_SYS_CONTEXT* sys_init_from_tcti_ctx(TSS2_TCTI_CONTEXT * tcti_ctx) {
    TSS2_SYS_CONTEXT *sys_ctx;
    TSS2_RC rc;
    size_t size;
    TSS2_ABI_VERSION abi_version = {
        .tssCreator = 1,
        .tssFamily = 2,
        .tssLevel = 1,
        .tssVersion = 108,
    };

    size = Tss2_Sys_GetContextSize(0);
    sys_ctx = (TSS2_SYS_CONTEXT *) calloc(1, size);
    if (sys_ctx == NULL) {
        fprintf(stderr,
                "Failed to allocate 0x%zx bytes for the SYS context\n", size);
        return NULL;
    }
    rc = Tss2_Sys_Initialize(sys_ctx, size, tcti_ctx, &abi_version);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to initialize SYS context: 0x%x\n", rc);
        free(sys_ctx);
        return NULL;
    }
    return sys_ctx;
}

int initialize_tpm2() {
    TSS2_TCTI_CONTEXT *tcti_ctx = tcti_device_init("/dev/tpmrm0");
    sys_ctx = sys_init_from_tcti_ctx(tcti_ctx);
    return 0;
}

// ibmtpm simulator comply with the mssim specification
int initialize_tpm2_mssim() {
    size_t tcti_size = 0;
    uint8_t recv_buf[4] = { 0 };
    TSS2_RC ret = TSS2_RC_SUCCESS;
    TSS2_TCTI_CONTEXT *ctx = NULL;

    ret = Tss2_Tcti_Mssim_Init (NULL, &tcti_size, NULL);
    assert(ret == TSS2_RC_SUCCESS);
    ctx = (TSS2_TCTI_CONTEXT *)calloc (1, tcti_size);
    assert(ctx!=NULL);
    ret = Tss2_Tcti_Mssim_Init (ctx, &tcti_size, "host=127.0.0.1,port=2321");

    //- Init the context.
    sys_ctx = sys_init_from_tcti_ctx(ctx);
    return 0;
}
#endif

void ocall_create_counter(uint32_t* counter_id) {
#ifdef SGX_USE_TPM_COUNTER
    //- A Raft node only uses two counters, so:
    //- For raft node 0, the nv handle varies from 0x01000000 to 0x01000001
    //- For raft node 1, the nv handle varies from 0x01000002 to 0x01000003
    uint32_t nv_first = 0x01000000 + (node_num * 0x2);
    //- FIXME: Ensure that these counters exist in the TPM. We can use command line tools
    // 1. create: tpm2_nvdefine -C o -s 8 -a "ownerread|ownerwrite|nt=1|authread|authwrite" 0x01000000
    // 2. increase: tpm2_nvincrement -C o  0x01000000
    // 3. read:  tpm2_nvread -C o 0x01000000|xxd -p
    *counter_id = nv_first + cnt;
    LOG(INFO) << "Func: " << __FUNCTION__ << " nv_handle = " << *counter_id;
    cnt++;
#endif
    return ;
}

//- Receive nonce_caller, encrypted_salt from the enclave
//- Return nonce_tpm and session handle
void ocall_start_auth_session(
    void* nonce_buffer, int nonce_buf_size, 
    void* encrypted_salt_buffer, int encrypted_salt_buf_size, 
    void* nonce_tpm_buffer,
    uint32_t* session_handle) {     
#ifdef SGX_USE_TPM_COUNTER
    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_NULL,
    };
    TPM2B_NONCE* nonce_caller = (TPM2B_NONCE*) nonce_buffer;
    TPM2B_ENCRYPTED_SECRET* encrypted_salt 
        = (TPM2B_ENCRYPTED_SECRET*) encrypted_salt_buffer;
    TPM2B_NONCE* nonce_tpm = (TPM2B_NONCE*) nonce_tpm_buffer;
    //- First 2 bytes are size field in TPM2B_NONCE structure
    nonce_tpm->size = nonce_buf_size - 2;

    int rc = Tss2_Sys_StartAuthSession(sys_ctx,
                                    ek_nv_handle,
                                    TPM2_RH_NULL,
                                    0,
                                    nonce_caller,
                                    encrypted_salt,
                                    TPM2_SE_HMAC,
                                    &symmetric,
                                    TPM2_ALG_SHA256,
                                    session_handle,
                                    nonce_tpm,
                                    0);
    if (rc != 0) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " StartAuthSession failed: " 
            << Tss2_RC_Decode(rc);
        return ;            
    }
    LOG(INFO) << "Func: " << __FUNCTION__ << " session handle = " << *session_handle;
#endif
    return ;
}


void ocall_add_counter(uint32_t session_handle, uint32_t nv_handle,
    void* nonce_buffer, int nonce_buf_size, //- Pointer to the whole nonce struct
    uint8_t* hmac_in_buffer, int hmac_size,
    uint8_t* nonce_tpm_buffer,
    uint8_t* hmac_out_buffer) {
#ifdef SGX_USE_TPM_COUNTER
    TPM2B_NONCE* nonce_caller = (TPM2B_NONCE*) nonce_buffer;
    TSS2L_SYS_AUTH_RESPONSE resp_auth;
    TSS2L_SYS_AUTH_COMMAND cmd_auth;
    cmd_auth.count = 1;
    cmd_auth.auths[0].sessionHandle = session_handle;
    cmd_auth.auths[0].sessionAttributes = TPMA_SESSION_CONTINUESESSION;
    cmd_auth.auths[0].nonce.size = nonce_caller->size;
    memcpy(cmd_auth.auths[0].nonce.buffer, nonce_caller->buffer, nonce_caller->size);

    cmd_auth.auths[0].hmac.size = hmac_size;
    memcpy(cmd_auth.auths[0].hmac.buffer, hmac_in_buffer, hmac_size);

    int rc = 0;
    // butil::Timer timer;
    // timer.start();
    timespec tm;
    timespec tm2;
    clock_gettime(CLOCK_MONOTONIC, &tm);
    rc = Tss2_Sys_NV_Increment(sys_ctx,
                        nv_handle,
                        nv_handle,
                        &cmd_auth,
                        &resp_auth);   
    // timer.stop();
    if (rc != TSS2_RC_SUCCESS) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Increment failed: " << Tss2_RC_Decode(rc);
        return ;
    }
    clock_gettime(CLOCK_MONOTONIC, &tm2);
    if (tm2.tv_sec > tm.tv_sec) {
        LOG(INFO) << "Func: " << __FUNCTION__ << " TIME_OF NV_Increment = "
        << (tm2.tv_nsec+(tm2.tv_sec - tm.tv_sec)*1000000000-tm.tv_nsec)/1000000 << " ms";
    } else {
        LOG(INFO) << "Func: " << __FUNCTION__ << " TIME_OF NV_Increment = "
        << ((tm2.tv_nsec - tm.tv_nsec)/1000000) << " ms";
    }

    
        
    memcpy(nonce_tpm_buffer, resp_auth.auths[0].nonce.buffer, nonce_buf_size-2);
    memcpy(hmac_out_buffer, resp_auth.auths[0].hmac.buffer, hmac_size);
#endif
    return ;
}

//- read_data is a pointer to the whole TPM2B_MAX_NV_BUFFER struct
//- nonce_buffer is a pointer to the whole TPM2B_NONCE struct
void ocall_read_counter(uint32_t session_handle, uint32_t nv_handle,
    void* nonce_buffer, int nonce_buf_size,
    uint8_t* hmac_in_buffer, int hmac_size,
    uint8_t* nonce_tpm_buffer, uint8_t* hmac_out_buffer,     
    void* read_data, int read_data_size) {
#ifdef SGX_USE_TPM_COUNTER
    TPM2B_NONCE* nonce_caller = (TPM2B_NONCE*) nonce_buffer;
    TSS2L_SYS_AUTH_RESPONSE resp_auth;
    TSS2L_SYS_AUTH_COMMAND cmd_auth;
    cmd_auth.count = 1;
    cmd_auth.auths[0].sessionHandle = session_handle;
    cmd_auth.auths[0].sessionAttributes = TPMA_SESSION_CONTINUESESSION;
    cmd_auth.auths[0].nonce.size = nonce_caller->size;
    memcpy(cmd_auth.auths[0].nonce.buffer, nonce_caller->buffer, nonce_caller->size);

    cmd_auth.auths[0].hmac.size = hmac_size;
    memcpy(cmd_auth.auths[0].hmac.buffer, hmac_in_buffer, hmac_size);

    int rc = 0;
    TPM2B_MAX_NV_BUFFER* nv_data = (TPM2B_MAX_NV_BUFFER*) read_data;
    rc = Tss2_Sys_NV_Read(sys_ctx,
                        nv_handle,
                        nv_handle,
                        &cmd_auth,
                        8, 0,
                        nv_data,
                        &resp_auth);
    if (rc != TSS2_RC_SUCCESS) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Read failed: " << Tss2_RC_Decode(rc);
        return ;
    }
    memcpy(nonce_tpm_buffer, resp_auth.auths[0].nonce.buffer, nonce_buf_size-2);
    memcpy(hmac_out_buffer, resp_auth.auths[0].hmac.buffer, hmac_size);
#endif
    return ;
}

