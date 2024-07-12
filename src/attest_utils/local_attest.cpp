#include "interface_t.h"
#include "attest_utils/attestation.h"
#include "attest_utils/dispatcher.h"
#include "attest_utils/dev_key_pub.h"
#include <openenclave/attestation/sgx/evidence.h>
#include "attest_utils/local_attest.pb.h"


void kve_setup_local_req_handler();
const char* enclave_name = "KV-Enclave";
static oe_uuid_t sgx_local_uuid = {OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};

uint8_t g_enclave_secret_data[ENCLAVE_SECRET_DATA_SIZE] =
    {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

enclave_config_data_t config_data = {
    g_enclave_secret_data,
    OTHER_ENCLAVE_PUBLIC_KEY,
    sizeof(OTHER_ENCLAVE_PUBLIC_KEY)};
ecall_dispatcher kve_dispatcher(enclave_name, &config_data);

void enclave_kv_enclave_setup() {
    kve_setup_local_req_handler();
    printf("Enclave setup\n");
    int ret = 1;
    uint8_t** format_settings = (uint8_t**)malloc(sizeof(uint8_t*));
    size_t format_settings_size = 0;
    int ret_sz = 0;
    const oe_uuid_t* format_id = &sgx_local_uuid;
    kve_dispatcher.get_enclave_format_settings(format_id, format_settings, &format_settings_size);
    printf("format_settings_size: %d\n", format_settings_size);
    // for (int i = 0; i < format_settings_size; i++) {
    //     printf("%02x", ((uint8_t*)(*format_settings))[i]);
    // }
    // printf("\n\n");
    
    void* other_enclave_format_settings = malloc(format_settings_size);
    host_ipc_recv_attest_req(*format_settings, format_settings_size, other_enclave_format_settings, format_settings_size, &ret_sz);
    printf("done\n");
    // for (int i = 0; i < format_settings_size; i++) {
    //     printf("%02x", ((uint8_t*)other_enclave_format_settings)[i]);
    // }
    // printf("\n");

    uint8_t** pem_key = (uint8_t**)malloc(sizeof(uint8_t*));
    uint8_t** evidence_buffer = (uint8_t**)malloc(sizeof(uint8_t*));
    size_t pem_key_size = 0;
    size_t evidence_buffer_size = 0;
    kve_dispatcher.get_evidence_with_public_key(format_id, (uint8_t*)(other_enclave_format_settings), format_settings_size, pem_key, &pem_key_size, evidence_buffer, &evidence_buffer_size);

    LocalAttestationRequest req;
    req.set_step(1);
    req.set_evidence((void*)(*evidence_buffer), evidence_buffer_size);
    req.set_evidence_size(evidence_buffer_size);
    req.set_pub_key((void*)(*pem_key), pem_key_size);
    req.set_pub_key_size(pem_key_size);
    size_t req_size = req.ByteSize();
    void *req_buf = malloc(req_size);
    req.SerializeToArray(req_buf, req_size);
    size_t resp_size = 2*req_size;
    void* resp_buf = malloc(resp_size);
    int ret_resp_sz = 0;
    host_ipc_recv_attest_req(req_buf, req_size, resp_buf, resp_size, &ret_resp_sz);

    // print data byte-by-byte in one line
    // TRACE_ENCLAVE("print req.pub_key");
    // for (int j = 0; j < req.pub_key_size(); j++)
    // {
    //     printf("%0x", (uint8_t)(req.pub_key().data()[j]));
    // }
    // printf("\n");

    LocalAttestationRequest resp;
    resp.ParseFromArray(resp_buf, ret_resp_sz);
    int local_attest_status = kve_dispatcher.verify_evidence_and_set_public_key(format_id, (uint8_t*)resp.pub_key().data(), resp.pub_key_size(), (uint8_t*)resp.evidence().data(), resp.evidence_size());
    printf("local_attest_status = %d\n", local_attest_status);


    // kve_dispatcher.test_dispatcher();
}