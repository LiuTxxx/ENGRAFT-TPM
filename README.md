### Introduction
ENGRAFT, a BFT system built atop Intel SGX and Baidu BRaft.

### Build and Run

This project use the modified OpenEnclave SDK, environment has been configured in docker, run docker with image below and remember to port the device of SGX, if use TPM, port TPM:

```bash
# example
docker run --network=host --name oe_sdk_ant --device /dev/tpm0:/dev/tpm0 --device /dev/tpmrm0:/dev/tpmrm0 --device /dev/sgx_enclave:/dev/sgx/enclave --device /dev/sgx_provision:/dev/sgx/provision -i -t registry.cn-shenzhen.aliyuncs.com/openenclave_sdk/oesdk_v0_17_0:2024_06_30_v2
```



```bash
cd ~/code_dev
git clone https://github.com/LiuTxxx/ENGRAFT-TPM.git
cd ENGRAFT-TPM
# create key and file for memory sharing
./init_env.sh
# build
mkdir build
# cmake that enables TPM
cmake .. -DEnableTPM=1
make -j32
# run
cd ../runtime
# create folder for running data, logs
mkdir 0 1 2
# this will run 3 node in 8100 8101 8102
./local_start_cluster.sh -b

# if cannot get key and cert for remote attestation run this:
unset SGX_AESM_ADDR
# or check pccs url:
vim /etc/sgx_default_qcnl.conf
# check lines below
# //PCCS server address
# "pccs_url": "https://10.16.46.212:8081/sgx/certification/v4/"
```

