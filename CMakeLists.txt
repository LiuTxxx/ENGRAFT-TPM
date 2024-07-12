# trash *(D) && cmake -DCMAKE_BUILD_TYPE=Debug .. && make -j16
cmake_minimum_required(VERSION 3.11)


project("SGX-Braft version 0.06" LANGUAGES C CXX)

option(KVENCLAVE "Build KV enclave" ON)
if(KVENCLAVE)
    message("Build KV server enclave")
else()
    message("Build counter server enclave")
endif()

# option(TESTIF "test" OFF)
# if(TESTIF)
#     message("true")
# else()
#     message("false")
# endif()

option(EnableTPM "If true, will search tss2 libraries and use" OFF)
if(EnableTPM)
    message("Enable TPM usage in enclave")
    add_compile_definitions(SGX_USE_TPM_COUNTER)
endif()

add_compile_definitions(USE_HOST_EVENT_DISPATCHER)
#add_compile_definitions(SGX_USE_REMOTE_ATTESTATION)
message(cpp_compiler: ${CMAKE_CXX_COMPILER})
message(c_compiler: ${CMAKE_C_COMPILER})

# Use ccache to boost compilation
set(CMAKE_CXX_COMPILER_LAUNCHER ccache)
set(CMAKE_C_COMPILER_LAUNCHER ccache)

#- Generate compile commands used by clangd.
set(CMAKE_EXPORT_COMPILE_COMMANDS 1)
# Set build type to debug to use oegdb
set(CMAKE_BUILD_TYPE Debug)
# set(CMAKE_BUILD_TYPE Release)

# Currently the `OpenEnclave` package depends on `project()`.
find_package(OpenEnclave CONFIG REQUIRED PATHS /opt/openenclave_0_17_0 NO_DEFAULT_PATH)
# find_package(OpenEnclave CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 11)
set(OE_CRYPTO_LIB
    openssl
    CACHE STRING "Crypto library used by enclaves.")

# enclave code
if(KVENCLAVE)
    add_subdirectory(example/kv_store)
else()
    add_subdirectory(example/counter)
endif()

# host code
add_subdirectory(src/host)

# Generate key
# add_custom_command(
#   OUTPUT private.pem public.pem
#   COMMAND openssl genrsa -out private.pem -3 3072
#   COMMAND openssl rsa -in private.pem -pubout -out public.pem)

# Sign enclave
# Note that we use a developer key (dev_key_priv.pem, it belongs to the enclave developer, and the developer will share dev_key_pub.pem to users to facilicate attestation) here instead of a randomly generated key.
if(KVENCLAVE)
    add_custom_command(
        OUTPUT example/kv_store/enclave.signed
        DEPENDS enclave example/kv_store/kvenclave.conf dev_key_priv.pem
        COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave> -c
                ${CMAKE_SOURCE_DIR}/example/kv_store/kvenclave.conf -k ${CMAKE_SOURCE_DIR}/dev_key_priv.pem)
    add_custom_target(sign ALL DEPENDS example/kv_store/enclave.signed)
else()
    add_custom_command(
        OUTPUT example/counter/enclave.signed
        DEPENDS enclave example/counter/sgx_raft.conf dev_key_priv.pem
        COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave> -c
                ${CMAKE_SOURCE_DIR}/example/counter/sgx_raft.conf -k ${CMAKE_SOURCE_DIR}/dev_key_priv.pem)
    add_custom_target(sign ALL DEPENDS example/counter/enclave.signed)
endif()


add_custom_target(
run
DEPENDS sgx_raft_host sign
COMMAND sgx_raft_host ${CMAKE_BINARY_DIR}/enclave/enclave.signed)
