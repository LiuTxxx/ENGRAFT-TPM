#!/usr/bin/env bash
# Run this script first when cloning the project to a new environment
# Assume root user
mkdir /root/KV-Enclave-Running-Data
for i in {0..2..1}; do
    mkdir /root/KV-Enclave-Running-Data/$i
    # Assume the current directory is the root of the project
    cp example/counter/key.pem /root/KV-Enclave-Running-Data/$i/
    cp example/counter/cert.pem /root/KV-Enclave-Running-Data/$i/
    touch /root/KV-Enclave-Running-Data/ipc_key_$i.txt
done
