#!/bin/bash
# set -e
echo "Creating TPM counters from 0x01000000 to 0x01000005 for testing"
# Template tpm2_nvdefine -C o -s 8 -a "ownerread|ownerwrite|nt=1|authread|authwrite" 0x01000000
for ((i=0; i<6; ++i)); do
    tpm2_nvdefine -C o -s 8 -a "ownerread|ownerwrite|nt=1|authread|authwrite" 0x0100000$i
done

