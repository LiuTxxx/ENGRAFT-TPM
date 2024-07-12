#!/bin/bash
echo "Removing..."
# Remove the data directory
for ((i=0; i<100; ++i)); do
   sudo rm -rf /root/KV-Enclave-Running-Data/$i/data
   sudo rm -rf /root/KV-Enclave-Running-Data/$i/counter.tmp
done
