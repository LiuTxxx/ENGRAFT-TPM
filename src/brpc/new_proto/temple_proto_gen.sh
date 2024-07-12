/root/code_dev/protobuf-2.4.1/installed/bin/protoc -I/root/code_dev/protobuf-2.4.1/installed/include --cpp_out=/root/code_dev/sgxbraft_006/src/brpc/new_proto --proto_path=/root/code_dev/protobuf-2.4.1/installed/include --proto_path=/root/code_dev/sgxbraft_006/src /root/code_dev/sgxbraft_006/src/sgxbutil/state_cont/counter_rpc.proto

mv -f sgxbutil/state_cont/counter* ../../sgxbutil/state_cont/