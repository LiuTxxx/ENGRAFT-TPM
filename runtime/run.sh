#!/usr/bin/env bash
current_folder=$(basename "$PWD")
init_port=8100
port_num=$((${init_port}+${current_folder}))
echo "port_num = ${port_num}"
while getopts "a:cde" arg #选项后面的冒号表示该选项需要参数
do
        case $arg in
             a)
                echo "a's arg:$OPTARG" #参数存在$OPTARG中
                ;;
             c)
                echo "Foreground running"
                echo "Clear data in runtime"
                cp ../../build/src/host/sgx_raft_host .
                cp ../../build/example/kv_store/enclave.signed .
                sudo rm -rf /root/KV-Enclave-Running-Data/${current_folder}/data
                sudo rm -rf /root/KV-Enclave-Running-Data/${current_folder}/counter.tmp
                sudo ./sgx_raft_host enclave.signed -port=${port_num} 2>&1 | tee out.log${current_folder}
                ;;
             d)
                echo "Background running, Clear data in runtime"
                cp ../../build/src/host/sgx_raft_host .
                cp ../../build/example/kv_store/enclave.signed .
                sudo rm -rf /root/KV-Enclave-Running-Data/${current_folder}/data
                sudo rm -rf /root/KV-Enclave-Running-Data/${current_folder}/counter.tmp
                sudo ./sgx_raft_host enclave.signed -port=${port_num} > out.log${current_folder} 2>&1 &
                ;;
             e)
                echo "Background running, use existing runtime"
                cp ../../build/src/host/sgx_raft_host .
                cp ../../build/example/kv_store/enclave.signed .
                sudo ./sgx_raft_host enclave.signed -port=${port_num} > out.log${current_folder} 2>&1 &
                ;;
            #  v)
            #     echo "Using valgrind"
            #     running_cmd="valgrind --tool=memcheck --leak-check=full --log-file=valout_mem.txt"
            #     ;;
             ?)  #当有不认识的选项的时候arg为?
            echo "unknow argument"
        exit 1
        ;;
        esac
done