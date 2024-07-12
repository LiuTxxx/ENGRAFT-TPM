#!/usr/bin/env bash
# This script should be executed in XPS machine
# b means cluster begins
# e means cluster stops
binary_path=/root/code_dev/sgxbraft_006/runtime/
binary_name=sgx_raft_host

start_xps() {
    ssh xps1 "
    echo start ${binary_name} in xps1;
    cd $binary_path/1;
    ../run.sh -d;
    pwd;
    "
    ssh xps2 "
    echo start ${binary_name} in xps2;
    cd $binary_path/2;
    ../run.sh -d;
    pwd;
    "
    sleep 0.3
    pushd 0
    ../run.sh -d
    popd
}

stop_xps() {
    echo kill ${binary_name} process in xps0
    sudo killall -9 ${binary_name}

    ssh xps1 "
    echo kill ${binary_name} process in xps1;
    sudo killall -9 ${binary_name}
    ;
    "

    ssh xps2 "
    echo kill ${binary_name} process in xps2;
    sudo killall -9 ${binary_name}
    ;
    "
}

int_handler() {
    stop_xps;
    exit;
}

while getopts "a:be" arg #选项后面的冒号表示该选项需要参数
do
        case $arg in
             a)
                echo "a's arg:$OPTARG" #参数存在$OPTARG中
                ;;
             b)
                # Firstly stop the running servers
                stop_xps
                start_xps
                trap int_handler SIGINT
                run=0
                while true
                do
                    echo Raft servers have been running for $run seconds;
                    sleep 10;
                    run=`expr $run + 10`;
                done
                ;;
             e)
                stop_xps
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

