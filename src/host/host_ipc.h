/*
 * @Author: Weili
 * @Date: 2023-12-14
 * @LastEditTime: 2024-01-06
 * @FilePath: /sgxbraft_006/src/host/host_ipc.h
 * @Description: 
 */

#ifndef HOST_IPC_H
#define HOST_IPC_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <time.h>
#include <stdint.h>

// 1MB
#define IPC_MESSAGE_SIZE 1024*1024

typedef struct ipc_message {
    long mtype;
    int msize;
    char msg[IPC_MESSAGE_SIZE];
} ipc_message;

void ipc_setup(int node_num);
void ipc_setup_thread(int node_num);

void ipc_start_listening();
void* ipc_start_listening_thread_worker(void* arg);
void* ipc_thread_worker(void* arg);
void ipc_handle_kv_request(ipc_message* msg, int size, uint8_t* resp_buf, int resp_sz, int* ret_resp_sz);


#endif // HOST_IPC_H