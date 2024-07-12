/*
 * @Author: Weili
 * @Date: 2023-12-14
 * @LastEditTime: 2024-01-12
 * @FilePath: /sgxbraft_006/src/host/host_ipc.cpp
 * @Description: Inter process communication
 */

#include <openenclave/host.h>
#include <pthread.h>
#include <stdio.h>
#include "host_ipc.h"
#include "interface_u.h"
#include <errno.h>
#include <string>

extern oe_enclave_t* enclave;
static key_t ipc_key;
static int ipc_msgid;
static bool ipc_initialized = false;
static pthread_t ipc_thread_temparary;
static pthread_t ipc_thread;

void host_ipc_recv_attest_req(void *buffer, int size, void *response, int response_size, int* ret_resp_sz) {
    ipc_message msg;
    // Receive message
    msgrcv(ipc_msgid, &msg, IPC_MESSAGE_SIZE, 1, 0);
    memcpy(response, msg.msg, msg.msize);
    *ret_resp_sz = msg.msize;
    if (msg.msize > response_size) {
        printf("Error: response buffer size is not enough\n");
        return;
    }
    printf("[KVE-host]Received message with size = %d\n", msg.msize);
    // Send message
    ipc_message msg2;
    msg2.mtype = 2;
    msg2.msize = size;
    memcpy(msg2.msg, buffer, size);
    if (msgsnd(ipc_msgid, &msg2, size+8, 0) == -1) {
        printf("Error: msgsnd, errno = %d\n", errno);
        return;
    }
    printf("[KVE-host]Sent message with size = %d\n", size);
    // printf("host print data");
    // for (int j = 0; j < size; j++)
    // {
    //     printf("%0x", ((uint8_t*)buffer)[j]);
    // }
    // printf("host print data end\n");
    return;
}


void ipc_setup(int node_num) {
    printf("ipc_setup, node_num = %d\n", node_num);
    std::string path = "/root/KV-Enclave-Running-Data/";
    path += "ipc_key_";
    path += std::to_string(node_num);
    path += ".txt";
    // Generate unique key, we need to pass a valid path name here
    ipc_key = ftok(path.c_str(), '0');
    if (ipc_key == -1) {
        printf("Error: ftok, errno = %d\n", errno);
        return;
    }
    // Retrieve message queue
    ipc_msgid = msgget(ipc_key, 0666 | IPC_CREAT);
    if (ipc_msgid == -1) {
        printf("Error: msgget, errno = %d\n", errno);
        return;
    }
    ipc_initialized = true;
}

void ipc_handle_kv_request(ipc_message* msg, int size, uint8_t* resp_buf, int resp_sz, int* ret_resp_sz) {
    // printf("Func: %s, size = %d\n", __FUNCTION__, size);
    // for (int i = 0; i < size; i++) {
    //     printf("%X", ((uint8_t*)msg->msg)[i]);
    // }
    // printf("\n");
    // printf("print end\n");
    enclave_handle_local_kv_req(enclave, (uint8_t*)msg->msg, size, resp_buf, resp_sz, ret_resp_sz);
    if (*ret_resp_sz > resp_sz) {
        printf("Error: response buffer size is not enough\n");
        return;
    }
}

void* ipc_thread_worker(void* arg) {
    int node_num = *(int*)arg;
    ipc_setup(node_num);
    enclave_kv_enclave_setup(enclave);
    ipc_start_listening();
    return NULL;
}

void ipc_setup_thread(int node_num) {
    pthread_attr_t attributes;
    pthread_attr_init(&attributes);
    pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
    int* arg = (int*)malloc(sizeof(int));
    *arg = node_num;
    if (pthread_create(&ipc_thread_temparary, NULL, ipc_thread_worker, arg) != 0) {
        printf("Error: pthread_create\n");
        return;
    }
}

void* ipc_start_listening_thread_worker(void* arg) {
    // An infinite loop to listen to the message queue
    while (true) {
        ipc_message msg;
        // Receive message with message type 3 only
        msgrcv(ipc_msgid, &msg, IPC_MESSAGE_SIZE, 3, 0);

        printf("Received message [msg type 3] with size = %d\n", msg.msize);
        // for (int i = 0; i < msg.msize; i++) {
        //     printf("%X", ((uint8_t*)msg.msg)[i]);
        // }
        // printf("\n");

        // Invoke do_sth to handle the message
        const int resp_sz = 1024*1024; // 1MB should be enough
        int ret_resp_sz = 0;
        uint8_t* resp = (uint8_t*)malloc(sizeof(uint8_t) * resp_sz);
        ipc_handle_kv_request(&msg, msg.msize, resp, resp_sz, &ret_resp_sz);
        // Send response with message type 4
        ipc_message msg2;
        msg2.mtype = 4;
        msg2.msize = ret_resp_sz;
        memcpy(msg2.msg, resp, ret_resp_sz);
        if (msgsnd(ipc_msgid, &msg2, ret_resp_sz+8, 0) == -1) {
            printf("Error: msgsnd, errno = %d\n", errno);
            return NULL;
        }
        printf("Sent response [msg type 4] with size = %d\n", ret_resp_sz);
        free(resp);
    }
    return NULL;
}


// We create a thread to listen to the message queue (the local AKM enclave will send messages to this queue)
void ipc_start_listening() {
    if (!ipc_initialized) {
        printf("Error: ipc not initialized\n");
        return;
    }
    printf("ipc_start_listening\n");
    // Create a pthread to execute ipc_start_listening_thread_worker
    if (pthread_create(&ipc_thread, NULL, ipc_start_listening_thread_worker, NULL) != 0) {
        printf("Error: pthread_create\n");
        return;
    }
    printf("ipc_start_listening end\n");
}