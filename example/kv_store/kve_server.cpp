/*
 * @Author: Weili
 * @Date: 2023-12-21
 * @LastEditTime: 2024-07-09
 * @FilePath: /sgxbraft_006/example/kv_store/kve_server.cpp
 * @Description: KV Enclave Server
 */

#include <brpc/controller.h>       // brpc::Controller
#include <brpc/server.h>           // brpc::Server
#include <braft/raft.h>                  // braft::Node braft::StateMachine
#include <braft/storage.h>               // braft::SnapshotWriter
#include <braft/util.h>                  // braft::AsyncClosureGuard
#include <braft/protobuf_file.h>         // braft::ProtoBufFile
#include <bthread/bthread.h>
#include <sgxbutil/state_cont/state_cont_service.h>
#include <sgxbutil/state_cont/openssl_utils.h>
#include "brpc/channel.h"
#include "interface_t.h"
#include "google/gflags/gflags.h"
#include "kve.pb.h"
#include <attest_utils/attestation.h>
#include <attest_utils/dispatcher.h>
#include <attest_utils/local_attest.pb.h>


extern ecall_dispatcher kve_dispatcher;
static void* local_req_handler = NULL;

DEFINE_bool(run_in_XPS_cluster, false, "Run nodes in cluster or local");
DEFINE_bool(check_term, true, "Check if the leader changed to another term");
DEFINE_bool(disable_cli, false, "Don't allow raft_cli access this node");
DEFINE_bool(log_applied_task, true, "Print notice log when a task is applied");
//- 原来的值是5000，单位：毫秒
DEFINE_int32(election_timeout_ms, 4000, 
            "Start election in such milliseconds if disconnect with the leader");
DEFINE_int32(port, 8100, "Listen port of this peer");
//- 原来的值是30，单位：秒
DEFINE_int32(snapshot_interval, 3000, "Interval between each snapshot");

//- A config consists of five nodes, it will be overwritten later if FLAGS_run_in_XPS_cluster is false
DEFINE_string(conf, "101.132.73.155:8100:0,47.97.177.123:8101:0,47.94.230.204:8102:0,47.101.134.142:8103:0,47.97.181.37:8104:0", "Initial configuration of the replication group");

DEFINE_string(data_path, "./data", "Path of data stored on");
DEFINE_string(group, "KVEnclave", "Id of the replication group");


namespace kv_enclave {
class KV_Store;
class LocalKVStoreReqHandler;

// Implements Closure which encloses RPC stuff
class StoreKVClosure : public braft::Closure {
public:
    StoreKVClosure(KV_Store* kvs, 
                    const KVStoreRequest* request,
                    KVResponse* response,
                    google::protobuf::Closure* done)
        : _kv_store(kvs)
        , _request(request)
        , _response(response)
        , _done(done) {}
    ~StoreKVClosure() {}

    const KVStoreRequest* request() const { return _request; }
    KVResponse* response() const { return _response; }
    void Run();

private:
    KV_Store* _kv_store;
    const KVStoreRequest* _request;
    KVResponse* _response;
    google::protobuf::Closure* _done;
};

// Implementation of kvenclave::KV_Store as a braft::StateMachine.
class KV_Store : public braft::StateMachine {
public:
    KV_Store()
        : _node(NULL)
        , _leader_term(-1)
    {}
    ~KV_Store() {
        delete _node;
    }

    // Starts this node
    int start() {
        if (!FLAGS_run_in_XPS_cluster) {
            FLAGS_conf = "172.28.197.94:8100:0,172.28.197.94:8101:0,172.28.197.94:8102:0,";
        }
        // -sgxbutil::my_ip() is executed by butil (in brpc)
        // -FLAGS_port is from user command line 
        sgxbutil::EndPoint addr(sgxbutil::my_ip(), FLAGS_port);
        braft::NodeOptions node_options;
        // -FLAGS_conf stores the information of all group members in "IP + Port" manner
        // -parse_from(func) updates _peers(set<PeerId>) inside initial_conf(Configuration)
        if (node_options.initial_conf.parse_from(FLAGS_conf) != 0) {
            LOG(ERROR) << "Fail to parse configuration `" << FLAGS_conf << '\'';
            return -1;
        }
        // -see struct NodeOptions in "raft.h" for further info
        node_options.election_timeout_ms = FLAGS_election_timeout_ms;
        if (FLAGS_port == 8100) {
            node_options.election_timeout_ms = FLAGS_election_timeout_ms / 2;
        }
        node_options.fsm = this;
        node_options.node_owns_fsm = false;
        node_options.snapshot_interval_s = FLAGS_snapshot_interval;

        std::string null_path("null_path");

        /* Different log storage options 
        *  local: file-based storage without encryption
        *  encrypted_local: encrypted file-based storage with monotonic counters
        *  memory: in-memory storage
        */
        // std::string prefix_log_storage = "local://" + FLAGS_data_path;
        std::string prefix_log_storage = "encrypted_local://" + FLAGS_data_path;
        // std::string prefix_log_storage = "memory://" + FLAGS_data_path;
        node_options.log_uri = prefix_log_storage + "/log";

        std::string prefix = "local://" + FLAGS_data_path;
        node_options.raft_meta_uri = prefix + "/raft_meta";
        node_options.snapshot_uri = prefix + "/snapshot";
        node_options.disable_cli = FLAGS_disable_cli;
        braft::Node* node = new braft::Node(FLAGS_group, braft::PeerId(addr));
        if (node->init(node_options) != 0) {
            LOG(ERROR) << "Fail to init raft node";
            delete node;
            return -1;
        }
        _node = node;
        return 0;
    }

    // Impelements Service methods
    void store_kv_item(const KVStoreRequest* request,
                   KVResponse* response,
                   google::protobuf::Closure* done) {
        VLOG(78) << "[KVE-enclave]Received store request from AKM enclave, key = " << request->key() << " value = (not printed here)";
        brpc::ClosureGuard done_guard(done);

        // Recovery debugging, print all the kv
        // VLOG(79) << "Current KV store:";
        // for (auto it = _store.begin(); it != _store.end(); it++) {
        //     VLOG(79) << "Key = " << it->first << " Value = " << std::string(it->second.begin(), it->second.end());
        // }

        // Serialize request to the replicated write-ahead-log so that all the
        // peers in the group receive this request as well.
        // Notice that _value can't be modified in this routine otherwise it
        // will be inconsistent with others in this group.
        
        // Serialize request to IOBuf
        const int64_t term = _leader_term.load(sgxbutil::memory_order_relaxed);
        if (term < 0) {
            return redirect(response);
        }
        sgxbutil::IOBuf log;
        sgxbutil::IOBufAsZeroCopyOutputStream wrapper(&log);
        if (!request->SerializeToZeroCopyStream(&wrapper)) {
            LOG(ERROR) << "Fail to serialize request";
            response->set_success(false);
            return;
        }
        // Apply this log as a braft::Task
        braft::Task task;
        task.data = &log;
        // This callback would be iovoked when the task actually excuted or
        // fail
        task.done = new StoreKVClosure(this, request, response,
                                        done_guard.release());
        if (FLAGS_check_term) {
            // ABA problem can be avoid if expected_term is set
            task.expected_term = term;
        }
        // Now the task is applied to the group, waiting for the result.
        return _node->apply(task);
    }

    void load_kv_item(const KVLoadRequest* request, KVResponse* response) {
        VLOG(78) << "[KVE-enclave]Received load request from AKM enclave, key = " << request->key();
        if (!is_leader()) {
            // This node is a follower or it's not up-to-date. Redirect to
            // the leader if possible.
            return redirect(response);
        }
        // This is the leader and is up-to-date. It's safe to respond client
        response->set_success(true);
        std::string key = request->key();
        pthread_mutex_lock(&_store_mutex);
        std::vector<uint8_t> value = _store[key];
        pthread_mutex_unlock(&_store_mutex);
        response->set_value(std::string(value.begin(), value.end()));
    }

    bool is_leader() const 
    { return _leader_term.load(sgxbutil::memory_order_acquire) > 0; }

    // Shut this node down.
    void shutdown() {
        if (_node) {
            _node->shutdown(NULL);
        }
    }

    // Blocking this thread until the node is eventually down.
    void join() {
        if (_node) {
            _node->join();
        }
    }

private:
friend class StoreKVClosure;
friend class LocalKVStoreReqHandler;

    void redirect(KVResponse* response) {
        response->set_success(false);
        if (_node) {
            braft::PeerId leader = _node->leader_id();
            if (!leader.is_empty()) {
                response->set_redirect(leader.to_string());
            }
        }
    }

    // @braft::StateMachine
    void on_apply(braft::Iterator& iter) {
        // A batch of tasks are committed, which must be processed through 
        // |iter|
        for (; iter.valid(); iter.next()) {
            std::string key;
            std::vector<uint8_t> value;
            KVResponse* response = NULL;
            // This guard helps invoke iter.done()->Run() asynchronously to
            // avoid that callback blocks the StateMachine.
            braft::AsyncClosureGuard closure_guard(iter.done());
            if (iter.done()) {
                // This task is applied by this node, get value from this
                // closure to avoid additional parsing.
                StoreKVClosure* c = dynamic_cast<StoreKVClosure*>(iter.done());
                response = c->response();
                key = c->request()->key();
                std::string value_str = c->request()->value();
                value = std::vector<uint8_t>(value_str.begin(), value_str.end());
            } else {
                // Have to parse request from this log.
                sgxbutil::IOBufAsZeroCopyInputStream wrapper(iter.data());
                KVStoreRequest request;
                CHECK(request.ParseFromZeroCopyStream(&wrapper));
                key = request.key();
                std::string value_str = request.value();
                value = std::vector<uint8_t>(value_str.begin(), value_str.end());
            }

            // Now the log has been parsed. Update this state machine by this
            // operation.
            pthread_mutex_lock(&_store_mutex);
            _store[key] = value;
            std::string value_str = std::string(_store[key].begin(), _store[key].end());
            pthread_mutex_unlock(&_store_mutex);
            if (response) {
                response->set_success(true);
                response->set_value(value_str);
            }
            LOG_IF(ERROR, FLAGS_log_applied_task) 
                    << "Key = " << key << " value = (not printed)" << " at log_index=" << iter.index();
        }
    }

    struct SnapshotArg {
        int64_t value;
        braft::SnapshotWriter* writer;
        braft::Closure* done;
    };

    // TODO: snapshot related functions
    // static void *save_snapshot(void* arg) {
    //     SnapshotArg* sa = (SnapshotArg*) arg;
    //     std::unique_ptr<SnapshotArg> arg_guard(sa);
    //     // Serialize StateMachine to the snapshot
    //     brpc::ClosureGuard done_guard(sa->done);
    //     std::string snapshot_path = sa->writer->get_path() + "/data";
    //     LOG(INFO) << "Saving snapshot to " << snapshot_path;
    //     // Use protobuf to store the snapshot for backward compatibility.
    //     Snapshot s;
    //     s.set_value(sa->value);
    //     braft::ProtoBufFile pb_file(snapshot_path);
    //     if (pb_file.save(&s, true) != 0)  {
    //         sa->done->status().set_error(EIO, "Fail to save pb_file");
    //         return NULL;
    //     }
    //     // Snapshot is a set of files in raft. Add the only file into the
    //     // writer here.
    //     if (sa->writer->add_file("data") != 0) {
    //         sa->done->status().set_error(EIO, "Fail to add file to writer");
    //         return NULL;
    //     }
    //     return NULL;
    // }

    // void on_snapshot_save(braft::SnapshotWriter* writer, braft::Closure* done) {
    //     // Save current StateMachine in memory and starts a new bthread to avoid
    //     // blocking StateMachine since it's a bit slow to write data to disk
    //     // file.
    //     SnapshotArg* arg = new SnapshotArg;
    //     arg->value = _value.load(sgxbutil::memory_order_relaxed);
    //     arg->writer = writer;
    //     arg->done = done;
    //     bthread_t tid;
    //     bthread_start_urgent(&tid, NULL, save_snapshot, arg);
    // }

    // int on_snapshot_load(braft::SnapshotReader* reader) {
    //     // Load snasphot from reader, replacing the running StateMachine
    //     CHECK(!is_leader()) << "Leader is not supposed to load snapshot";
    //     if (reader->get_file_meta("data", NULL) != 0) {
    //         LOG(ERROR) << "Fail to find `data' on " << reader->get_path();
    //         return -1;
    //     }
    //     std::string snapshot_path = reader->get_path() + "/data";
    //     braft::ProtoBufFile pb_file(snapshot_path);
    //     Snapshot s;
    //     if (pb_file.load(&s) != 0) {
    //         LOG(ERROR) << "Fail to load snapshot from " << snapshot_path;
    //         return -1;
    //     }
    //     _value.store(s.value(), sgxbutil::memory_order_relaxed);
    //     return 0;
    // }

    void on_leader_start(int64_t term) {
        _leader_term.store(term, sgxbutil::memory_order_release);
        LOG(INFO) << "Node becomes leader";
    }
    void on_leader_stop(const sgxbutil::Status& status) {
        _leader_term.store(-1, sgxbutil::memory_order_release);
        LOG(INFO) << "Node stepped down : " << status;
    }

    void on_shutdown() {
        LOG(INFO) << "This node is down";
    }
    void on_error(const ::braft::Error& e) {
        LOG(ERROR) << "Met raft error " << e;
    }
    void on_configuration_committed(const ::braft::Configuration& conf) {
        LOG(INFO) << "Configuration of this group is " << conf;
    }
    void on_stop_following(const ::braft::LeaderChangeContext& ctx) {
        LOG(INFO) << "Node stops following " << ctx;
    }
    void on_start_following(const ::braft::LeaderChangeContext& ctx) {
        LOG(INFO) << "Node start following " << ctx;
    }
    // end of @braft::StateMachine

private:
    braft::Node* volatile _node;
    sgxbutil::atomic<int64_t> _leader_term;
    // Add a kv store variable, key is string, value is vector of uint8_t
    std::map<std::string, std::vector<uint8_t>> _store;
    pthread_mutex_t _store_mutex = PTHREAD_MUTEX_INITIALIZER;
};

void StoreKVClosure::Run() {
    // Auto delete this after Run()
    std::unique_ptr<StoreKVClosure> self_guard(this);
    // Repsond this RPC.
    brpc::ClosureGuard done_guard(_done);
    if (status().ok()) {
        return;
    }
    // Try redirect if this request failed.
    _kv_store->redirect(_response);
}


class KVStoreServiceImpl : public KVStoreService {
public:
    explicit KVStoreServiceImpl(KV_Store* kvs) : _kv_store(kvs) {}
    void store_kv_item(google::protobuf::RpcController* controller,
                               const KVStoreRequest* request,
                               KVResponse* response,
                               google::protobuf::Closure* done) {
        return _kv_store->store_kv_item(request, response, done);
    }
    void load_kv_item(google::protobuf::RpcController* controller,
                               const KVLoadRequest* request,
                               KVResponse* response,
                               google::protobuf::Closure* done) {
        brpc::ClosureGuard done_guard(done);                                
        return _kv_store->load_kv_item(request, response);
    }

private:
    KV_Store* _kv_store;
};

// Create a new class that processes the local AKM enclave's request
class LocalKVStoreReqHandler {
public:
    LocalKVStoreReqHandler() {}
    ~LocalKVStoreReqHandler() {}

    int handle_req_from_akme(uint8_t* encrypted_req, int enc_req_sz, uint8_t* encrypted_resp, int enc_resp_sz, int* ret_enc_resp_sz);
    int check_and_remove_nonce(uint64_t nonce);
    int send_store_request(std::string key, std::string value);
    int send_load_request(std::string key, std::string* value);
    void refresh_raft_leader() {_leader = _kvs_inst->_node->leader_id();}
    void set_kvs_inst(KV_Store* kvs) {_kvs_inst = kvs;}
    bool kve_server_is_up();

private:
    KV_Store* _kvs_inst = NULL;
    std::set<uint64_t> _nonce_set; // Maintain a nonce set
    braft::PeerId _leader;
    int _network_timeout = 1000;
};

bool LocalKVStoreReqHandler::kve_server_is_up() {
    // Before handling store/load kv requests, we need to check if the kve server is up
    return _kvs_inst == NULL ? false : true;
}

int LocalKVStoreReqHandler::send_store_request(std::string key, std::string value) {
    while(true) {
        refresh_raft_leader();
        KVStoreRequest req;
        KVResponse resp;
        req.set_key(key);
        req.set_value(value);
        brpc::Channel channel;
        brpc::ChannelOptions options;
        options.mutable_ssl_options();
        options.connection_type = brpc::CONNECTION_TYPE_SINGLE;
        if (channel.Init(_leader.addr, &options) != 0) {
            LOG(ERROR) << "Fail to init channel to " << _leader;
            bthread_usleep(_network_timeout * 1000L);
        }
        kv_enclave::KVStoreService_Stub stub(&channel);
        brpc::Controller cntl;
        cntl.set_timeout_ms(_network_timeout);
        // If leader is the current node, it is totally fine to send the request to itself
        stub.store_kv_item(&cntl, &req, &resp, NULL);
        if (cntl.Failed()) {
            LOG(ERROR) << "Fail to send request to " << _leader
                    << " : " << cntl.ErrorText();
            bthread_usleep(_network_timeout * 1000L);
            continue;
        }
        if (!resp.success()) {
            LOG(ERROR) << "Fail to store key = " << key << " to " << _leader;
            bthread_usleep(_network_timeout * 1000L);
            continue;
        }
        break;
    }
    return 0;
}

int LocalKVStoreReqHandler::send_load_request(std::string key, std::string* value) {
    while(true) {
        refresh_raft_leader();
        if(_kvs_inst->is_leader()) {
            // If current node is the leader, then store the key-value pair
            pthread_mutex_lock(&_kvs_inst->_store_mutex);
            *value = std::string(_kvs_inst->_store[key].begin(), _kvs_inst->_store[key].end());
            pthread_mutex_unlock(&_kvs_inst->_store_mutex);
            break;
        }
        KVLoadRequest req;
        KVResponse resp;
        req.set_key(key);
        brpc::Channel channel;
        brpc::ChannelOptions options;
        options.mutable_ssl_options();
        options.connection_type = brpc::CONNECTION_TYPE_SINGLE;
        if (channel.Init(_leader.addr, &options) != 0) {
            LOG(ERROR) << "Fail to init channel to " << _leader;
            bthread_usleep(_network_timeout * 1000L);
        }
        kv_enclave::KVStoreService_Stub stub(&channel);
        brpc::Controller cntl;
        cntl.set_timeout_ms(_network_timeout);
        stub.load_kv_item(&cntl, &req, &resp, NULL);
        if (cntl.Failed()) {
            LOG(ERROR) << "Fail to send request to " << _leader
                    << " : " << cntl.ErrorText();
            bthread_usleep(_network_timeout * 1000L);
            continue;
        }
        if (!resp.success()) {
            LOG(ERROR) << "Fail to load key = " << key << " from " << _leader;
            bthread_usleep(_network_timeout * 1000L);
            continue;
        }
        *value = resp.value();
        break;
    }
    return 0;
}

int LocalKVStoreReqHandler::check_and_remove_nonce(uint64_t nonce) {
    // The nonce should be in the nonce set, otherwise, deemed as replay attack
    if (_nonce_set.find(nonce) == _nonce_set.end()) {
        LOG(ERROR) << "Error: nonce not found";
        return -1;
    }
    _nonce_set.erase(nonce);
    return 0;
}

int LocalKVStoreReqHandler::handle_req_from_akme(uint8_t* encrypted_req, int enc_req_sz, uint8_t* encrypted_resp, int enc_resp_sz, int* ret_enc_resp_sz) {
    // 1.Decryption
    uint8_t** req = (uint8_t**)malloc(sizeof(uint8_t*));
    size_t req_sz = 0;
    kve_dispatcher.decrypt_data_from_akme(encrypted_req, enc_req_sz, req, &req_sz);
    // LOG(INFO) << "[KVE-enclave]Decrypted request with size = " << req_sz;
    
    // debug_util_print_buffer(*req, req_sz);
    // 2.Read protobuf back from req, and process
    AKMEnclaveRequest akm_req;
    akm_req.ParseFromArray(*req, req_sz);
    KVEnclaveResponse resp;
    VLOG(78) << "[KVE-enclave]Received request from AKM enclave, type = " << akm_req.req_type() << " all require fields: " << akm_req.req_type() << " " << akm_req.akme_nonce() << " " << akm_req.kve_nonce();
    if (akm_req.req_type() == "get_nonce") {
        // Genearte a new nonce and insert to the nonce set
        uint64_t nonce = sgxbutil::generate_nonce_u64();
        _nonce_set.insert(nonce);
        // LOG(INFO) << "[KVE-enclave]Generated nonce = " << nonce;
        VLOG(78) << "[KVE-enclave]Generated nonce = " << nonce;
        resp.set_success(true);
        resp.set_akme_nonce(akm_req.akme_nonce());
        resp.set_kve_nonce(nonce);
    } else if (akm_req.req_type() == "store_kv") {
        if (check_and_remove_nonce(akm_req.kve_nonce()) != 0) {
            LOG(ERROR) << "Error: nonce check failed";
            return -1;
        }
        VLOG(78) << "nonce check passed";
        while (!kve_server_is_up()) {
            LOG(ERROR) << "Error: kve server is not up";
            bthread_usleep(3000000L); // 3 seconds
        }
        // Store the key-value pair
        std::string key = akm_req.key();
        std::string value = akm_req.value();
        if (send_store_request(key, value) != 0) {
            LOG(ERROR) << "Error: send store request failed";
            resp.set_success(false);
        } else {
            resp.set_success(true);
        }
        resp.set_akme_nonce(akm_req.akme_nonce());
        resp.set_kve_nonce(akm_req.kve_nonce());
    } else if (akm_req.req_type() == "load_kv") {
        if (check_and_remove_nonce(akm_req.kve_nonce()) != 0) {
            LOG(ERROR) << "Error: nonce check failed";
            return -1;
        }
        // Load the key-value pair
        std::string key = akm_req.key();
        std::string value;
        if (send_load_request(key, &value) != 0) {
            LOG(ERROR) << "Error: send load request failed";
            resp.set_success(false);
        } else {
            resp.set_success(true);
            resp.set_value(value);
            VLOG(78) << " value.size = " << value.size();
        }
        resp.set_akme_nonce(akm_req.akme_nonce());
        resp.set_kve_nonce(akm_req.kve_nonce());
    } else {
        LOG(ERROR) << "Error: unknown request type: " << akm_req.req_type();
        return -1;
    }

    // 3.Serialize protobuf and encrypt
    size_t resp_sz = resp.ByteSize();
    uint8_t* resp_buf = (uint8_t*)malloc(resp_sz);
    resp.SerializeToArray(resp_buf, resp_sz);
    uint8_t** encrypt_buf = (uint8_t**)malloc(sizeof(uint8_t*));
    size_t encrypt_sz = 0;
    kve_dispatcher.encrypt_data_to_akme(resp_buf, resp_sz, encrypt_buf, &encrypt_sz);
    // LOG(INFO) << "[KVE-enclave]Encrypted response with size = " << encrypt_sz;
    *ret_enc_resp_sz = encrypt_sz;
    memcpy(encrypted_resp, *encrypt_buf, encrypt_sz);

    // Free memory
    free(req);
    free(resp_buf);
    free(encrypt_buf);
    return 0;
}


}  // namespace kv_enclave

void start_kve_server(int port) {
    FLAGS_port = port;
    sgxbutil::AtExitManager exit_manager;

    // Generally you only need one Server.
    brpc::Server server;
    kv_enclave::KV_Store kvs_inst;
    kv_enclave::KVStoreServiceImpl kvs_service(&kvs_inst);

    // Add your service into RPC server
    if (server.AddService(&kvs_service, 
                          brpc::SERVER_DOESNT_OWN_SERVICE) != 0) {
        LOG(ERROR) << "Fail to add kvs service";
        return ;
    }

    sgxbutil::EndPoint self_addr(sgxbutil::my_ip(), FLAGS_port);
    sgxbutil::StateContServiceImpl st_service(self_addr);
    if (server.AddService(&st_service, 
                          brpc::SERVER_DOESNT_OWN_SERVICE) != 0) {
        LOG(ERROR) << "Fail to add state continuity service";
        return ;
    }
    // raft can share the same RPC server. Notice the second parameter, because
    // adding services into a running server is not allowed and the listen
    // address of this server is impossible to get before the server starts. You
    // have to specify the address of the server.
    if (braft::add_service(&server, FLAGS_port) != 0) {
        LOG(ERROR) << "Fail to add raft service";
        return ;
    }

    brpc::ServerOptions options;
    // options.has_builtin_services = false;
    // options.num_threads = 9;
    options.mutable_ssl_options();
#ifndef SGX_USE_REMOTE_ATTESTATION    
    options.mutable_ssl_options()->default_cert.certificate = "cert.pem";
    options.mutable_ssl_options()->default_cert.private_key = "key.pem";
#endif
    if (server.Start(FLAGS_port, &options) != 0) {
        LOG(ERROR) << "Fail to start Server";
        return ;
    }

    // It's ok to start kve;
    if (kvs_inst.start() != 0) {
        LOG(ERROR) << "Fail to start kv enclave";
        return ;
    }

    LOG(INFO) << "KV Enclave service is running on " << server.listen_address();

    // if (port == 8100) { // testing
    if (local_req_handler == NULL) {
        LOG(ERROR) << "Error: local_req_handler is NULL";
        return;
    }
    kv_enclave::LocalKVStoreReqHandler* kvs_handler = (kv_enclave::LocalKVStoreReqHandler*)local_req_handler;
    kvs_handler->set_kvs_inst(&kvs_inst);
    // }

    // Wait until 'CTRL-C' is pressed. then Stop() and Join() the service
    while (!brpc::IsAskedToQuit()) {
        sleep(2);
        LOG(INFO) << "KV Enclave server wakes up.";
    }
    LOG(INFO) << "KV Enclave server is going to quit";
    server.Stop(0);
    // Wait until all the processing tasks are over.
    server.Join();
    return ;
}

void enclave_handle_local_kv_req(uint8_t* encrypted_req, int enc_req_sz, uint8_t* encrypted_resp, int enc_resp_sz, int* ret_enc_resp_sz) {
    VLOG(78) << "Enclave handle local kv request, enc_req_sz = " << enc_req_sz;

    // debug_util_print_buffer(__FILE__, __FUNCTION__, __LINE__, encrypted_req, enc_req_sz);

    kv_enclave::LocalKVStoreReqHandler* handler = (kv_enclave::LocalKVStoreReqHandler*)local_req_handler;
    if (handler == NULL) {
        LOG(ERROR) << "Error: local_req_handler is NULL";
        return;
    }
    handler->handle_req_from_akme(encrypted_req, enc_req_sz, encrypted_resp, enc_resp_sz, ret_enc_resp_sz);
}

// A temporary workaround for the enclave to setup the local request handler
void kve_setup_local_req_handler() {
    local_req_handler = (void*)new kv_enclave::LocalKVStoreReqHandler();
}