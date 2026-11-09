#include "hsm_host.h"
#include "edge/edge_call.h"
#include "host/keystone.h"
#include <cstring>
#include <cstdio>
#include <pthread.h>

static Keystone::Enclave* g_enclave = nullptr;
static pthread_t g_worker_thread;
static int g_running = 0;

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_req_ready = PTHREAD_COND_INITIALIZER;
static pthread_cond_t  g_resp_ready = PTHREAD_COND_INITIALIZER;

static hsm_req_t  g_pending_req;
static hsm_resp_t g_pending_resp;
static int g_has_request = 0;
static int g_has_response = 0;
static int g_first_call = 1;

static void bridge_dispatch(void* buffer) {
    struct edge_call* edge_call = (struct edge_call*)buffer;
    uintptr_t call_args;
    size_t arg_len;

    pthread_mutex_lock(&g_mutex);

    if (edge_call_args_ptr(edge_call, &call_args, &arg_len) == 0 &&
        arg_len >= sizeof(hsm_resp_t)) {
        memcpy(&g_pending_resp, (void*)call_args, sizeof(hsm_resp_t));
    } else {
        memset(&g_pending_resp, 0, sizeof(hsm_resp_t));
        g_pending_resp.status = HSM_STATUS_READY;
    }

    if (!g_first_call) {
        g_has_response = 1;
        pthread_cond_signal(&g_resp_ready);
    }
    g_first_call = 0;

    while (!g_has_request && g_running) {
        pthread_cond_wait(&g_req_ready, &g_mutex);
    }

    hsm_req_t req;
    if (g_has_request) {
        memcpy(&req, &g_pending_req, sizeof(hsm_req_t));
        g_has_request = 0;
    } else {
        memset(&req, 0, sizeof(hsm_req_t));
        req.cmd_id = HSM_CMD_SHUTDOWN;
    }

    pthread_mutex_unlock(&g_mutex);

    uintptr_t data_section = edge_call_data_ptr();
    memcpy((void*)data_section, &req, sizeof(hsm_req_t));

    if (edge_call_setup_ret(edge_call, (void*)data_section, sizeof(hsm_req_t))) {
        edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
    } else {
        edge_call->return_data.call_status = CALL_STATUS_OK;
    }
}

static void* enclave_worker(void* arg) {
    (void)arg;
    uintptr_t encl_ret = 0;
    g_enclave->run(&encl_ret);
    pthread_mutex_lock(&g_mutex);
    g_running = 0;
    g_has_response = 1;
    g_pending_resp.status = HSM_STATUS_ERR_GENERAL;
    pthread_cond_signal(&g_resp_ready);
    pthread_mutex_unlock(&g_mutex);
    return nullptr;
}

extern "C" int hsm_host_init(const char* eapp_path, const char* runtime_path) {
    if (g_running) return -1;

    g_enclave = new Keystone::Enclave();
    Keystone::Params params;
    params.setFreeMemSize(256 * 1024);
    params.setUntrustedMem(DEFAULT_UNTRUSTED_PTR, 64 * 1024);

    if (g_enclave->init(eapp_path, runtime_path, params) != Keystone::Error::Success) {
        fprintf(stderr, "[hsm_host] Could not initialize Keystone Enclave\n");
        delete g_enclave;
        g_enclave = nullptr;
        return -1;
    }

    g_enclave->registerOcallDispatch(incoming_call_dispatch);
    register_call(OCALL_HSM_DISPATCH, bridge_dispatch);
    edge_call_init_internals(
        (uintptr_t)g_enclave->getSharedBuffer(),
        g_enclave->getSharedBufferSize());

    g_running = 1;
    g_first_call = 1;
    g_has_request = 0;
    g_has_response = 0;

    if (pthread_create(&g_worker_thread, nullptr, enclave_worker, nullptr) != 0) {
        fprintf(stderr, "[hsm_host] Failed to create worker thread\n");
        delete g_enclave;
        g_enclave = nullptr;
        g_running = 0;
        return -1;
    }

    return 0;
}

extern "C" int hsm_host_send_command(const hsm_req_t* req, hsm_resp_t* resp) {
    if (!g_running || !req || !resp) return -1;

    pthread_mutex_lock(&g_mutex);

    memcpy(&g_pending_req, req, sizeof(hsm_req_t));
    g_has_request = 1;
    g_has_response = 0;
    pthread_cond_signal(&g_req_ready);

    while (!g_has_response) {
        pthread_cond_wait(&g_resp_ready, &g_mutex);
    }
    g_has_response = 0;

    memcpy(resp, &g_pending_resp, sizeof(hsm_resp_t));
    pthread_mutex_unlock(&g_mutex);

    return 0;
}

extern "C" int hsm_host_destroy(void) {
    if (!g_running) return 0;

    hsm_req_t shutdown_req;
    memset(&shutdown_req, 0, sizeof(hsm_req_t));
    shutdown_req.cmd_id = HSM_CMD_SHUTDOWN;

    pthread_mutex_lock(&g_mutex);
    memcpy(&g_pending_req, &shutdown_req, sizeof(hsm_req_t));
    g_has_request = 1;
    pthread_cond_signal(&g_req_ready);
    pthread_mutex_unlock(&g_mutex);

    pthread_join(g_worker_thread, nullptr);

    delete g_enclave;
    g_enclave = nullptr;
    g_running = 0;
    return 0;
}
