#include "main/libnngio_main.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Helper: sleep for a short time (ms) for connect
#ifdef _WIN32
#include <windows.h>
#define sleep_ms(ms) Sleep(ms)
#else
#include <unistd.h>
#define sleep_ms(ms) usleep((ms) * 1000)
#endif

void test_tcp_basic() {
    libnngio_ctx *server = NULL, *client = NULL;
    libnngio_config server_cfg = {0}, client_cfg = {0};
    const char *url = "tcp://127.0.0.1:5555";
    char msg[256] = {0};
    size_t msglen;
    int rv;

    server_cfg.mode = LIBNNGIO_MODE_LISTEN;
    server_cfg.proto = LIBNNGIO_PROTO_PAIR;
    server_cfg.url = url;

    client_cfg.mode = LIBNNGIO_MODE_DIAL;
    client_cfg.proto = LIBNNGIO_PROTO_PAIR;
    client_cfg.url = url;

    // Server setup
    rv = libnngio_init(&server, &server_cfg);
    assert(rv == 0);

    // Client setup
    rv = libnngio_init(&client, &client_cfg);
    assert(rv == 0);

    // Allow time for connection
    sleep_ms(100);

    // Communication
    const char *hello = "hello-tcp";
    rv = libnngio_send(client, hello, strlen(hello) + 1);
    assert(rv == 0);

    msglen = sizeof(msg);
    rv = libnngio_recv(server, msg, &msglen);
    assert(rv == 0 && strcmp(msg, hello) == 0);

    libnngio_free(client);
    libnngio_free(server);
    printf("TCP test PASSED\n");
}

void test_tls_basic() {
    libnngio_ctx *server = NULL, *client = NULL;
    libnngio_config server_cfg = {0}, client_cfg = {0};
    const char *url = "tls+tcp://127.0.0.1:5556";
    char msg[256] = {0};
    size_t msglen;
    int rv;

    // Paths to PEM files (update as appropriate)
    const char *cert = "test_certs/server.crt";
    const char *key  = "test_certs/server.key";
    const char *ca   = "test_certs/dev-ca.pem";

    // Server config
    server_cfg.mode = LIBNNGIO_MODE_LISTEN;
    server_cfg.proto = LIBNNGIO_PROTO_PAIR;
    server_cfg.url = url;
    server_cfg.tls_cert = cert;
    server_cfg.tls_key  = key;
    server_cfg.tls_ca_cert = ca;

    // Client config
    client_cfg.mode = LIBNNGIO_MODE_DIAL;
    client_cfg.proto = LIBNNGIO_PROTO_PAIR;
    client_cfg.url = url;
    client_cfg.tls_ca_cert = ca;

    rv = libnngio_init(&server, &server_cfg);
    assert(rv == 0);

    rv = libnngio_init(&client, &client_cfg);
    assert(rv == 0);

    // Allow time for TLS handshake
    sleep_ms(100);

    const char *hello = "hello-tls";
    rv = libnngio_send(client, hello, strlen(hello) + 1);
    assert(rv == 0);

    msglen = sizeof(msg);
    rv = libnngio_recv(server, msg, &msglen);
    assert(rv == 0 && strcmp(msg, hello) == 0);

    libnngio_free(client);
    libnngio_free(server);
    printf("TLS test PASSED\n");
}

// ---------- ASYNC TESTING SUPPORT -----------
typedef struct {
    volatile int done;
    int result;
    char buf[256];
    size_t len;
} async_test_sync;

void async_recv_cb(libnngio_ctx *ctx, int result, void *data, size_t len, void *user_data) {
    async_test_sync *sync = (async_test_sync *)user_data;
    if (result == 0 && data && len <= sizeof(sync->buf)) {
        memcpy(sync->buf, data, len);
        sync->len = len;
    } else {
        sync->len = 0;
    }
    sync->result = result;
    sync->done = 1;
}

void async_send_cb(libnngio_ctx *ctx, int result, void *data, size_t len, void *user_data) {
    async_test_sync *sync = (async_test_sync *)user_data;
    sync->result = result;
    sync->done = 1;
}

void test_tcp_async() {
    libnngio_ctx *server = NULL, *client = NULL;
    libnngio_config server_cfg = {0}, client_cfg = {0};
    const char *url = "tcp://127.0.0.1:5557";
    int rv;

    server_cfg.mode = LIBNNGIO_MODE_LISTEN;
    server_cfg.proto = LIBNNGIO_PROTO_PAIR;
    server_cfg.url = url;

    client_cfg.mode = LIBNNGIO_MODE_DIAL;
    client_cfg.proto = LIBNNGIO_PROTO_PAIR;
    client_cfg.url = url;

    rv = libnngio_init(&server, &server_cfg);
    assert(rv == 0);

    rv = libnngio_init(&client, &client_cfg);
    assert(rv == 0);

    sleep_ms(100);

    const char *hello = "hello-tcp-async";
    async_test_sync send_sync = {0}, recv_sync = {0};

    recv_sync.len = sizeof(recv_sync.buf);
    rv = libnngio_recv_async(server, recv_sync.buf, &recv_sync.len, async_recv_cb, &recv_sync);
    assert(rv == 0);

    rv = libnngio_send_async(client, hello, strlen(hello) + 1, async_send_cb, &send_sync);
    assert(rv == 0);

    // Wait for send to finish
    while (!send_sync.done) { sleep_ms(1); }
    assert(send_sync.result == 0);

    // Wait for recv to finish
    while (!recv_sync.done) { sleep_ms(1); }
    assert(recv_sync.result == 0);
    assert(strcmp(recv_sync.buf, hello) == 0);

    libnngio_free(client);
    libnngio_free(server);
    printf("TCP async test PASSED\n");
}

void test_tls_async() {
    libnngio_ctx *server = NULL, *client = NULL;
    libnngio_config server_cfg = {0}, client_cfg = {0};
    const char *url = "tls+tcp://127.0.0.1:5558";
    int rv;

    // Paths to PEM files (update as appropriate)
    const char *cert = "test_certs/server.crt";
    const char *key  = "test_certs/server.key";
    const char *ca   = "test_certs/dev-ca.pem";

    server_cfg.mode = LIBNNGIO_MODE_LISTEN;
    server_cfg.proto = LIBNNGIO_PROTO_PAIR;
    server_cfg.url = url;
    server_cfg.tls_cert = cert;
    server_cfg.tls_key = key;
    server_cfg.tls_ca_cert = ca;

    client_cfg.mode = LIBNNGIO_MODE_DIAL;
    client_cfg.proto = LIBNNGIO_PROTO_PAIR;
    client_cfg.url = url;
    client_cfg.tls_ca_cert = ca;

    rv = libnngio_init(&server, &server_cfg);
    assert(rv == 0);

    rv = libnngio_init(&client, &client_cfg);
    assert(rv == 0);

    sleep_ms(100);

    const char *hello = "hello-tls-async";
    async_test_sync send_sync = {0}, recv_sync = {0};

    recv_sync.len = sizeof(recv_sync.buf);
    rv = libnngio_recv_async(server, recv_sync.buf, &recv_sync.len, async_recv_cb, &recv_sync);
    assert(rv == 0);

    rv = libnngio_send_async(client, hello, strlen(hello) + 1, async_send_cb, &send_sync);
    assert(rv == 0);

    while (!send_sync.done) { sleep_ms(1); }
    assert(send_sync.result == 0);

    while (!recv_sync.done) { sleep_ms(1); }
    assert(recv_sync.result == 0);
    assert(strcmp(recv_sync.buf, hello) == 0);

    libnngio_free(client);
    libnngio_free(server);
    printf("TLS async test PASSED\n");
}

int main() {
    // Register cleanup for global NNG state
    atexit(libnngio_cleanup);

    test_tcp_basic();
    test_tls_basic();
    test_tcp_async();
    test_tls_async();
    return 0;
}
