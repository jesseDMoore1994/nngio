/**
 * @file test_main.c
 * @brief Unit tests for libnngio transport and context functionalities.
 *      Tests include TCP and TLS transports, synchronous and asynchronous
 *      operations, and various messaging patterns (REQ/REP, PUB/SUB,
 * PUSH/PULL). Uses assertions to validate expected behaviors. Tests can be run
 * with or without mocking support. Compile with -DNNGIO_MOCK_MAIN to enable
 * mocking.
 */

#include <assert.h>
#include <nng/nng.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "main/libnngio_main.h"

/**
 * @brief Sleep for specified milliseconds.
 */
#define sleep_ms(ms) usleep((ms) * 1000)

/**
 * @brief Basic TCP transport test: server listens, client dials, sends and
 *        receives a message.
 */
void test_tcp_basic() {
  libnngio_transport *server = NULL, *client = NULL;
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

  libnngio_log(
      "INF", "TEST_TCP_BASIC", __FILE__, __LINE__, -1,
      "Starting TCP basic test: server listening on %s, client dialing.", url);

  // Server setup
  rv = libnngio_transport_init(&server, &server_cfg);
  assert(rv == 0);

  // Client setup
  rv = libnngio_transport_init(&client, &client_cfg);
  assert(rv == 0);

  libnngio_log("INF", "TEST_TCP_BASIC", __FILE__, __LINE__, -1,
               "Transports initialized successfully.");

  libnngio_log("INF", "TEST_TCP_BASIC", __FILE__, __LINE__, -1,
               "Initializing contexts.");

  libnngio_context *server_ctx = NULL, *client_ctx = NULL;
  rv = libnngio_context_init(&server_ctx, server, &server_cfg, NULL, NULL);
  assert(rv == 0);
  rv = libnngio_context_init(&client_ctx, client, &client_cfg, NULL, NULL);
  assert(rv == 0);

  libnngio_log("INF", "TEST_TCP_BASIC", __FILE__, __LINE__, -1,
               "context for client initialized successfully.");

  libnngio_log("INF", "TEST_TCP_BASIC", __FILE__, __LINE__, -1,
               "Contexts initialized successfully.");

  // Allow time for connection
  sleep_ms(100);

  // Communication
  const char *hello = "hello-tcp";
  rv = libnngio_context_send(client_ctx, hello, strlen(hello) + 1);
  assert(rv == 0);
#ifdef NNGIO_MOCK_MAIN
  // Validate mock send
  assert(mock_stats.last_send.ctx == client_ctx);
  assert(mock_stats.last_send.buf == hello);
  assert(mock_stats.last_send.len == strlen(hello) + 1);
#endif

  msglen = sizeof(msg);
#ifdef NNGIO_MOCK_MAIN
  // Mocking: set expected receive buffer
  libnngio_mock_set_recv_buffer(hello, strlen(hello) + 1);
#endif
  rv = libnngio_context_recv(server_ctx, msg, &msglen);
  assert(rv == 0 && strcmp(msg, hello) == 0);

  libnngio_context_free(client_ctx);
  libnngio_context_free(server_ctx);

  libnngio_transport_free(client);
  libnngio_transport_free(server);

#ifdef NNGIO_MOCK_MAIN
  // Verify mock stats
  assert(mock_stats.init_calls == 2);
  assert(mock_stats.send_calls == 1);
  assert(mock_stats.recv_calls == 1);
  assert(mock_stats.free_calls == 2);
  assert(mock_stats.last_init_result == 0);
  assert(mock_stats.last_send_result == 0);
  assert(mock_stats.last_recv_result == 0);
  libnngio_log("INF", "TEST_TCP_BASIC", __FILE__, __LINE__, -1,
               "Mock stats verified successfully.");
  libnngio_mock_reset();
#endif  // NNGIO_MOCK_MAIN
  //
  libnngio_log("INF", "TEST_TCP_BASIC", __FILE__, __LINE__, -1,
               "TCP basic test completed successfully.");
}

/**
 * @brief Basic TLS transport test: server listens with TLS, client dials with
 TLS, sends and receives a message.
 */
void test_tls_basic() {
  libnngio_transport *server = NULL, *client = NULL;
  libnngio_config server_cfg = {0}, client_cfg = {0};
  const char *url = "tls+tcp://127.0.0.1:5556";
  char msg[256] = {0};
  size_t msglen;
  int rv;

  // Paths to PEM files (update as appropriate)
  const char *cert = "test_certs/server.crt";
  const char *key = "test_certs/server.key";
  const char *ca = "test_certs/dev-ca.pem";

  // Server config
  server_cfg.mode = LIBNNGIO_MODE_LISTEN;
  server_cfg.proto = LIBNNGIO_PROTO_PAIR;
  server_cfg.url = url;
  server_cfg.tls_cert = cert;
  server_cfg.tls_key = key;
  server_cfg.tls_ca_cert = ca;

  // Client config
  client_cfg.mode = LIBNNGIO_MODE_DIAL;
  client_cfg.proto = LIBNNGIO_PROTO_PAIR;
  client_cfg.url = url;
  client_cfg.tls_ca_cert = ca;

  rv = libnngio_transport_init(&server, &server_cfg);
  assert(rv == 0);

  rv = libnngio_transport_init(&client, &client_cfg);
  assert(rv == 0);

  libnngio_context *server_ctx = NULL, *client_ctx = NULL;
  rv = libnngio_context_init(&server_ctx, server, &server_cfg, NULL, NULL);
  assert(rv == 0);
  rv = libnngio_context_init(&client_ctx, client, &client_cfg, NULL, NULL);
  assert(rv == 0);

  // Allow time for TLS handshake
  sleep_ms(100);

  const char *hello = "hello-tls";
  rv = libnngio_context_send(client_ctx, hello, strlen(hello) + 1);
  assert(rv == 0);
#ifdef NNGIO_MOCK_MAIN
  // Validate mock send
  assert(mock_stats.last_send.ctx == client_ctx);
  assert(mock_stats.last_send.buf == hello);
  assert(mock_stats.last_send.len == strlen(hello) + 1);
  libnngio_mock_set_recv_buffer(hello, strlen(hello) + 1);
#endif
  msglen = sizeof(msg);
  rv = libnngio_context_recv(server_ctx, msg, &msglen);
  assert(rv == 0 && strcmp(msg, hello) == 0);

  libnngio_context_free(client_ctx);
  libnngio_context_free(server_ctx);

  libnngio_transport_free(client);
  libnngio_transport_free(server);

#ifdef NNGIO_MOCK_MAIN
  // Verify mock stats
  assert(mock_stats.init_calls == 2);
  assert(mock_stats.send_calls == 1);
  assert(mock_stats.recv_calls == 1);
  assert(mock_stats.free_calls == 2);
  assert(mock_stats.last_init_result == 0);
  assert(mock_stats.last_send_result == 0);
  assert(mock_stats.last_recv_result == 0);
  libnngio_log("INF", "TEST_TLS_BASIC", __FILE__, __LINE__, -1,
               "Mock stats verified successfully.");
  libnngio_mock_reset();
#endif  // NNGIO_MOCK_MAIN

  libnngio_log("INF", "TEST_TLS_BASIC", __FILE__, __LINE__, -1,
               "TLS basic test completed successfully.");
}

/**
 * @brief A simple structure to synchronize async test state.
 */
typedef struct {
  volatile int done; /**< Flag to indicate completion */
  int result;        /**< Result of the async operation */
  char buf[256];     /**< Buffer to hold received data */
  size_t len;        /**< Length of received data */
} async_test_sync;

/**
 * @brief Test async recv callback
 */
void async_recv_cb(libnngio_context *ctx, int result, void *data, size_t len,
                   void *user_data) {
  libnngio_log("INF", "TEST_ASYNC_RECV_CB", __FILE__, __LINE__, -1,
               "Async recv callback called with result=%d, len=%zu", result,
               len);
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

/**
 * @brief Test async send callback
 */
void async_send_cb(libnngio_context *ctx, int result, void *data, size_t len,
                   void *user_data) {
  libnngio_log("INF", "TEST_ASYNC_SEND_CB", __FILE__, __LINE__, -1,
               "Async send callback called with result=%d, len=%zu", result,
               len);
  async_test_sync *sync = (async_test_sync *)user_data;
  sync->result = result;
  sync->done = 1;
}

/**
 * @brief Test TCP transport with async send/recv
 */
void test_tcp_async() {
  libnngio_transport *server = NULL, *client = NULL;
  libnngio_config server_cfg = {0}, client_cfg = {0};
  libnngio_context *server_ctx = NULL, *client_ctx = NULL;
  const char *url = "tcp://127.0.0.1:5557";
  int rv;

  server_cfg.mode = LIBNNGIO_MODE_LISTEN;
  server_cfg.proto = LIBNNGIO_PROTO_REP;
  server_cfg.url = url;

  client_cfg.mode = LIBNNGIO_MODE_DIAL;
  client_cfg.proto = LIBNNGIO_PROTO_REQ;
  client_cfg.url = url;

  rv = libnngio_transport_init(&server, &server_cfg);
  assert(rv == 0);

  rv = libnngio_transport_init(&client, &client_cfg);
  assert(rv == 0);

  rv = libnngio_context_init(&server_ctx, server, &server_cfg, NULL, NULL);
  assert(rv == 0);

  rv = libnngio_context_init(&client_ctx, client, &client_cfg, NULL, NULL);
  assert(rv == 0);

  sleep_ms(100);

  const char *hello = "hello-tcp-async";
  async_test_sync send_sync = {0}, recv_sync = {0};

#ifdef NNGIO_MOCK_MAIN
  libnngio_mock_set_recv_buffer(hello, strlen(hello) + 1);
#endif
  recv_sync.len = sizeof(recv_sync.buf);
  rv = libnngio_context_recv_async(server_ctx, recv_sync.buf, &recv_sync.len,
                                   async_recv_cb, &recv_sync);
  assert(rv == 0);

  rv = libnngio_context_send_async(client_ctx, hello, strlen(hello) + 1,
                                   async_send_cb, &send_sync);
  assert(rv == 0);
#ifdef NNGIO_MOCK_MAIN
  // Validate mock send
  assert(mock_stats.last_send_async.ctx == client_ctx);
  assert(mock_stats.last_send_async.buf == hello);
  assert(mock_stats.last_send_async.len == strlen(hello) + 1);
#endif

  // Wait for send to finish
  while (!send_sync.done) {
    sleep_ms(1);
  }
  assert(send_sync.result == 0);

  // Wait for recv to finish
  while (!recv_sync.done) {
    sleep_ms(1);
  }
  assert(recv_sync.result == 0);
  assert(strcmp(recv_sync.buf, hello) == 0);

  libnngio_context_free(client_ctx);
  libnngio_context_free(server_ctx);
  libnngio_transport_free(client);
  libnngio_transport_free(server);

#ifdef NNGIO_MOCK_MAIN
  // Verify mock stats
  assert(mock_stats.init_calls == 2);
  assert(mock_stats.send_async_calls == 1);
  assert(mock_stats.recv_async_calls == 1);
  assert(mock_stats.free_calls == 2);
  assert(mock_stats.last_init_result == 0);
  assert(mock_stats.last_send_async_result == 0);
  assert(mock_stats.last_recv_async_result == 0);
  libnngio_log("INF", "TEST_TCP_ASYNC", __FILE__, __LINE__, -1,
               "Mock stats verified successfully.");
  libnngio_mock_reset();
#endif  // NNGIO_MOCK_MAIN

  libnngio_log("INF", "TEST_TCP_ASYNC", __FILE__, __LINE__, -1,
               "TCP async test completed successfully.");
}

/**
 * @brief Test TLS transport with async send/recv
 */
void test_tls_async() {
  libnngio_transport *server = NULL, *client = NULL;
  libnngio_config server_cfg = {0}, client_cfg = {0};
  libnngio_context *server_ctx = NULL, *client_ctx = NULL;
  const char *url = "tls+tcp://127.0.0.1:5558";
  int rv;

  // Paths to server PEM files (update as appropriate)
  const char *ca_cert = "test_certs/dev-ca.pem";
  const char *s_cert = "test_certs/server.crt";
  const char *s_key = "test_certs/server.key";
  const char *c_cert = "test_certs/client.crt";
  const char *c_key = "test_certs/client.key";

  server_cfg.mode = LIBNNGIO_MODE_LISTEN;
  server_cfg.proto = LIBNNGIO_PROTO_REP;
  server_cfg.url = url;
  server_cfg.tls_cert = s_cert;
  server_cfg.tls_key = s_key;
  server_cfg.tls_ca_cert = ca_cert;

  client_cfg.mode = LIBNNGIO_MODE_DIAL;
  client_cfg.proto = LIBNNGIO_PROTO_REQ;
  client_cfg.url = url;
  client_cfg.tls_cert = c_cert;
  client_cfg.tls_key = c_key;
  client_cfg.tls_ca_cert = ca_cert;

  rv = libnngio_transport_init(&server, &server_cfg);
  assert(rv == 0);

  rv = libnngio_transport_init(&client, &client_cfg);
  assert(rv == 0);

  rv = libnngio_context_init(&server_ctx, server, &server_cfg, NULL, NULL);
  assert(rv == 0);

  rv = libnngio_context_init(&client_ctx, client, &client_cfg, NULL, NULL);
  assert(rv == 0);

  sleep_ms(100);

  const char *hello = "hello-tls-async";
  async_test_sync send_sync = {0}, recv_sync = {0};

#ifdef NNGIO_MOCK_MAIN
  libnngio_mock_set_recv_buffer(hello, strlen(hello) + 1);
#endif
  recv_sync.len = sizeof(recv_sync.buf);
  rv = libnngio_context_recv_async(server_ctx, recv_sync.buf, &recv_sync.len,
                                   async_recv_cb, &recv_sync);
  assert(rv == 0);

  sleep_ms(100);

  rv = libnngio_context_send_async(client_ctx, hello, strlen(hello) + 1,
                                   async_send_cb, &send_sync);
  assert(rv == 0);

  while (!send_sync.done) {
    sleep_ms(1);
  }
  assert(send_sync.result == 0);

  while (!recv_sync.done) {
    sleep_ms(1);
  }
  assert(recv_sync.result == 0);
  assert(strcmp(recv_sync.buf, hello) == 0);

  libnngio_context_free(client_ctx);
  libnngio_context_free(server_ctx);
  libnngio_transport_free(client);
  libnngio_transport_free(server);

#ifdef NNGIO_MOCK_MAIN
  // Verify mock stats
  assert(mock_stats.init_calls == 2);
  assert(mock_stats.send_async_calls == 1);
  assert(mock_stats.recv_async_calls == 1);
  assert(mock_stats.free_calls == 2);
  assert(mock_stats.last_init_result == 0);
  assert(mock_stats.last_send_async_result == 0);
  assert(mock_stats.last_recv_async_result == 0);
  libnngio_log("INF", "TEST_TLS_ASYNC", __FILE__, __LINE__, -1,
               "Mock stats verified successfully.");
  libnngio_mock_reset();
#endif  // NNGIO_MOCK_MAIN

  libnngio_log("INF", "TEST_TLS_ASYNC", __FILE__, __LINE__, -1,
               "TLS async test completed successfully.");
}

/**
 * @brief Basic REQ/REP test: server (REP) listens, client (REQ) dials,
 *        client sends request, server replies, client receives reply.
 */
void test_reqrep_basic() {
  libnngio_transport *server = NULL, *client = NULL;
  libnngio_config server_cfg = {0}, client_cfg = {0};
  const char *url = "tcp://127.0.0.1:5560";
  char msg[256] = {0};
  size_t msglen;
  int rv;

  server_cfg.mode = LIBNNGIO_MODE_LISTEN;
  server_cfg.proto = LIBNNGIO_PROTO_REP;
  server_cfg.url = url;

  client_cfg.mode = LIBNNGIO_MODE_DIAL;
  client_cfg.proto = LIBNNGIO_PROTO_REQ;
  client_cfg.url = url;

  rv = libnngio_transport_init(&server, &server_cfg);
  assert(rv == 0);

  rv = libnngio_transport_init(&client, &client_cfg);
  assert(rv == 0);

  sleep_ms(100);

  libnngio_context *server_ctx = NULL, *client_ctx = NULL;
  rv = libnngio_context_init(&server_ctx, server, &server_cfg, NULL, NULL);
  assert(rv == 0);
  rv = libnngio_context_init(&client_ctx, client, &client_cfg, NULL, NULL);
  assert(rv == 0);

  // Client sends request
  const char *req = "request-data";
  rv = libnngio_context_send(client_ctx, req, strlen(req) + 1);
  assert(rv == 0);

  // Server receives request
#ifdef NNGIO_MOCK_MAIN
  libnngio_mock_set_recv_buffer(req, strlen(req) + 1);
#endif
  msglen = sizeof(msg);
  rv = libnngio_context_recv(server_ctx, msg, &msglen);
  assert(rv == 0 && strcmp(msg, req) == 0);

  // Server sends reply
  const char *rep = "reply-data";
  rv = libnngio_context_send(server_ctx, rep, strlen(rep) + 1);
  assert(rv == 0);

  // Client receives reply
#ifdef NNGIO_MOCK_MAIN
  libnngio_mock_set_recv_buffer(rep, strlen(rep) + 1);
#endif
  msglen = sizeof(msg);
  rv = libnngio_context_recv(client_ctx, msg, &msglen);
  assert(rv == 0 && strcmp(msg, rep) == 0);

  libnngio_context_free(client_ctx);
  libnngio_context_free(server_ctx);

  libnngio_transport_free(client);
  libnngio_transport_free(server);

#ifdef NNGIO_MOCK_MAIN
  // Verify mock stats
  assert(mock_stats.init_calls == 2);
  assert(mock_stats.send_calls == 2);
  assert(mock_stats.recv_calls == 2);
  assert(mock_stats.free_calls == 2);
  assert(mock_stats.last_init_result == 0);
  assert(mock_stats.last_send_result == 0);
  assert(mock_stats.last_recv_result == 0);
  libnngio_log("INF", "TEST_REQREP_BASIC", __FILE__, __LINE__, -1,
               "Mock stats verified successfully.");
  libnngio_mock_reset();
#endif  // NNGIO_MOCK_MAIN
  //
  libnngio_log("INF", "TEST_REQREP_BASIC", __FILE__, __LINE__, -1,
               "REQ/REP basic test completed successfully.");
}

/**
 * @brief Basic PUB/SUB test: server (PUB) listens, client (SUB) dials,
 *        server sends message, client receives message.
 */
void test_pubsub_basic() {
  libnngio_transport *server = NULL, *client = NULL;
  libnngio_config server_cfg = {0}, client_cfg = {0};
  const char *url = "tcp://127.0.0.1:5561";
  char msg[256] = {0};
  size_t msglen;
  int rv;

  server_cfg.mode = LIBNNGIO_MODE_LISTEN;
  server_cfg.proto = LIBNNGIO_PROTO_PUB;
  server_cfg.url = url;

  client_cfg.mode = LIBNNGIO_MODE_DIAL;
  client_cfg.proto = LIBNNGIO_PROTO_SUB;
  client_cfg.url = url;

  rv = libnngio_transport_init(&server, &server_cfg);
  assert(rv == 0);

  rv = libnngio_transport_init(&client, &client_cfg);
  assert(rv == 0);

  libnngio_context *server_ctx = NULL, *client_ctx = NULL;
  rv = libnngio_context_init(&server_ctx, server, &server_cfg, NULL, NULL);
  assert(rv == 0);
  rv = libnngio_context_init(&client_ctx, client, &client_cfg, NULL, NULL);
  assert(rv == 0);

  sleep_ms(100);

  const char *hello = "hello-sub";
  rv = libnngio_context_send(server_ctx, hello, strlen(hello) + 1);
  assert(rv == 0);
#ifdef NNGIO_MOCK_MAIN
  // Validate mock send
  assert(mock_stats.last_send.ctx == server_ctx);
  assert(mock_stats.last_send.buf == hello);
  assert(mock_stats.last_send.len == strlen(hello) + 1);
  libnngio_mock_set_recv_buffer(hello, strlen(hello) + 1);
#endif
  msglen = sizeof(msg);
  rv = libnngio_context_recv(client_ctx, msg, &msglen);
  assert(rv == 0 && strcmp(msg, hello) == 0);

  libnngio_context_free(client_ctx);
  libnngio_context_free(server_ctx);

  libnngio_transport_free(client);
  libnngio_transport_free(server);

#ifdef NNGIO_MOCK_MAIN
  // Verify mock stats
  assert(mock_stats.init_calls == 2);
  assert(mock_stats.send_calls == 1);
  assert(mock_stats.recv_calls == 1);
  assert(mock_stats.free_calls == 2);
  assert(mock_stats.last_init_result == 0);
  assert(mock_stats.last_send_result == 0);
  assert(mock_stats.last_recv_result == 0);
  libnngio_log("INF", "TEST_PUBSUB_BASIC", __FILE__, __LINE__, -1,
               "Mock stats verified successfully.");
  libnngio_mock_reset();
#endif  // NNGIO_MOCK_MAIN

  libnngio_log("INF", "TEST_PUBSUB_BASIC", __FILE__, __LINE__, -1,
               "PUB/SUB basic test completed successfully.");
}

/**
 * @brief Basic PUSH/PULL test: server (PUSH) listens, client (PULL) dials,
 *        server pushes message, client pulls message.
 */
void test_pushpull_basic() {
  libnngio_transport *push = NULL, *pull = NULL;
  libnngio_config push_cfg = {0}, pull_cfg = {0};
  const char *url = "tcp://127.0.0.1:5562";
  char msg[256] = {0};
  size_t msglen;
  int rv;

  push_cfg.mode = LIBNNGIO_MODE_LISTEN;
  push_cfg.proto = LIBNNGIO_PROTO_PUSH;
  push_cfg.url = url;

  pull_cfg.mode = LIBNNGIO_MODE_DIAL;
  pull_cfg.proto = LIBNNGIO_PROTO_PULL;
  pull_cfg.url = url;

  rv = libnngio_transport_init(&push, &push_cfg);
  assert(rv == 0);

  rv = libnngio_transport_init(&pull, &pull_cfg);
  assert(rv == 0);

  libnngio_context *push_ctx = NULL, *pull_ctx = NULL;
  rv = libnngio_context_init(&push_ctx, push, &push_cfg, NULL, NULL);
  assert(rv == 0);
  rv = libnngio_context_init(&pull_ctx, pull, &pull_cfg, NULL, NULL);
  assert(rv == 0);

  sleep_ms(100);

  const char *payload = "pushed-data";
  rv = libnngio_context_send(push_ctx, payload, strlen(payload) + 1);
  assert(rv == 0);

#ifdef NNGIO_MOCK_MAIN
  libnngio_mock_set_recv_buffer(payload, strlen(payload) + 1);
#endif
  msglen = sizeof(msg);
  rv = libnngio_context_recv(pull_ctx, msg, &msglen);
  assert(rv == 0 && strcmp(msg, payload) == 0);

  libnngio_context_free(push_ctx);
  libnngio_context_free(pull_ctx);

  libnngio_transport_free(push);
  libnngio_transport_free(pull);

#ifdef NNGIO_MOCK_MAIN
  // Verify mock stats
  assert(mock_stats.init_calls == 2);
  assert(mock_stats.send_calls == 1);
  assert(mock_stats.recv_calls == 1);
  assert(mock_stats.free_calls == 2);
  assert(mock_stats.last_init_result == 0);
  assert(mock_stats.last_send_result == 0);
  assert(mock_stats.last_recv_result == 0);
  libnngio_log("INF", "TEST_PUSHPULL_BASIC", __FILE__, __LINE__, -1,
               "Mock stats verified successfully.");
  libnngio_mock_reset();
#endif  // NNGIO_MOCK_MAIN

  libnngio_log("INF", "TEST_PUSHPULL_BASIC", __FILE__, __LINE__, -1,
               "PUSH/PULL basic test completed successfully.");
}

/**
 * @brief Test libnngio_context_init and libnngio_context_free
 */
static void test_libnngio_context_init() {
  libnngio_transport *t = NULL;
  libnngio_config config = {0};
  config.url = "tcp://127.0.0.1:5563";
  config.mode = LIBNNGIO_MODE_LISTEN;
  config.proto = LIBNNGIO_PROTO_REP;
  int rv = libnngio_transport_init(&t, &config);
  assert(rv == 0);
  libnngio_context *ctx = NULL;
  rv = libnngio_context_init(&ctx, t, &config, NULL, NULL);
  assert(rv == 0);
  assert(ctx != NULL);
  libnngio_context_free(ctx);
  libnngio_transport_free(t);
}

/**
 * @brief simple user data structure for example_ctx_cb
 */
typedef struct example_user_data {
  int touched; /**< Flag to indicate if callback was invoked */
} example_user_data;

/**
 * @brief Example context callback that sets touched flag in user data
 */
void example_ctx_cb(void *arg) {
  libnngio_context *ctx = (libnngio_context *)arg;
  example_user_data *data =
      (example_user_data *)libnngio_context_get_user_data(ctx);
  libnngio_log("INF", "EXAMPLE_CTX_CB", __FILE__, __LINE__, -1,
               "Example context callback invoked.");
  data->touched = 1;
}

/**
 * @brief Test multiple contexts with individual user data and callbacks
 */
static void test_libnngio_multiple_contexts() {
  libnngio_transport *t = NULL;
  libnngio_config config = {0};
  config.url = "tcp://127.0.0.1:5564";
  config.mode = LIBNNGIO_MODE_LISTEN;
  config.proto = LIBNNGIO_PROTO_REP;
  int rv = libnngio_transport_init(&t, &config);
  assert(rv == 0);
  libnngio_context *ctxs[3] = {0};

  example_user_data user_data[3] = {0};
  for (int i = 0; i < 3; i++) {
    user_data[i].touched = 0;
    rv = libnngio_context_init(&ctxs[i], t, &config, example_ctx_cb,
                               &user_data[i]);
    assert(rv == 0);
  }

  for (int i = 0; i < 3; i++) {
    example_user_data *data =
        (example_user_data *)libnngio_context_get_user_data(ctxs[i]);
    assert(data == &user_data[i]);
    assert(user_data[i].touched == 0);
    libnngio_context_start(ctxs[i]);
    assert(user_data[i].touched == 1);
    libnngio_context_free(ctxs[i]);
  }

  libnngio_transport_free(t);
}

/**
 * @brief User data structure for test_ctx_cb
 */
typedef struct {
  int id;      /**< Context identifier */
  int started; /**< Flag to indicate if context has started */
} test_user_data;

/**
 * @brief Context callback that sets started flag in user data
 */
void test_ctx_cb(void *arg) {
  libnngio_context *ctx = (libnngio_context *)arg;
  test_user_data *ud = (test_user_data *)libnngio_context_get_user_data(ctx);
  if (ud) ud->started = 1;
}

/**
 * @brief Test multiple contexts initialization, starting, and freeing
 */
void test_libnngio_multiple_contexts2() {
  libnngio_transport *t = NULL;
  libnngio_config config = {0};
  config.url = "tcp://127.0.0.1:12345";
  config.mode = LIBNNGIO_MODE_LISTEN;
  config.proto = LIBNNGIO_PROTO_REP;

  int rv = libnngio_transport_init(&t, &config);
  assert(rv == 0);

  size_t n = 4;
  libnngio_context **ctxs = NULL;
  test_user_data user_datas[4] = {0};
  void *ud_ptrs[4] = {&user_datas[0], &user_datas[1], &user_datas[2],
                      &user_datas[3]};

  rv = libnngio_contexts_init(&ctxs, n, t, &config, test_ctx_cb, ud_ptrs);
  assert(rv == 0 && ctxs);

  for (size_t i = 0; i < n; ++i) {
    assert(ctxs[i] != NULL);
    user_datas[i].id = (int)i;
    user_datas[i].started = 0;
  }

  libnngio_contexts_start(ctxs, n);

  for (size_t i = 0; i < n; ++i) {
    assert(user_datas[i].started ==
           1);  // callback should have set started to 1
  }

  libnngio_contexts_free(ctxs, n);
  libnngio_transport_free(t);

  libnngio_log("INF", "TEST_MULTIPLE_CTX_UTILS", __FILE__, __LINE__, -1,
               "test_multiple_contexts_utils: PASS");
}

/**
 * @brief Number of messages/contexts for REQ/REP test
 */
#define REQREP_TEST_MSG_COUNT 4
/**
 * @brief TCP port for REQ/REP test
 */
#define REQREP_TEST_TCP_PORT 5567

/**
 * @brief User data structure for REQ/REP test with multiple contexts
 */
typedef struct {
  int index;                     /**< Context index */
  int received;                  /**< Number of requests received */
  int replied;                   /**< Number of replies sent */
  char req_buf[128];             /**< Buffer to hold received request */
  size_t req_len;                /**< Length of received request */
  char rep_buf[128];             /**< Buffer to hold reply */
  size_t rep_len;                /**< Length of reply */
  libnngio_context *ctx;         /**< Pointer to the context */
  libnngio_transport *transport; /**< Pointer to the transport */
} reqrep_user_data;

// Forward declaration of service routine
void reqrep_service_routine(void *arg);

/**
 * @brief Async reply callback for requests
 */
void reqrep_reply_cb(libnngio_context *t, int result, void *data, size_t len,
                     void *user_data) {
  reqrep_user_data *ud = (reqrep_user_data *)user_data;
  libnngio_log("DBG", "REPLY_CB", __FILE__, __LINE__, ud->index,
               "Context %d: reply sent: %s", ud->index, ud->rep_buf);
  assert(result == 0);
  ud->replied++;

#ifndef NNGIO_MOCK_MAIN
  // After reply sent, post another receive by re-entering the service routine
  reqrep_service_routine(ud->ctx);
#endif
}

/**
 * @brief Async receive callback for requests
 */
void reqrep_recv_cb(libnngio_context *t, int result, void *data, size_t len,
                    void *user_data) {
  reqrep_user_data *ud = (reqrep_user_data *)user_data;
  libnngio_log("DBG", "RECV_CB", __FILE__, __LINE__, ud->index,
               "Context %d: received request: %s", ud->index, (char *)data);
  if (result != 0 && result != 7) {
    libnngio_log("ERR", "RECV_CB", __FILE__, __LINE__, ud->index,
                 "Context %d: receive error: %d", ud->index, result);
  }
  if (result == 7) {
    // This is a special case for NNG where it indicates that the context is
    // closed
    libnngio_log("INF", "RECV_CB", __FILE__, __LINE__, ud->index,
                 "Context %d: receive closed", ud->index);
    return;  // No further processing needed
  }
  assert(result == 0 || result == 7);
  if (result == 0 && ud && data && len <= sizeof(ud->req_buf)) {
    memcpy(ud->req_buf, data, len);
    ud->req_len = len;
    ud->received++;
    libnngio_log("DBG", "RECV_CB", __FILE__, __LINE__, ud->index,
                 "Context %d received request: %s", ud->index, ud->req_buf);
    // Prepare reply
    snprintf(ud->rep_buf, sizeof(ud->rep_buf), "reply-%d", ud->index);
    ud->rep_len = strlen(ud->rep_buf) + 1;
    // Send reply asynchronously
    int rv = libnngio_context_send_async(t, ud->rep_buf, ud->rep_len,
                                         reqrep_reply_cb, ud);
    assert(rv == 0);
  }
}

/**
 * @brief Service routine for REQ/REP context: starts async receive
 */
void reqrep_service_routine(void *arg) {
  libnngio_context *ctx = (libnngio_context *)arg;
  reqrep_user_data *ud =
      (reqrep_user_data *)libnngio_context_get_user_data(ctx);
  ud->ctx = ctx;  // store the context pointer (optional if not already set)
  ud->req_len = sizeof(ud->req_buf);

#ifdef NNGIO_MOCK_MAIN
  // Mocking: set expected receive buffer for REP contexts
  char expected_req[32];
  snprintf(expected_req, sizeof(expected_req), "request-%d", ud->index);
  libnngio_mock_set_recv_buffer(expected_req, strlen(expected_req) + 1);
#endif
  libnngio_log("DBG", "SERVICE_ROUTINE", __FILE__, __LINE__, ud->index,
               "Context %d starting async receive", ud->index);
  int rv = libnngio_context_recv_async(ctx, ud->req_buf, &ud->req_len,
                                       reqrep_recv_cb, ud);
  assert(rv == 0);
}

/**
 * @brief Test multiple REQ/REP contexts with concurrent request handling
 */
void test_multiple_contexts_reqrep_concurrent_ctx_cb_tcp() {
  libnngio_transport *rep = NULL, *req = NULL;
  libnngio_config rep_cfg = {0}, req_cfg = {0};
  char url[64];
  snprintf(url, sizeof(url), "tcp://127.0.0.1:%d", REQREP_TEST_TCP_PORT);

  rep_cfg.url = url;
  rep_cfg.mode = LIBNNGIO_MODE_LISTEN;
  rep_cfg.proto = LIBNNGIO_PROTO_REP;
  req_cfg.url = url;
  req_cfg.mode = LIBNNGIO_MODE_DIAL;
  req_cfg.proto = LIBNNGIO_PROTO_REQ;

  int rv = libnngio_transport_init(&rep, &rep_cfg);
  assert(rv == 0);
  libnngio_log("INF", "TEST_CTX_CB_TCP", __FILE__, __LINE__, -1,
               "REP transport initialized on %s", url);
  rv = libnngio_transport_init(&req, &req_cfg);
  assert(rv == 0);
  libnngio_log("INF", "TEST_CTX_CB_TCP", __FILE__, __LINE__, -1,
               "REQ transport initialized on %s", url);

  libnngio_context *req_ctx = NULL;

  rv = libnngio_context_init(&req_ctx, req, &req_cfg, NULL, NULL);
  assert(rv == 0);

  // Prepare contexts for REP side
  size_t n = REQREP_TEST_MSG_COUNT;
  libnngio_context **ctxs = NULL;
  reqrep_user_data user_datas[REQREP_TEST_MSG_COUNT] = {0};
  void *ud_ptrs[REQREP_TEST_MSG_COUNT];
  for (size_t i = 0; i < n; ++i) {
    user_datas[i].index = (int)i;
    user_datas[i].transport = rep;
    ud_ptrs[i] = &user_datas[i];
  }
  rv = libnngio_contexts_init(&ctxs, n, rep, &rep_cfg, reqrep_service_routine,
                              ud_ptrs);
  assert(rv == 0);
  libnngio_log("INF", "TEST_CTX_CB_TCP", __FILE__, __LINE__, -1,
               "%zu REP contexts initialized", n);

  // Start service routines for all contexts
  libnngio_contexts_start(ctxs, n);
  libnngio_log("INF", "TEST_CTX_CB_TCP", __FILE__, __LINE__, -1,
               "All REP context service routines started");

  usleep(100000);

  // Send requests from REQ side and receive replies synchronously
  for (size_t i = 0; i < n; ++i) {
    char req_msg[32], rep_msg[128];
    size_t rep_len = sizeof(rep_msg);
    snprintf(req_msg, sizeof(req_msg), "request-%zu", i);

    libnngio_log("DBG", "TEST_CTX_CB_TCP", __FILE__, __LINE__, i,
                 "REQ sending: %s", req_msg);
    rv = libnngio_context_send(req_ctx, req_msg, strlen(req_msg) + 1);
  }

  // Wait for all contexts to finish at least one request/reply
  int all_done = 0;
  for (int tries = 0; tries < 100 && !all_done; ++tries) {
    all_done = 1;
    for (size_t i = 0; i < n; ++i) {
      if (!(user_datas[i].received >= 1 && user_datas[i].replied >= 1))
        all_done = 0;
    }
    if (!all_done) {
      usleep(10000);
    }
  }

  for (size_t i = 0; i < n; ++i) {
    assert(user_datas[i].received >= 1);
    assert(user_datas[i].replied >= 1);
    libnngio_log("INF", "TEST_CTX_CB_TCP", __FILE__, __LINE__, i,
                 "Context %zu handled request: %s -> reply: %s", i,
                 user_datas[i].req_buf, user_datas[i].rep_buf);
  }

  libnngio_context_free(req_ctx);
  libnngio_contexts_free(ctxs, n);
  libnngio_log("INF", "TEST_CTX_CB_TCP", __FILE__, __LINE__, -1,
               "REP contexts freed");
  libnngio_transport_free(rep);
  libnngio_transport_free(req);
  libnngio_log("INF", "TEST_CTX_CB_TCP", __FILE__, __LINE__, -1,
               "REP and REQ transports freed");

  libnngio_log("INF", "TEST_CTX_CB_TCP", __FILE__, __LINE__, -1,
               "test_multiple_contexts_reqrep_concurrent_ctx_cb_tcp: PASS");
}

/**
 * @brief Main function to run all tests
 */
int main() {
  // Register cleanup for global NNG state
  atexit(libnngio_cleanup);

  // Get the value associated with the variable
  const char *loglevelstr = getenv("NNGIO_LOGLEVEL");
  printf("Beggining NNGIO tests...\n");
  libnngio_log_init(loglevelstr);

  test_tcp_basic();
  test_tls_basic();
  test_tcp_async();
  test_tls_async();
  test_reqrep_basic();
  test_pubsub_basic();
  test_pushpull_basic();
  test_libnngio_context_init();
  test_libnngio_multiple_contexts();
  test_libnngio_multiple_contexts2();
  test_multiple_contexts_reqrep_concurrent_ctx_cb_tcp();

  libnngio_log("INF", "MAIN", __FILE__, __LINE__, -1,
               "All tests completed successfully.");

  return 0;
}
