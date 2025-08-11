#include <assert.h>
#include <nng/nng.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "main/libnngio_main.h"

// Helper: sleep for a short time (ms) for connect
#ifdef _WIN32
#include <windows.h>
#define sleep_ms(ms) Sleep(ms)
#else
#include <unistd.h>
#define sleep_ms(ms) usleep((ms) * 1000)
#endif

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

  // Server setup
  rv = libnngio_transport_init(&server, &server_cfg);
  assert(rv == 0);

  // Client setup
  rv = libnngio_transport_init(&client, &client_cfg);
  assert(rv == 0);

  // Allow time for connection
  sleep_ms(100);

  // Communication
  const char *hello = "hello-tcp";
  rv = libnngio_transport_send(client, hello, strlen(hello) + 1);
  assert(rv == 0);
#ifdef NNGIO_MOCK_MAIN
  // Validate mock send
  assert(mock_stats.last_send.ctx == client);
  assert(mock_stats.last_send.buf == hello);
  assert(mock_stats.last_send.len == strlen(hello) + 1);
#endif

  msglen = sizeof(msg);
#ifdef NNGIO_MOCK_MAIN
  // Mocking: set expected receive buffer
  libnngio_mock_set_recv_buffer(hello, strlen(hello) + 1);
#endif
  rv = libnngio_transport_recv(server, msg, &msglen);
  assert(rv == 0 && strcmp(msg, hello) == 0);

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

  // Allow time for TLS handshake
  sleep_ms(100);

  const char *hello = "hello-tls";
  rv = libnngio_transport_send(client, hello, strlen(hello) + 1);
  assert(rv == 0);
#ifdef NNGIO_MOCK_MAIN
  // Validate mock send
  assert(mock_stats.last_send.ctx == client);
  assert(mock_stats.last_send.buf == hello);
  assert(mock_stats.last_send.len == strlen(hello) + 1);
#endif

#ifdef NNGIO_MOCK_MAIN
  // Mocking: set expected receive buffer
  libnngio_mock_set_recv_buffer(hello, strlen(hello) + 1);
#endif
  msglen = sizeof(msg);
  rv = libnngio_transport_recv(server, msg, &msglen);
  assert(rv == 0 && strcmp(msg, hello) == 0);

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

// ---------- ASYNC TESTING SUPPORT -----------
typedef struct {
  volatile int done;
  int result;
  char buf[256];
  size_t len;
} async_test_sync;

void async_recv_cb(libnngio_transport *ctx, int result, void *data, size_t len,
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

void async_send_cb(libnngio_transport *ctx, int result, void *data, size_t len,
                   void *user_data) {
  libnngio_log("INF", "TEST_ASYNC_SEND_CB", __FILE__, __LINE__, -1,
               "Async send callback called with result=%d, len=%zu", result,
               len);
  async_test_sync *sync = (async_test_sync *)user_data;
  sync->result = result;
  sync->done = 1;
}

void test_tcp_async() {
  libnngio_transport *server = NULL, *client = NULL;
  libnngio_config server_cfg = {0}, client_cfg = {0};
  const char *url = "tcp://127.0.0.1:5557";
  int rv;

  server_cfg.mode = LIBNNGIO_MODE_LISTEN;
  server_cfg.proto = LIBNNGIO_PROTO_PAIR;
  server_cfg.url = url;

  client_cfg.mode = LIBNNGIO_MODE_DIAL;
  client_cfg.proto = LIBNNGIO_PROTO_PAIR;
  client_cfg.url = url;

  rv = libnngio_transport_init(&server, &server_cfg);
  assert(rv == 0);

  rv = libnngio_transport_init(&client, &client_cfg);
  assert(rv == 0);

  sleep_ms(100);

  const char *hello = "hello-tcp-async";
  async_test_sync send_sync = {0}, recv_sync = {0};

#ifdef NNGIO_MOCK_MAIN
  libnngio_mock_set_recv_buffer(hello, strlen(hello) + 1);
#endif
  recv_sync.len = sizeof(recv_sync.buf);
  rv = libnngio_transport_recv_async(server, recv_sync.buf, &recv_sync.len, async_recv_cb,
                           &recv_sync);
  assert(rv == 0);

  rv = libnngio_transport_send_async(client, hello, strlen(hello) + 1, async_send_cb,
                           &send_sync);
  assert(rv == 0);
#ifdef NNGIO_MOCK_MAIN
  // Validate mock send
  assert(mock_stats.last_send_async.ctx == client);
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

void test_tls_async() {
  libnngio_transport *server = NULL, *client = NULL;
  libnngio_config server_cfg = {0}, client_cfg = {0};
  const char *url = "tls+tcp://127.0.0.1:5558";
  int rv;

  // Paths to server PEM files (update as appropriate)
  const char *ca_cert = "test_certs/dev-ca.pem";
  const char *s_cert = "test_certs/server.crt";
  const char *s_key = "test_certs/server.key";
  const char *c_cert = "test_certs/client.crt";
  const char *c_key = "test_certs/client.key";

  server_cfg.mode = LIBNNGIO_MODE_LISTEN;
  server_cfg.proto = LIBNNGIO_PROTO_PAIR;
  server_cfg.url = url;
  server_cfg.tls_cert = s_cert;
  server_cfg.tls_key = s_key;
  server_cfg.tls_ca_cert = ca_cert;

  client_cfg.mode = LIBNNGIO_MODE_DIAL;
  client_cfg.proto = LIBNNGIO_PROTO_PAIR;
  client_cfg.url = url;
  // client_cfg.tls_cert = c_cert;
  // client_cfg.tls_key = c_key;
  client_cfg.tls_ca_cert = ca_cert;

  rv = libnngio_transport_init(&server, &server_cfg);
  assert(rv == 0);

  rv = libnngio_transport_init(&client, &client_cfg);
  assert(rv == 0);

  sleep_ms(100);

  const char *hello = "hello-tls-async";
  async_test_sync send_sync = {0}, recv_sync = {0};

#ifdef NNGIO_MOCK_MAIN
  libnngio_mock_set_recv_buffer(hello, strlen(hello) + 1);
#endif
  recv_sync.len = sizeof(recv_sync.buf);
  rv = libnngio_transport_recv_async(server, recv_sync.buf, &recv_sync.len, async_recv_cb,
                           &recv_sync);
  assert(rv == 0);

  sleep_ms(100);

  rv = libnngio_transport_send_async(client, hello, strlen(hello) + 1, async_send_cb,
                           &send_sync);
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

  // Client sends request
  const char *req = "request-data";
  rv = libnngio_transport_send(client, req, strlen(req) + 1);
  assert(rv == 0);

  // Server receives request
#ifdef NNGIO_MOCK_MAIN
  libnngio_mock_set_recv_buffer(req, strlen(req) + 1);
#endif
  msglen = sizeof(msg);
  rv = libnngio_transport_recv(server, msg, &msglen);
  assert(rv == 0 && strcmp(msg, req) == 0);

  // Server sends reply
  const char *rep = "reply-data";
  rv = libnngio_transport_send(server, rep, strlen(rep) + 1);
  assert(rv == 0);

  // Client receives reply
#ifdef NNGIO_MOCK_MAIN
  libnngio_mock_set_recv_buffer(rep, strlen(rep) + 1);
#endif
  msglen = sizeof(msg);
  rv = libnngio_transport_recv(client, msg, &msglen);
  assert(rv == 0 && strcmp(msg, rep) == 0);

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
  libnngio_log("INF", "TEST_TLS_ASYNC", __FILE__, __LINE__, -1,
               "Mock stats verified successfully.");
  libnngio_mock_reset();
#endif  // NNGIO_MOCK_MAIN
  //
  libnngio_log("INF", "TEST_REQREP_BASIC", __FILE__, __LINE__, -1,
               "REQ/REP basic test completed successfully.");
}

void test_pubsub_basic() {
  libnngio_transport *server = NULL, *client = NULL;
  libnngio_config server_cfg = {0}, client_cfg = {0};
  const char *url = "tcp://127.0.0.1:5561";
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

  sleep_ms(100);

  const char *hello = "hello-sub";
  async_test_sync send_sync = {0}, recv_sync = {0};

#ifdef NNGIO_MOCK_MAIN
  libnngio_mock_set_recv_buffer(hello, strlen(hello) + 1);
#endif
  recv_sync.len = sizeof(recv_sync.buf);
  rv = libnngio_transport_recv_async(client, recv_sync.buf, &recv_sync.len, async_recv_cb,
                           &recv_sync);
  assert(rv == 0);

  rv = libnngio_transport_send_async(server, hello, strlen(hello) + 1, async_send_cb,
                           &send_sync);
  assert(rv == 0);

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
  libnngio_log("INF", "TEST_PUBSUB_BASIC", __FILE__, __LINE__, -1,
               "Mock stats verified successfully.");
  libnngio_mock_reset();
#endif  // NNGIO_MOCK_MAIN

  libnngio_log("INF", "TEST_PUBSUB_BASIC", __FILE__, __LINE__, -1,
               "PUB/SUB basic test completed successfully.");
}

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

  sleep_ms(100);

  const char *payload = "pushed-data";
  rv = libnngio_transport_send(push, payload, strlen(payload) + 1);
  assert(rv == 0);

#ifdef NNGIO_MOCK_MAIN
  libnngio_mock_set_recv_buffer(payload, strlen(payload) + 1);
#endif
  msglen = sizeof(msg);
  rv = libnngio_transport_recv(pull, msg, &msglen);
  assert(rv == 0 && strcmp(msg, payload) == 0);

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

  printf("All tests completed successfully.\n");

  return 0;
}
