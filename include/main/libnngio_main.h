#ifndef LIBNNGIO_MAIN_H
#define LIBNNGIO_MAIN_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ========================
// libnngio public API
// ========================

// Protocols supported
typedef enum {
  LIBNNGIO_PROTO_PAIR = 0,
  LIBNNGIO_PROTO_REQ,
  LIBNNGIO_PROTO_REP,
  LIBNNGIO_PROTO_PUB,
  LIBNNGIO_PROTO_SUB,
  LIBNNGIO_PROTO_PUSH,
  LIBNNGIO_PROTO_PULL,
  LIBNNGIO_PROTO_SURVEYOR,
  LIBNNGIO_PROTO_RESPONDENT,
  LIBNNGIO_PROTO_BUS,
} libnngio_proto;

typedef enum { LIBNNGIO_MODE_DIAL = 0, LIBNNGIO_MODE_LISTEN = 1 } libnngio_mode;

// Flexible option passing
typedef struct {
  const char *key;
  const char *value;
} libnngio_option;

typedef struct libnngio_transport libnngio_transport;

// User configuration
typedef struct {
  libnngio_mode mode;
  libnngio_proto proto;
  const char *url;

  // TLS options: paths to certificate/key/CA PEM files
  const char *tls_cert;
  const char *tls_key;
  const char *tls_ca_cert;

  // Optionally set timeouts (ms) and max message size
  int recv_timeout_ms;
  int send_timeout_ms;
  size_t max_msg_size;

  // Arbitrary nng socket options
  const libnngio_option *options;
  size_t option_count;
} libnngio_config;

// Logging made available for users as well
void libnngio_log_init(const char *level);
void libnngio_log(const char *level, const char *tag, const char *file,
                  int line, int id, const char *fmt, ...);

// Profide functions for interacting with the transport directly
int libnngio_transport_init(libnngio_transport **tp,
                            const libnngio_config *config);
int libnngio_transport_send(libnngio_transport *t, const void *buf, size_t len);
int libnngio_transport_recv(libnngio_transport *t, void *buf, size_t *len);
void libnngio_transport_free(libnngio_transport *t);

typedef struct libnngio_context libnngio_context;
typedef void (*libnngio_ctx_cb)(void *args);
typedef void (*libnngio_async_cb)(libnngio_context *ctx, int result, void *data,
                                  size_t len, void *user_data);

int libnngio_context_init(libnngio_context **ctxp, libnngio_transport *t,
                          const libnngio_config *config, libnngio_ctx_cb cb,
                          void *user_data);
void libnngio_context_start(libnngio_context *ctx);
int libnngio_context_send_async(libnngio_context *ctx, const void *buf,
                                size_t len, libnngio_async_cb cb,
                                void *user_data);
int libnngio_context_recv_async(libnngio_context *ctx, void *buf, size_t *len,
                                libnngio_async_cb cb, void *user_data);
void libnngio_context_set_user_data(libnngio_context *ctx, void *user_data);
void *libnngio_context_get_user_data(libnngio_context *ctx);
void libnngio_context_free(libnngio_context *ctx);
int libnngio_contexts_init(libnngio_context ***ctxs, size_t n,
                           libnngio_transport *t, const libnngio_config *config,
                           libnngio_ctx_cb cb, void **user_datas);
void libnngio_contexts_free(libnngio_context **ctxs, size_t n);
void libnngio_contexts_start(libnngio_context **ctxs, size_t n);

// Cleanup global NNG state (calls nng_fini). Safe to call multiple times.
// After this, no more libnngio functions should be called.
void libnngio_cleanup(void);

#ifdef __cplusplus
}
#endif

// ===============================================================================
// MOCKING SUPPORT BELOW -- These APIs are only available if using the mock
// library
// ===============================================================================

#ifdef NNGIO_MOCK_MAIN
// Stores all function parameters for the most recent calls
typedef struct libnngio_mock_call {
  libnngio_transport *ctx;
  const void *buf;
  size_t len;
  size_t *len_ptr;
  libnngio_async_cb cb;
  void *user_data;
} libnngio_mock_call;

typedef struct libnngio_mock_stats {
  int init_calls;
  int send_calls;
  int recv_calls;
  int free_calls;
  int send_async_calls;
  int recv_async_calls;
  int last_init_result;
  int last_send_result;
  int last_recv_result;
  int last_send_async_result;
  int last_recv_async_result;
  libnngio_mock_call last_init;
  libnngio_mock_call last_send;
  libnngio_mock_call last_recv;
  libnngio_mock_call last_send_async;
  libnngio_mock_call last_recv_async;
} libnngio_mock_stats;

// Expose the stats object for assertions
extern libnngio_mock_stats mock_stats;

// Allow tests to set forced return values for each API call
void libnngio_mock_set_init_result(int result);
void libnngio_mock_set_send_result(int result);
void libnngio_mock_set_recv_result(int result);
void libnngio_mock_set_send_async_result(int result);
void libnngio_mock_set_recv_async_result(int result);

// Allow tests to set the buffer returned by recv/recv_async
void libnngio_mock_set_recv_buffer(const void *buf, size_t len);

// Optionally clear/reset stats and buffers before/after tests
void libnngio_mock_reset(void);
#endif  // NNGIO_MOCK_MAIN

#endif  // LIBNNGIO_MAIN_H
