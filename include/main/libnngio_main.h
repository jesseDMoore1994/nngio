#ifndef LIBNNGIO_MAIN_H
#define LIBNNGIO_MAIN_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

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

typedef struct libnngio_ctx libnngio_ctx;

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

// Callback type for async send/recv
typedef void (*libnngio_async_cb)(libnngio_ctx *ctx, int result, void *data,
                                  size_t len, void *user_data);

// Core API (sync)
void libnngio_log(const char *level, const char *tag, const char *file,
                  int line, int id, const char *fmt, ...);
int libnngio_init(libnngio_ctx **ctxp, const libnngio_config *config);
int libnngio_send(libnngio_ctx *ctx, const void *buf, size_t len);
int libnngio_recv(libnngio_ctx *ctx, void *buf, size_t *len);
void libnngio_free(libnngio_ctx *ctx);

// Async API
int libnngio_send_async(libnngio_ctx *ctx, const void *buf, size_t len,
                        libnngio_async_cb cb, void *user_data);
int libnngio_recv_async(libnngio_ctx *ctx, void *buf, size_t *len,
                        libnngio_async_cb cb, void *user_data);

// Cleanup global NNG state (calls nng_fini). Safe to call multiple times.
// after this, no more libnngio functions should be called.
void libnngio_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif  // LIBNNGIO_MAIN_H
