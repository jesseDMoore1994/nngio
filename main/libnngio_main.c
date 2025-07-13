#include "main/libnngio_main.h"

#include <nng/nng.h>
#include <nng/protocol/bus0/bus.h>
#include <nng/protocol/pair1/pair.h>
#include <nng/protocol/pipeline0/pull.h>
#include <nng/protocol/pipeline0/push.h>
#include <nng/protocol/pubsub0/pub.h>
#include <nng/protocol/pubsub0/sub.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/protocol/survey0/respond.h>
#include <nng/protocol/survey0/survey.h>
#include <nng/supplemental/tls/tls.h>
#include <nng/supplemental/util/platform.h>  // for nng_msleep if needed for timer
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Context data structure
struct libnngio_ctx {
  nng_socket sock;
  nng_dialer dialer;
  nng_listener listener;
  int is_open;
  int is_dial;
  int id;  // Unique ID for this context
  // Store allocated PEM buffers to free on ctx free
  char *tls_cert_mem;
  char *tls_key_mem;
  char *tls_ca_mem;
};

static int free_id = 0;  // Global ID counter for contexts

// Helper: Read a file into a NUL-terminated string buffer
static char *libnngio_read_file(const char *filename) {
  FILE *f = fopen(filename, "rb");
  char *buf = NULL;
  long sz;
  if (!f) return NULL;
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return NULL;
  }
  sz = ftell(f);
  if (sz < 0) {
    fclose(f);
    return NULL;
  }
  rewind(f);
  buf = (char *)malloc(sz + 1);
  if (!buf) {
    fclose(f);
    return NULL;
  }
  if (fread(buf, 1, sz, f) != (size_t)sz) {
    free(buf);
    fclose(f);
    return NULL;
  }
  buf[sz] = 0;
  fclose(f);
  return buf;
}

static int libnngio_proto_open(nng_socket *sock, libnngio_proto proto) {
  switch (proto) {
    case LIBNNGIO_PROTO_PAIR:
      return nng_pair_open(sock);
    case LIBNNGIO_PROTO_REQ:
      return nng_req_open(sock);
    case LIBNNGIO_PROTO_REP:
      return nng_rep_open(sock);
    case LIBNNGIO_PROTO_PUB:
      return nng_pub_open(sock);
    case LIBNNGIO_PROTO_SUB:
      return nng_sub_open(sock);
    case LIBNNGIO_PROTO_PUSH:
      return nng_push_open(sock);
    case LIBNNGIO_PROTO_PULL:
      return nng_pull_open(sock);
    case LIBNNGIO_PROTO_SURVEYOR:
      return nng_surveyor_open(sock);
    case LIBNNGIO_PROTO_RESPONDENT:
      return nng_respondent_open(sock);
    case LIBNNGIO_PROTO_BUS:
      return nng_bus_open(sock);
    default:
      return NNG_ENOTSUP;
  }
}

static char *libnngio_proto_name(libnngio_proto proto) {
  switch (proto) {
    case LIBNNGIO_PROTO_PAIR:
      return "pair";
    case LIBNNGIO_PROTO_REQ:
      return "req";
    case LIBNNGIO_PROTO_REP:
      return "rep";
    case LIBNNGIO_PROTO_PUB:
      return "pub";
    case LIBNNGIO_PROTO_SUB:
      return "sub";
    case LIBNNGIO_PROTO_PUSH:
      return "push";
    case LIBNNGIO_PROTO_PULL:
      return "pull";
    case LIBNNGIO_PROTO_SURVEYOR:
      return "survey";
    case LIBNNGIO_PROTO_RESPONDENT:
      return "respondent";
    case LIBNNGIO_PROTO_BUS:
      return "bus";
    default:
      return NULL;
  }
}

// Configure the TLS config object on dialer/listener
static int libnngio_configure_tls(libnngio_ctx *ctx, nng_dialer dialer,
                                  nng_listener listener, int is_dial,
                                  const char *certfile, const char *keyfile,
                                  const char *cacert) {
  nng_tls_config *tls = NULL;
  int rv = 0;
  char *certbuf = NULL, *keybuf = NULL, *cabuf = NULL;

  if (is_dial) {
    rv = nng_dialer_get_ptr(dialer, NNG_OPT_TLS_CONFIG, (void **)&tls);
  } else {
    rv = nng_listener_get_ptr(listener, NNG_OPT_TLS_CONFIG, (void **)&tls);
  }
  if (rv != 0 || tls == NULL) {
    return 0;  // No TLS config; not an error unless TLS is required
  }

  // Read cert and key if supplied
  if (certfile != NULL) {
    certbuf = libnngio_read_file(certfile);
    if (!certbuf) return NNG_EINVAL;
    ctx->tls_cert_mem = certbuf;
    // Use keyfile if supplied, else certfile (for combined file)
    if (keyfile && strcmp(certfile, keyfile) != 0) {
      keybuf = libnngio_read_file(keyfile);
      if (!keybuf) return NNG_EINVAL;
      ctx->tls_key_mem = keybuf;
    } else {
      keybuf = certbuf;
    }
    rv = nng_tls_config_own_cert(tls, certbuf, keybuf, NULL);
    if (rv != 0) return rv;
  }
  if (cacert != NULL) {
    cabuf = libnngio_read_file(cacert);
    if (!cabuf) return NNG_EINVAL;
    ctx->tls_ca_mem = cabuf;
    rv = nng_tls_config_ca_chain(tls, cabuf, NULL);
    if (rv != 0) return rv;
  }
  return 0;
}

static int libnngio_apply_options(nng_socket sock, const libnngio_option *opts,
                                  size_t nopts) {
  int rv = 0;
  for (size_t i = 0; i < nopts; ++i) {
    rv = nng_socket_set(sock, opts[i].key, (void *)opts[i].value,
                        strlen(opts[i].value));
    if (rv != 0) return rv;
  }
  return 0;
}

int libnngio_init(libnngio_ctx **ctxp, const libnngio_config *config) {
  printf("libnngio_init: Initializing context\n");
  if (!ctxp || !config) return NNG_EINVAL;
  int rv;
  libnngio_ctx *ctx = calloc(1, sizeof(*ctx));
  if (!ctx) return NNG_ENOMEM;

  ctx->id = free_id++;

  ctx->is_dial = (config->mode == LIBNNGIO_MODE_DIAL);

  printf("libnngio_init (ctx %d): Opening socket\n", ctx->id);
  printf("libnngio_init (ctx %d): Protocol %s, URL %s\n", ctx->id,
         libnngio_proto_name(config->proto), config->url);
  rv = libnngio_proto_open(&ctx->sock, config->proto);
  if (rv != 0) {
    free(ctx);
    return rv;
  }

  if (ctx->is_dial) {
    printf("libnngio_init (ctx %d): Creating dialer for URL %s\n", ctx->id,
           config->url);
    rv = nng_dialer_create(&ctx->dialer, ctx->sock, config->url);
    if (rv != 0) {
      nng_close(ctx->sock);
      free(ctx);
      return rv;
    }
  } else {
    printf("libnngio_init (ctx %d): Creating listener for URL %s\n", ctx->id,
           config->url);
    rv = nng_listener_create(&ctx->listener, ctx->sock, config->url);
    if (rv != 0) {
      nng_close(ctx->sock);
      free(ctx);
      return rv;
    }
  }

  printf("libnngio_init (ctx %d): Setting tls options\n", ctx->id);
  rv = libnngio_configure_tls(ctx, ctx->dialer, ctx->listener, ctx->is_dial,
                              config->tls_cert, config->tls_key,
                              config->tls_ca_cert);
  if (rv != 0) {
    printf("libnngio_init (ctx %d): TLS configuration failed with error %d\n",
           ctx->id, rv);
    if (ctx->is_dial)
      nng_dialer_close(ctx->dialer);
    else
      nng_listener_close(ctx->listener);
    nng_close(ctx->sock);
    free(ctx);
    return rv;
  }

  if (config->options && config->option_count > 0) {
    rv = libnngio_apply_options(ctx->sock, config->options,
                                config->option_count);
    if (rv != 0) {
      printf("libnngio_init (ctx %d): Failed to apply options with error %d\n",
             ctx->id, rv);
      if (ctx->is_dial)
        nng_dialer_close(ctx->dialer);
      else
        nng_listener_close(ctx->listener);
      nng_close(ctx->sock);
      free(ctx);
      return rv;
    }
  }

  if (config->recv_timeout_ms > 0)
    nng_socket_set_ms(ctx->sock, NNG_OPT_RECVTIMEO, config->recv_timeout_ms);
  if (config->send_timeout_ms > 0)
    nng_socket_set_ms(ctx->sock, NNG_OPT_SENDTIMEO, config->send_timeout_ms);
  if (config->max_msg_size > 0)
    nng_socket_set_size(ctx->sock, NNG_OPT_RECVMAXSZ, config->max_msg_size);

  if (ctx->is_dial) {
    printf("libnngio_init (ctx %d): Starting dialer\n", ctx->id);
    rv = nng_dialer_start(ctx->dialer, 0);
  } else {
    printf("libnngio_init (ctx %d): Starting listener\n", ctx->id);
    rv = nng_listener_start(ctx->listener, 0);
  }

  if (rv != 0) {
    printf("libnngio_init (ctx %d): Failed to start %s with error %d\n",
           ctx->id, ctx->is_dial ? "dialer" : "listener", rv);
    if (ctx->is_dial)
      nng_dialer_close(ctx->dialer);
    else
      nng_listener_close(ctx->listener);
    nng_close(ctx->sock);
    free(ctx);
    return rv;
  }

  ctx->is_open = 1;
  *ctxp = ctx;

  printf("libnngio_init (ctx %d): Context initialized successfully\n", ctx->id);
  return 0;
}

int libnngio_send(libnngio_ctx *ctx, const void *buf, size_t len) {
  if (!ctx || !ctx->is_open || !buf || len == 0) return NNG_EINVAL;
  printf("libnngio_send (ctx %d): Sending %zu bytes\n", ctx->id, len);
  return nng_send(ctx->sock, (void *)buf, len, 0);
}

int libnngio_recv(libnngio_ctx *ctx, void *buf, size_t *len) {
  if (!ctx || !ctx->is_open || !buf || !len || *len == 0) return NNG_EINVAL;
  size_t maxlen = *len;
  printf("libnngio_recv (ctx %d): Receiving up to %zu bytes\n", ctx->id, maxlen);
  int rv = nng_recv(ctx->sock, buf, &maxlen, 0);
  if (rv == 0) *len = maxlen;
  return rv;
}

// --- Async context extension ---
typedef struct libnngio_async_op {
  nng_aio *aio;
  void *buf;             // User-provided buffer
  size_t *lenp;          // User-provided length pointer (for recv)
  libnngio_async_cb cb;  // User callback
  void *user_data;       // Opaque user pointer
} libnngio_async_op;

static libnngio_async_op *libnngio_async_op_alloc(void) {
  printf("libnngio_async_op_alloc: Allocating async operation\n");
  libnngio_async_op *op = calloc(1, sizeof(*op));
  return op;
}

static void libnngio_async_op_free(libnngio_async_op *op) {
  if (!op) return;
  printf("libnngio_async_op_free: Freeing async operation\n");
  if (op->aio) nng_aio_reap(op->aio);
  free(op);
}

// --- Async SEND ---
static void libnngio_send_aio_cb(void *arg) {
  libnngio_async_op *op = (libnngio_async_op *)arg;
  int rv = nng_aio_result(op->aio);
  // For send, just inform user of result, data, and length
  op->cb(NULL, rv, op->buf, op->lenp ? *op->lenp : 0, op->user_data);
  libnngio_async_op_free(op);
}

int libnngio_send_async(libnngio_ctx *ctx, const void *buf, size_t len,
                        libnngio_async_cb cb, void *user_data) {
  printf("libnngio_send_async: Starting async send\n");
  if (!ctx || !ctx->is_open || !buf || len == 0 || !cb) return NNG_EINVAL;
  libnngio_async_op *op = libnngio_async_op_alloc();
  if (!op) return NNG_ENOMEM;
  int rv = nng_aio_alloc(&op->aio, libnngio_send_aio_cb, op);
  if (rv != 0) {
    libnngio_async_op_free(op);
    return rv;
  }

  op->buf = (void *)buf;
  op->cb = cb;
  op->user_data = user_data;
  op->lenp = NULL;  // Not used for send

  nng_aio_set_timeout(op->aio, -1);

  nng_msg *msg = NULL;
  rv = nng_msg_alloc(&msg, len);
  if (rv != 0) {
    libnngio_async_op_free(op);
    return rv;
  }
  memcpy(nng_msg_body(msg), buf, len);
  nng_aio_set_msg(op->aio, msg);

  nng_send_aio(ctx->sock, op->aio);
  return 0;
}

// --- Async RECV ---
static void libnngio_recv_aio_cb(void *arg) {
  printf("libnngio_recv_aio_cb: Async receive callback invoked\n");
  libnngio_async_op *op = (libnngio_async_op *)arg;
  int rv = nng_aio_result(op->aio);

  size_t actual = 0;
  if (rv == 0) {
    nng_msg *msg = nng_aio_get_msg(op->aio);
    size_t msglen = nng_msg_len(msg);
    if (op->buf && op->lenp && *(op->lenp) >= msglen) {
      memcpy(op->buf, nng_msg_body(msg), msglen);
      actual = msglen;
      *(op->lenp) = msglen;
    } else if (op->lenp) {
      *(op->lenp) = 0;
      rv = NNG_EMSGSIZE;
    }
    nng_msg_free(msg);
  }
  op->cb(NULL, rv, op->buf, op->lenp ? *(op->lenp) : 0, op->user_data);
  libnngio_async_op_free(op);
}

int libnngio_recv_async(libnngio_ctx *ctx, void *buf, size_t *len,
                        libnngio_async_cb cb, void *user_data) {
  if(!ctx) {
    printf("libnngio_recv_async: Invalid context\n");
    return NNG_EINVAL;
  }
  if(!ctx->is_open) {
    printf("libnngio_recv_async: Context is not open\n");
    return NNG_EINVAL;
  }
  if(!buf || !len || *len == 0) {
    printf("libnngio_recv_async: Invalid buffer or length\n");
    return NNG_EINVAL;
  }
  if(!cb) {
    printf("libnngio_recv_async: Invalid callback\n");
    return NNG_EINVAL;
  }

  libnngio_async_op *op = libnngio_async_op_alloc();
  if (!op) {
    printf("libnngio_recv_async: Failed to allocate async operation\n");
    return NNG_ENOMEM;
  }
  int rv = nng_aio_alloc(&op->aio, libnngio_recv_aio_cb, op);
  if (rv != 0) {
    printf("libnngio_recv_async: Failed to allocate AIO with error %d\n", rv);
    libnngio_async_op_free(op);
    return rv;
  }

  op->buf = buf;
  op->lenp = len;
  op->cb = cb;
  op->user_data = user_data;

  printf("libnngio_recv_async (ctx %d): Setting up async receive\n", ctx->id);
  nng_aio_set_timeout(op->aio, -1);
  nng_recv_aio(ctx->sock, op->aio);
  return 0;
}

// Free all resources associated with context
void libnngio_free(libnngio_ctx *ctx) {
  if (!ctx) return;
  printf("libnngio_free (ctx %d): Freeing context\n", ctx->id);
  if (ctx->is_open) {
    if (ctx->is_dial) {
      printf("libnngio_free (ctx %d): Closing dialer\n", ctx->id);
      nng_dialer_close(ctx->dialer);
    } else {
      printf("libnngio_free (ctx %d): Closing listener\n", ctx->id);
      nng_listener_close(ctx->listener);
    }
    printf("libnngio_free (ctx %d): Closing socket\n", ctx->id);
    nng_close(ctx->sock);
  }

  printf("libnngio_free (ctx %d): Context freed\n", ctx->id);
  // Free TLS PEM buffers if allocated
  if (ctx->tls_cert_mem) free(ctx->tls_cert_mem);
  if (ctx->tls_key_mem && ctx->tls_key_mem != ctx->tls_cert_mem)
    free(ctx->tls_key_mem);
  if (ctx->tls_ca_mem) free(ctx->tls_ca_mem);

  free(ctx);
}

// User-invoked cleanup for global NNG state
void libnngio_cleanup(void) {
  printf("libnngio_cleanup: Finalizing NNG\n");
  nng_fini();
  printf("libnngio_cleanup: NNG finalized\n");
}
