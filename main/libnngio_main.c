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
#include <stdarg.h>
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

static char *libnngio_mode_name(libnngio_mode mode) {
  switch (mode) {
    case LIBNNGIO_MODE_DIAL:
      return "dial";
    case LIBNNGIO_MODE_LISTEN:
      return "listen";
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

void libnngio_log_init(const char *level) {
  // Initialize logging system with the specified level
  if (level == NULL || strlen(level) == 0) {
    nng_log_set_level(NNG_LOG_ERR);  // Default to ERR if no level specified
  } else if (strcmp(level, "DBG") == 0) {
    nng_log_set_level(NNG_LOG_DEBUG);
  } else if (strcmp(level, "INF") == 0) {
    nng_log_set_level(NNG_LOG_INFO);
  } else if (strcmp(level, "WRN") == 0) {
    nng_log_set_level(NNG_LOG_WARN);
  } else if (strcmp(level, "ERR") == 0) {
    nng_log_set_level(NNG_LOG_ERR);
  } else {
    fprintf(stderr, "Unknown log level '%s', defaulting to ERR.\n", level);
    nng_log_set_level(NNG_LOG_ERR);  // Default to ERR
  }
  nng_log_set_logger(nng_stderr_logger);
}

void libnngio_log(const char *level, const char *routine, const char *file,
                  const int line, const int ctxid, const char *msg, ...) {
  // Allocate header and body strings
  char *header = (char *)malloc(1024);
  char *body = (char *)malloc(1024);

  if (!header || !body) {
    // Allocation failed, clean up and return
    free(header);
    free(body);
    return;
  }

  // Create header string
  if (ctxid < 0) {
    snprintf(header, 1024, "%s >>> [%s:%d]", routine, file, line);
  } else {
    snprintf(header, 1024, "%s >>> (Context ID: %d) [%s:%d]", routine, ctxid,
             file, line);
  }

  // Create body string using variadic arguments
  va_list args;
  va_start(args, msg);
  vsnprintf(body, 1024, msg, args);
  va_end(args);

  switch (level[0]) {
    case 'D':
      nng_log_debug(header, body);  // Debug level
      break;
    case 'I':
      nng_log_info(header, body);  // Info level
      break;
    case 'W':
      nng_log_warn(header, body);  // Warning level
      break;
    case 'E':
      nng_log_err(header, body);  // Error level
      break;
    default:
      nng_log_info(header, body);  // Default to info
      // log an error if level is unknown
      fprintf(stderr, "Unknown log level '%s' in %s:%d\n", level, file, line);
      break;
  }

  free(header);
  free(body);
}

static int validate_config(const libnngio_config *config) {
  // Validate the configuration parameters, print an error message if invalid,
  // and return an appropriate error code. Also, make sure protocol and mode
  // are compatible
  if (!config) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "Configuration is NULL.");
    return NNG_EINVAL;
  }
  if (config->mode != LIBNNGIO_MODE_DIAL &&
      config->mode != LIBNNGIO_MODE_LISTEN) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "Invalid mode: %d. Must be DIAL or LISTEN.", config->mode);
    return NNG_EINVAL;
  }
  if (config->proto < LIBNNGIO_PROTO_PAIR ||
      config->proto > LIBNNGIO_PROTO_BUS) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "Invalid protocol: %d.", config->proto);
    return NNG_EINVAL;
  }
  if (!config->url || strlen(config->url) == 0) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "URL is NULL or empty.");
    return NNG_EINVAL;
  }
  if (config->tls_cert && (!config->tls_key || !config->tls_ca_cert)) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "TLS certificate provided without key or CA certificate.");
    return NNG_EINVAL;
  }
  if (config->tls_key && (!config->tls_cert || !config->tls_ca_cert)) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "TLS key provided without certificate or CA certificate.");
    return NNG_EINVAL;
  }
  if (config->recv_timeout_ms < 0 || config->send_timeout_ms < 0 ||
      config->max_msg_size < 0) {
    libnngio_log(
        "ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
        "Negative timeout or max message size: recv=%d, send=%d, max_msg=%d",
        config->recv_timeout_ms, config->send_timeout_ms, config->max_msg_size);
    return NNG_EINVAL;
  }
  if (config->proto == LIBNNGIO_PROTO_PAIR &&
      config->mode != LIBNNGIO_MODE_DIAL &&
      config->mode != LIBNNGIO_MODE_LISTEN) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "PAIR protocol can only be used in DIAL or LISTEN mode.");
    return NNG_EINVAL;
  }
  if (config->proto == LIBNNGIO_PROTO_REQ &&
      config->mode != LIBNNGIO_MODE_DIAL) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "REQ protocol can only be used in DIAL mode.");
    return NNG_EINVAL;
  }
  if (config->proto == LIBNNGIO_PROTO_REP &&
      config->mode != LIBNNGIO_MODE_LISTEN) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "REP protocol can only be used in LISTEN mode.");
    return NNG_EINVAL;
  }
  if (config->proto == LIBNNGIO_PROTO_PUB &&
      config->mode != LIBNNGIO_MODE_LISTEN) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "PUB protocol can only be used in LISTEN mode.");
    return NNG_EINVAL;
  }
  if (config->proto == LIBNNGIO_PROTO_SUB &&
      config->mode != LIBNNGIO_MODE_DIAL) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "SUB protocol can only be used in DIAL mode.");
    return NNG_EINVAL;
  }
  if (config->proto == LIBNNGIO_PROTO_PUSH &&
      config->mode != LIBNNGIO_MODE_LISTEN) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "PUSH protocol can only be used in LISTEN mode.");
    return NNG_EINVAL;
  }
  if (config->proto == LIBNNGIO_PROTO_PULL &&
      config->mode != LIBNNGIO_MODE_DIAL) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "PULL protocol can only be used in DIAL mode.");
    return NNG_EINVAL;
  }
  if (config->proto == LIBNNGIO_PROTO_SURVEYOR &&
      config->mode != LIBNNGIO_MODE_DIAL) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "SURVEYOR protocol can only be used in DIAL mode.");
    return NNG_EINVAL;
  }
  if (config->proto == LIBNNGIO_PROTO_RESPONDENT &&
      config->mode != LIBNNGIO_MODE_LISTEN) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "RESPONDENT protocol can only be used in LISTEN mode.");
    return NNG_EINVAL;
  }
  if (config->proto == LIBNNGIO_PROTO_BUS &&
      config->mode != LIBNNGIO_MODE_LISTEN &&
      config->mode != LIBNNGIO_MODE_DIAL) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "BUS protocol can only be used in DIAL or LISTEN mode.");
    return NNG_EINVAL;
  }
  libnngio_log(
      "DBG", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, free_id,
      "Configuration validated successfully: mode=%s, proto=%s, url=%s",
      libnngio_mode_name(config->mode), libnngio_proto_name(config->proto),
      config->url);
  return 0;
}

int libnngio_init(libnngio_ctx **ctxp, const libnngio_config *config) {
  libnngio_log("DBG", "NNGIO_INIT", __FILE__, __LINE__, free_id,
               "Initializing context.");
  int rv;
  libnngio_ctx *ctx = calloc(1, sizeof(*ctx));
  if (!ctxp || !config) return NNG_EINVAL;
  if (!ctx) return NNG_ENOMEM;
  rv = validate_config(config);
  if (rv != 0) {
    free(ctx);
    return rv;
  }

  ctx->id = free_id++;

  ctx->is_dial = (config->mode == LIBNNGIO_MODE_DIAL);

  libnngio_log("DBG", "NNGIO_INIT", __FILE__, __LINE__, ctx->id,
               "Creating %s context.", libnngio_mode_name(config->mode));
  libnngio_log("DBG", "NNGIO_INIT", __FILE__, __LINE__, ctx->id,
               "Protocol: %s, URL: %s", libnngio_proto_name(config->proto),
               config->url);
  libnngio_log("DBG", "NNGIO_INIT", __FILE__, __LINE__, ctx->id,
               "Opening socket!");
  rv = libnngio_proto_open(&ctx->sock, config->proto);
  if (rv != 0) {
    free(ctx);
    return rv;
  }

  if (config->proto == LIBNNGIO_PROTO_SUB) {
    // Subscribe to all topics
    int rv = nng_socket_set(ctx->sock, NNG_OPT_SUB_SUBSCRIBE, "", 0);
    if (rv != 0) {
      // Handle error (optional: log or abort)
      libnngio_log("DBG", "NNGIO_INIT", __FILE__, __LINE__, ctx->id,
                   "Failed to set SUB subscribe filter: %s\n",
                   nng_strerror(rv));
      return rv;
    }
  }

  if (ctx->is_dial) {
    libnngio_log("INF", "NNGIO_INIT", __FILE__, __LINE__, ctx->id,
                 "Creating dialer for URL %s.\n", config->url);
    rv = nng_dialer_create(&ctx->dialer, ctx->sock, config->url);
    if (rv != 0) {
      nng_close(ctx->sock);
      free(ctx);
      return rv;
    }
  } else {
    libnngio_log("INF", "NNGIO_INIT", __FILE__, __LINE__, ctx->id,
                 "Creating listener for URL %s.\n", config->url);
    rv = nng_listener_create(&ctx->listener, ctx->sock, config->url);
    if (rv != 0) {
      nng_close(ctx->sock);
      free(ctx);
      return rv;
    }
  }

  if (config->tls_cert && config->tls_key && config->tls_ca_cert) {
    libnngio_log("INF", "NNGIO_INIT", __FILE__, __LINE__, ctx->id,
                 "--tls-- cert: %s, key: %s, ca: %s",
                 config->tls_cert ? config->tls_cert : "NULL",
                 config->tls_key ? config->tls_key : "NULL",
                 config->tls_ca_cert ? config->tls_ca_cert : "NULL");
  } else {
    libnngio_log("WRN", "NNGIO_INIT", __FILE__, __LINE__, ctx->id,
                 "--tls-- Not enough information provided for TLS configuration.");
    libnngio_log("WRN", "NNGIO_INIT", __FILE__, __LINE__, ctx->id,
                 "--tls-- cert: %s, key: %s, ca: %s",
                  config->tls_cert ? config->tls_cert : "NULL",
                  config->tls_key ? config->tls_key : "NULL",
                  config->tls_ca_cert ? config->tls_ca_cert : "NULL");
  }
  rv = libnngio_configure_tls(ctx, ctx->dialer, ctx->listener, ctx->is_dial,
                              config->tls_cert, config->tls_key,
                              config->tls_ca_cert);
  if (rv != 0) {
    libnngio_log("ERR", "NNGIO_INIT", __FILE__, __LINE__, ctx->id,
                 "Failed to configure TLS with error %d\n", rv);
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
      libnngio_log("ERR", "NNGIO_INIT", __FILE__, __LINE__, ctx->id,
                   "Failed to apply options with error %d\n", rv);
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
    libnngio_log("INF", "NNGIO_INIT", __FILE__, __LINE__, ctx->id,
                 "Starting dialer for URL: %s.\n", config->url);
    rv = nng_dialer_start(ctx->dialer, 0);
  } else {
    libnngio_log("INF", "NNGIO_INIT", __FILE__, __LINE__, ctx->id,
                 "Starting listener for URL: %s.\n", config->url);
    rv = nng_listener_start(ctx->listener, 0);
  }

  if (rv != 0) {
    libnngio_log("ERR", "NNGIO_INIT", __FILE__, __LINE__, ctx->id,
                 "Failed to start %s with error %d.\n",
                 libnngio_mode_name(config->mode), rv);
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

  libnngio_log("DBG", "NNGIO_INIT", __FILE__, __LINE__, ctx->id,
               "Context initialized successfully: %s %s %s",
               libnngio_mode_name(config->mode),
               libnngio_proto_name(config->proto), config->url);
  return 0;
}

int libnngio_send(libnngio_ctx *ctx, const void *buf, size_t len) {
  if (!ctx || !ctx->is_open || !buf || len == 0) return NNG_EINVAL;
  libnngio_log("INF", "NNGIO_SEND", __FILE__, __LINE__, ctx->id,
               "Sending %zu bytes.\n", len);
  return nng_send(ctx->sock, (void *)buf, len, 0);
}

int libnngio_recv(libnngio_ctx *ctx, void *buf, size_t *len) {
  if (!ctx || !ctx->is_open || !buf || !len || *len == 0) return NNG_EINVAL;
  size_t maxlen = *len;
  libnngio_log("INF", "NNGIO_RECV", __FILE__, __LINE__, ctx->id,
               "Receiving up to %zu bytes.\n", maxlen);
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
  libnngio_async_op *op = calloc(1, sizeof(*op));
  return op;
}

static void libnngio_async_op_free(libnngio_async_op *op) {
  if (!op) return;
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
  if (!ctx) {
    libnngio_log("ERR", "LIBNNGIO_SEND_ASYNC", __FILE__, __LINE__, ctx->id,
                 "Invalid context.\n");
    return NNG_EINVAL;
  }
  if (!ctx->is_open) {
    libnngio_log("ERR", "LIBNNGIO_SEND_ASYNC", __FILE__, __LINE__, ctx->id,
                 "Context is not open.\n");
    return NNG_EINVAL;
  }
  if (!buf || len == 0) {
    libnngio_log("ERR", "LIBNNGIO_SEND_ASYNC", __FILE__, __LINE__, ctx->id,
                 "Invalid buffer or length.\n");
    return NNG_EINVAL;
  }
  if (!cb) {
    libnngio_log("ERR", "LIBNNGIO_SEND_ASYNC", __FILE__, __LINE__, ctx->id,
                 "Invalid callback function.\n");
    return NNG_EINVAL;
  }
  libnngio_async_op *op = libnngio_async_op_alloc();
  if (!op) {
    libnngio_log("ERR", "LIBNNGIO_RECV_ASYNC", __FILE__, __LINE__, ctx->id,
                 "Failed to allocate async operation.\n");
    return NNG_ENOMEM;
  }
  int rv = nng_aio_alloc(&op->aio, libnngio_send_aio_cb, op);
  if (rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_RECV_ASYNC", __FILE__, __LINE__, ctx->id,
                 "Failed to allocate AIO with error %d.\n", rv);
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

  libnngio_log("INF", "LIBNNGIO_SEND_ASYNC", __FILE__, __LINE__, ctx->id,
               "Setting up async send of %zu bytes.\n", len);
  nng_send_aio(ctx->sock, op->aio);
  return 0;
}

// --- Async RECV ---
static void libnngio_recv_aio_cb(void *arg) {
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
  if (!ctx) {
    libnngio_log("ERR", "LIBNNGIO_RECV_ASYNC", __FILE__, __LINE__, ctx->id,
                 "Invalid context.\n");
    return NNG_EINVAL;
  }
  if (!ctx->is_open) {
    libnngio_log("ERR", "LIBNNGIO_RECV_ASYNC", __FILE__, __LINE__, ctx->id,
                 "Context is not open.\n");
    return NNG_EINVAL;
  }
  if (!buf || !len || *len == 0) {
    libnngio_log("ERR", "LIBNNGIO_RECV_ASYNC", __FILE__, __LINE__, ctx->id,
                 "Invalid buffer or length.\n");
    return NNG_EINVAL;
  }
  if (!cb) {
    libnngio_log("ERR", "LIBNNGIO_RECV_ASYNC", __FILE__, __LINE__, ctx->id,
                 "Invalid callback function.\n");
    return NNG_EINVAL;
  }

  libnngio_async_op *op = libnngio_async_op_alloc();
  if (!op) {
    libnngio_log("ERR", "LIBNNGIO_RECV_ASYNC", __FILE__, __LINE__, ctx->id,
                 "Failed to allocate async operation.\n");
    return NNG_ENOMEM;
  }
  int rv = nng_aio_alloc(&op->aio, libnngio_recv_aio_cb, op);
  if (rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_RECV_ASYNC", __FILE__, __LINE__, ctx->id,
                 "Failed to allocate AIO with error %d.\n", rv);
    libnngio_async_op_free(op);
    return rv;
  }

  op->buf = buf;
  op->lenp = len;
  op->cb = cb;
  op->user_data = user_data;

  libnngio_log("INF", "LIBNNGIO_RECV_ASYNC", __FILE__, __LINE__, ctx->id,
               "Setting up async receive into buffer of size %zu.\n", *len);
  nng_aio_set_timeout(op->aio, -1);
  nng_recv_aio(ctx->sock, op->aio);
  return 0;
}

// Free all resources associated with context
void libnngio_free(libnngio_ctx *ctx) {
  if (!ctx) return;
  libnngio_log("DBG", "LIBNNGIO_FREE", __FILE__, __LINE__, ctx->id,
               "Freeing context.\n");
  if (ctx->is_open) {
    if (ctx->is_dial) {
      libnngio_log("DBG", "LIBNNGIO_FREE", __FILE__, __LINE__, ctx->id,
                   "Closing dialer for context.\n");
      nng_dialer_close(ctx->dialer);
    } else {
      libnngio_log("DBG", "LIBNNGIO_FREE", __FILE__, __LINE__, ctx->id,
                   "Closing listener for context.\n");
      nng_listener_close(ctx->listener);
    }
    libnngio_log("DBG", "LIBNNGIO_FREE", __FILE__, __LINE__, ctx->id,
                 "Closing socket for context.\n");
    nng_close(ctx->sock);
  }

  libnngio_log("INF", "LIBNNGIO_FREE", __FILE__, __LINE__, ctx->id,
               "Context freed successfully.\n");
  // Free TLS PEM buffers if allocated
  if (ctx->tls_cert_mem) free(ctx->tls_cert_mem);
  if (ctx->tls_key_mem && ctx->tls_key_mem != ctx->tls_cert_mem)
    free(ctx->tls_key_mem);
  if (ctx->tls_ca_mem) free(ctx->tls_ca_mem);

  free(ctx);
}

// User-invoked cleanup for global NNG state
void libnngio_cleanup(void) {
  libnngio_log("INF", "LIBNNGIO_CLEANUP", __FILE__, __LINE__, -1,
               "Cleaning up global NNG state.\n");
  nng_fini();
}
