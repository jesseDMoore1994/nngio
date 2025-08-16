#include <nng/nng.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "main/libnngio_main.h"

// Mock context structure
struct libnngio_transport {
  int is_open;
};

// Mock stats and helpers (no conditional guards needed in this file)
libnngio_mock_stats mock_stats = {0};

static int forced_init_result = 0;
static int forced_send_result = 0;
static int forced_recv_result = 0;
static int forced_send_async_result = 0;
static int forced_recv_async_result = 0;

// Buffer to use for mocked receive
static unsigned char mock_recv_buffer[1024];
static size_t mock_recv_buffer_len = 0;

// ========================
// libnngio public API
// ========================

char *test_logging_level = NULL;
void libnngio_log_init(const char *level) {
  // In mock, we just print to stdout
  if (level) {
    fprintf(stdout, "Logging initialized with level: %s\n", level);
    test_logging_level = strdup(level);
  } else {
    fprintf(stdout, "Logging initialized with level: ERR\n");
    test_logging_level = strdup("ERR");  // Default to ERR if NULL
  }
}

void libnngio_log(const char *level, const char *tag, const char *file,
                  int line, int id, const char *fmt, ...) {
  nng_log_level system_level = NNG_LOG_ERR;  // Default to ERR
  switch (test_logging_level[0]) {
    case 'D':
      system_level = NNG_LOG_DEBUG;
      break;
    case 'I':
      system_level = NNG_LOG_INFO;
      break;
    case 'N':
      system_level = NNG_LOG_NOTICE;
      break;
    case 'W':
      system_level = NNG_LOG_WARN;
      break;
    case 'E':
      system_level = NNG_LOG_ERR;
      break;
    default:
      system_level = NNG_LOG_ERR;  // Default to ERR if unknown
  }

  nng_log_level msg_level = NNG_LOG_ERR;
  switch (level[0]) {
    case 'D':
      msg_level = NNG_LOG_DEBUG;
      break;
    case 'I':
      msg_level = NNG_LOG_INFO;
      break;
    case 'N':
      msg_level = NNG_LOG_NOTICE;
      break;
    case 'W':
      msg_level = NNG_LOG_WARN;
      break;
    case 'E':
      msg_level = NNG_LOG_ERR;
      break;
    default:
      msg_level = NNG_LOG_ERR;  // Default to ERR if unknown
  }

  if (msg_level <= system_level) {
    fprintf(stdout, "[%s (%d)]", test_logging_level, system_level);
    va_list args;
    va_start(args, fmt);
    fprintf(stdout, "[%s (%d)][%s][%s:%d][%d] ", level, msg_level, tag, file, line, id);
    vfprintf(stdout, fmt, args);
    fprintf(stdout, "\n");
    va_end(args);
  }
}

int libnngio_transport_init(libnngio_transport **ctxp, const libnngio_config *config) {
  mock_stats.init_calls++;
  mock_stats.last_init_result = forced_init_result;
  mock_stats.last_init.ctx = NULL;
  mock_stats.last_init.buf = config;
  mock_stats.last_init.len = 0;

  libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_INIT", __FILE__, __LINE__, 0,
              "Initializing libnngio transport with config: %p", (void *)config);
  if (forced_init_result != 0) {
    libnngio_log("ERR", "MOCK_LIBNNGIO_TRANSPORT_INIT", __FILE__, __LINE__, 0,
                 "Forced init error: %d", forced_init_result);
    return forced_init_result;
  }

  *ctxp = calloc(1, sizeof(struct libnngio_transport));
  if (!*ctxp) {
    libnngio_log("ERR", "MOCK_LIBNNGIO_TRANSPORT_INIT", __FILE__, __LINE__, 0,
                 "Failed to allocate transport");
    return -1;
  }
  (*ctxp)->is_open = 1;
  libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_INIT", __FILE__, __LINE__, 0,
              "Initialized transport: %p", (void *)*ctxp);
  return 0;
}

int libnngio_transport_send(libnngio_transport *ctx, const void *buf, size_t len) {
  mock_stats.send_calls++;
  mock_stats.last_send_result = forced_send_result;
  mock_stats.last_send.ctx = ctx;
  mock_stats.last_send.buf = buf;
  mock_stats.last_send.len = len;

  libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_SEND", __FILE__, __LINE__, 0,
              "Sending %zu bytes", len);
  if (forced_send_result != 0) {
    libnngio_log("ERR", "MOCK_LIBNNGIO_TRANSPORT_SEND", __FILE__, __LINE__, 0,
                 "Forced send error: %d", forced_send_result);
    return forced_send_result;
  }
  if (!ctx || !ctx->is_open) {
    libnngio_log("ERR", "MOCK_LIBNNGIO_TRANSPORT_SEND", __FILE__, __LINE__, 0,
                 "Invalid context or context not open");
    return -1;
  }
  libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_SEND", __FILE__, __LINE__, 0,
              "Sent %zu bytes successfully", len);
  return 0;
}

int libnngio_transport_recv(libnngio_transport *ctx, void *buf, size_t *len) {
  mock_stats.recv_calls++;
  mock_stats.last_recv_result = forced_recv_result;
  mock_stats.last_recv.ctx = ctx;
  mock_stats.last_recv.buf = buf;
  mock_stats.last_recv.len_ptr = len;

  libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_RECV", __FILE__, __LINE__, 0,
              "Receiving data");
  if (forced_recv_result != 0) {
    libnngio_log("ERR", "MOCK_LIBNNGIO_TRANSPORT_RECV", __FILE__, __LINE__, 0,
                 "Forced receive error: %d", forced_recv_result);
    return forced_recv_result;
  }
  if (!ctx || !ctx->is_open || !buf || !len) {
    libnngio_log("ERR", "MOCK_LIBNNGIO_TRANSPORT_RECV", __FILE__, __LINE__, 0,
                 "Invalid context, buffer, or length pointer");
    return -1;
  }

  size_t copy_len = mock_recv_buffer_len < *len ? mock_recv_buffer_len : *len;
  memcpy(buf, mock_recv_buffer, copy_len);
  *len = copy_len;
  libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_RECV", __FILE__, __LINE__, 0,
              "Received %zu bytes successfully", copy_len);
  return 0;
}

void libnngio_transport_free(libnngio_transport *ctx) {
  libnngio_log("DBG", "MOCK_LIBNNGIO_FREE", __FILE__, __LINE__, 0,
              "Freeing context: %p", (void *)ctx);
  mock_stats.free_calls++;
  if (ctx) {
    libnngio_log("DBG", "MOCK_LIBNNGIO_FREE", __FILE__, __LINE__, 0,
                "Context is open, closing it");
    ctx->is_open = 0;
    free(ctx);
  }
  libnngio_log("DBG", "MOCK_LIBNNGIO_FREE", __FILE__, __LINE__, 0,
              "Context freed successfully");
}

int libnngio_transport_send_async(libnngio_transport *ctx, const void *buf, size_t len,
                        libnngio_async_cb cb, void *user_data) {
  mock_stats.send_async_calls++;
  mock_stats.last_send_async_result = forced_send_async_result;
  mock_stats.last_send_async.ctx = ctx;
  mock_stats.last_send_async.buf = buf;
  mock_stats.last_send_async.len = len;
  mock_stats.last_send_async.cb = cb;
  mock_stats.last_send_async.user_data = user_data;

  libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_SEND_ASYNC", __FILE__, __LINE__, 0,
              "Sending %zu bytes asynchronously", len);
  if (forced_send_async_result != 0) {
    libnngio_log("ERR", "MOCK_LIBNNGIO_TRANSPORT_SEND_ASYNC", __FILE__, __LINE__, 0,
                 "Forced send async error: %d", forced_send_async_result);
    return forced_send_async_result;
  }
  int rv = libnngio_transport_send(ctx, buf, len);
  if (cb) {
    libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_SEND_ASYNC", __FILE__, __LINE__, 0,
                "Calling async callback with result %d", rv);
    cb(ctx, rv, (void *)buf, len, user_data);
    libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_SEND_ASYNC", __FILE__, __LINE__, 0,
                "Async callback completed");
  } else {
    libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_SEND_ASYNC", __FILE__, __LINE__, 0,
                "No async callback provided, returning result %d", rv);
  }
  return rv;
}

int libnngio_transport_recv_async(libnngio_transport *ctx, void *buf, size_t *len,
                        libnngio_async_cb cb, void *user_data) {
  mock_stats.recv_async_calls++;
  mock_stats.last_recv_async_result = forced_recv_async_result;
  mock_stats.last_recv_async.ctx = ctx;
  mock_stats.last_recv_async.buf = buf;
  mock_stats.last_recv_async.len_ptr = len;
  mock_stats.last_recv_async.cb = cb;
  mock_stats.last_recv_async.user_data = user_data;

  libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_RECV_ASYNC", __FILE__, __LINE__, 0,
              "Receiving data asynchronously");
  if (forced_recv_async_result != 0) {
    libnngio_log("ERR", "MOCK_LIBNNGIO_TRANSPORT_RECV_ASYNC", __FILE__, __LINE__, 0,
                 "Forced receive async error: %d", forced_recv_async_result);
    return forced_recv_async_result;
  }

  int rv = libnngio_transport_recv(ctx, buf, len);
  if (cb) {
    libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_RECV_ASYNC", __FILE__, __LINE__, 0,
                "Calling async callback with result %d", rv);
    cb(ctx, rv, buf, len ? *len : 0, user_data);
    libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_RECV_ASYNC", __FILE__, __LINE__, 0,
                "Async callback completed");
  } else {
    libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_RECV_ASYNC", __FILE__, __LINE__, 0,
                "No async callback provided, returning result %d", rv);
  }
  return rv;
}

struct libnngio_context {
  int id;  // Unique identifier for the context
  void *user_data;  // Opaque user data pointer
  libnngio_ctx_cb cb;  // Callback function for context events
};
static int free_context_id = 0;  // Global counter for context IDs

int libnngio_context_init(libnngio_context **ctxp, libnngio_transport *transport,
                          const libnngio_config *config, libnngio_ctx_cb cb,
                          void *user_data) {
  if (!ctxp || !transport || !config) {
    return NNG_EINVAL;
  }

  libnngio_context *ctx = calloc(1, sizeof(libnngio_context));
  if (!ctx) {
    return NNG_ENOMEM;
  }

  ctx->id = free_context_id++;  // Assign a random ID for simplicity
  ctx->user_data = user_data;
  ctx->cb = cb;
  *ctxp = ctx;

  return 0;
}

void libnngio_context_start(libnngio_context *ctx) {
  if (!ctx) return;
  libnngio_log("DBG", "MOCK_LIBNNGIO_CONTEXT_START", __FILE__, __LINE__, ctx->id,
              "Starting context with ID %d", ctx->id);
  if (ctx->cb) {
    libnngio_log("DBG", "MOCK_LIBNNGIO_CONTEXT_START", __FILE__, __LINE__, ctx->id,
                "Invoking context callback for ID %d", ctx->id);
    ctx->cb(ctx);  // Call the user-defined callback
  } else {
    libnngio_log("DBG", "MOCK_LIBNNGIO_CONTEXT_START", __FILE__, __LINE__, ctx->id,
                "No callback defined for context ID %d", ctx->id);
  }
}

void libnngio_context_set_user_data(libnngio_context *ctx, void *user_data) {
  if (ctx) {
    libnngio_log("DBG", "MOCK_LIBNNGIO_CONTEXT_SET_USER_DATA", __FILE__, __LINE__,
                ctx->id, "Setting user data for context ID %d", ctx->id);
    ctx->user_data = user_data;
  }
}

void *libnngio_context_get_user_data(libnngio_context *ctx) {
  if (!ctx) return NULL;
  libnngio_log("DBG", "MOCK_LIBNNGIO_CONTEXT_GET_USER_DATA", __FILE__, __LINE__,
              ctx->id, "Retrieving user data for context ID %d", ctx->id);
  return ctx->user_data;
}

void libnngio_context_free(libnngio_context *ctx) {
  if (ctx) {
    libnngio_log("DBG", "MOCK_LIBNNGIO_CONTEXT_FREE", __FILE__, __LINE__, ctx->id,
                "Freeing context with ID %d", ctx->id);
    free(ctx);
  }
}

int libnngio_contexts_init(libnngio_context ***ctxs, size_t n,
                           libnngio_transport *transport,
                           const libnngio_config *config, libnngio_ctx_cb cb,
                           void **user_datas) {
  if (!ctxs || !transport || !config || n == 0) {
    return NNG_EINVAL;
  }

  *ctxs = calloc(n, sizeof(libnngio_context *));
  if (!*ctxs) {
    return NNG_ENOMEM;
  }

  for (size_t i = 0; i < n; i++) {
    libnngio_context *ctx;
    int rv = libnngio_context_init(&ctx, transport, config, cb,
                                   user_datas ? user_datas[i] : NULL);
    if (rv != 0) {
      for (size_t j = 0; j < i; j++) {
        libnngio_context_free((*ctxs)[j]);
      }
      free(*ctxs);
      *ctxs = NULL;
      return rv;
    }
    (*ctxs)[i] = ctx;
  }

  return 0;
}

void libnngio_contexts_free(libnngio_context **ctxs, size_t n) {
  if (!ctxs) return;
  for (size_t i = 0; i < n; i++) {
    if (ctxs[i]) {
      libnngio_log("DBG", "MOCK_LIBNNGIO_CONTEXTS_FREE", __FILE__, __LINE__, i,
                  "Freeing context with ID %d", ctxs[i]->id);
      libnngio_context_free(ctxs[i]);
    }
  }
  free(ctxs);
}

void libnngio_contexts_start(libnngio_context **ctxs, size_t n) {
  if (!ctxs || n == 0) return;
  for (size_t i = 0; i < n; i++) {
    if (ctxs[i]) {
      libnngio_log("DBG", "MOCK_LIBNNGIO_CONTEXTS_START", __FILE__, __LINE__, i,
                  "Starting context with ID %d", ctxs[i]->id);
      libnngio_context_start(ctxs[i]);
    }
  }
}

void libnngio_cleanup(void) {
  if (test_logging_level) {
    free(test_logging_level);
    test_logging_level = NULL;
  }
}

// ===============================================================================
// MOCKING SUPPORT BELOW -- These APIs are only available if using the mock
// library
// ===============================================================================

void libnngio_mock_set_init_result(int result) { forced_init_result = result; }
void libnngio_mock_set_send_result(int result) { forced_send_result = result; }
void libnngio_mock_set_recv_result(int result) { forced_recv_result = result; }
void libnngio_mock_set_send_async_result(int result) {
  forced_send_async_result = result;
}
void libnngio_mock_set_recv_async_result(int result) {
  forced_recv_async_result = result;
}

void libnngio_mock_set_recv_buffer(const void *buf, size_t len) {
  size_t copy_len =
      len < sizeof(mock_recv_buffer) ? len : sizeof(mock_recv_buffer);
  memcpy(mock_recv_buffer, buf, copy_len);
  mock_recv_buffer_len = copy_len;
}

void libnngio_mock_reset(void) {
  memset(&mock_stats, 0, sizeof(mock_stats));
  memset(mock_recv_buffer, 0, sizeof(mock_recv_buffer));
  mock_recv_buffer_len = 0;
  forced_init_result = forced_send_result = forced_recv_result = 0;
  forced_send_async_result = forced_recv_async_result = 0;
}
