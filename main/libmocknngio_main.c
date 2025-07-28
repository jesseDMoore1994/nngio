#include <nng/nng.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "main/libnngio_main.h"

// Mock context structure
struct libnngio_ctx {
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

int libnngio_init(libnngio_ctx **ctxp, const libnngio_config *config) {
  mock_stats.init_calls++;
  mock_stats.last_init_result = forced_init_result;
  mock_stats.last_init.ctx = NULL;
  mock_stats.last_init.buf = config;
  mock_stats.last_init.len = 0;

  if (forced_init_result != 0) return forced_init_result;
  *ctxp = calloc(1, sizeof(struct libnngio_ctx));
  if (!*ctxp) return -1;
  (*ctxp)->is_open = 1;
  return 0;
}

int libnngio_send(libnngio_ctx *ctx, const void *buf, size_t len) {
  mock_stats.send_calls++;
  mock_stats.last_send_result = forced_send_result;
  mock_stats.last_send.ctx = ctx;
  mock_stats.last_send.buf = buf;
  mock_stats.last_send.len = len;

  if (forced_send_result != 0) return forced_send_result;
  if (!ctx || !ctx->is_open) return -1;
  return 0;
}

int libnngio_recv(libnngio_ctx *ctx, void *buf, size_t *len) {
  mock_stats.recv_calls++;
  mock_stats.last_recv_result = forced_recv_result;
  mock_stats.last_recv.ctx = ctx;
  mock_stats.last_recv.buf = buf;
  mock_stats.last_recv.len_ptr = len;

  if (forced_recv_result != 0) return forced_recv_result;
  if (!ctx || !ctx->is_open || !buf || !len) return -1;

  size_t copy_len = mock_recv_buffer_len < *len ? mock_recv_buffer_len : *len;
  memcpy(buf, mock_recv_buffer, copy_len);
  *len = copy_len;
  return 0;
}

void libnngio_free(libnngio_ctx *ctx) {
  mock_stats.free_calls++;
  if (ctx) {
    ctx->is_open = 0;
    free(ctx);
  }
}

int libnngio_send_async(libnngio_ctx *ctx, const void *buf, size_t len,
                        libnngio_async_cb cb, void *user_data) {
  mock_stats.send_async_calls++;
  mock_stats.last_send_async_result = forced_send_async_result;
  mock_stats.last_send_async.ctx = ctx;
  mock_stats.last_send_async.buf = buf;
  mock_stats.last_send_async.len = len;
  mock_stats.last_send_async.cb = cb;
  mock_stats.last_send_async.user_data = user_data;

  if (forced_send_async_result != 0) return forced_send_async_result;
  int rv = libnngio_send(ctx, buf, len);
  if (cb) cb(ctx, rv, (void *)buf, len, user_data);
  return rv;
}

int libnngio_recv_async(libnngio_ctx *ctx, void *buf, size_t *len,
                        libnngio_async_cb cb, void *user_data) {
  mock_stats.recv_async_calls++;
  mock_stats.last_recv_async_result = forced_recv_async_result;
  mock_stats.last_recv_async.ctx = ctx;
  mock_stats.last_recv_async.buf = buf;
  mock_stats.last_recv_async.len_ptr = len;
  mock_stats.last_recv_async.cb = cb;
  mock_stats.last_recv_async.user_data = user_data;

  if (forced_recv_async_result != 0) return forced_recv_async_result;
  int rv = libnngio_recv(ctx, buf, len);
  if (cb) cb(ctx, rv, buf, len ? *len : 0, user_data);
  return rv;
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
