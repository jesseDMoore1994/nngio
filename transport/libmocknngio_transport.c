/**
 * @file libmocknngio_main.c
 * @brief Mock implementation of libnngio for testing purposes.
 * This file provides a mock version of the libnngio library, allowing for
 * controlled testing of applications that depend on libnngio without requiring
 * actual network operations.
 * The mock implementation includes functions to initialize transports,
 * send and receive data, manage contexts, and simulate errors.
 * It also includes logging functionality to trace operations and their
 * outcomes. The mock library maintains statistics on function calls and allows
 * for setting forced results for various operations.
 *
 * @note This implementation is intended for testing and should not be used
 * in production environments.
 */
#include <nng/nng.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "transport/libnngio_transport.h"

// Mock context structure
struct libnngio_transport {
  int is_open; /**< Indicates if the transport is open */
};

/**
 * @brief Structure to hold statistics for mock operations.
 * This structure tracks the number of calls to various functions,
 * the last results returned, and the parameters used in the last calls.
 */
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

static char *test_logging_level = NULL;
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
    fprintf(stdout, "[%s (%d)][%s][%s:%d][%d] ", level, msg_level, tag, file,
            line, id);
    vfprintf(stdout, fmt, args);
    fprintf(stdout, "\n");
    va_end(args);
  }
}

int libnngio_transport_init(libnngio_transport **ctxp,
                            const libnngio_config *config) {
  mock_stats.init_calls++;
  mock_stats.last_init_result = forced_init_result;
  mock_stats.last_init.ctx = NULL;
  mock_stats.last_init.buf = config;
  mock_stats.last_init.len = 0;

  libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_INIT", __FILE__, __LINE__, 0,
               "Initializing libnngio transport with config: %p",
               (void *)config);
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

struct libnngio_message {
  void *data; /**< Pointer to message data buffer */
  size_t len; /**< Length of message data */
};

/**
 * @brief Create a libnngio message with the given data.
 * @param msg Pointer to pointer to receive allocated message.
 * @param data Pointer to data buffer.
 * @param len Length of data buffer in bytes.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_message_init(libnngio_message **msg, const void *data,
                          size_t len) {
  if (!msg || !data || len == 0) return NNG_EINVAL;
  libnngio_message *m = calloc(1, sizeof(libnngio_message));
  if (!m) return NNG_ENOMEM;
  m->data = malloc(len);
  if (!m->data) {
    free(m);
    return NNG_ENOMEM;
  }
  memcpy(m->data, data, len);
  m->len = len;
  *msg = m;
  return 0;
}

/**
 * @brief Get the data buffer and length from a libnngio message.
 * @param msg Pointer to message.
 * @param data Pointer to receive data buffer pointer.
 * @param len Pointer to receive length of data buffer.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_message_get(libnngio_message *msg, void **data, size_t *len) {
  if (!msg || !data || !len) return NNG_EINVAL;
  *data = msg->data;
  *len = msg->len;
  libnngio_log("DBG", "MOCK_LIBNNGIO_MESSAGE_GET", __FILE__, __LINE__, 0,
               "Getting message data: %s, length: %zu", (char*)msg->data, msg->len);
  return 0;
}

/**
 * @brief Free a libnngio message and release resources.
 * @param msg Pointer to message to free.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_message_free(libnngio_message *msg) {
  if (!msg) return NNG_EINVAL;
  if (msg->data) free(msg->data);
  free(msg);
  return 0;
}

/**
 * @brief Initialize a message ring buffer.
 * @param ring Pointer to pointer to receive ring buffer structure.
 * @param max_size Maximum number of messages the buffer can hold.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_message_ring_buffer_init(libnngio_message_ring_buffer **ring,
                                      size_t max_size) {
  if (!ring || max_size == 0) return NNG_EINVAL;
  libnngio_message_ring_buffer *rb =
      calloc(1, sizeof(libnngio_message_ring_buffer));
  if (!rb) return NNG_ENOMEM;
  rb->buffer = calloc(max_size, sizeof(libnngio_message *));
  if (!rb->buffer) {
    free(rb);
    return NNG_ENOMEM;
  }
  rb->head = 0;
  rb->tail = 0;
  rb->max_size = max_size;
  rb->current_size = 0;
  *ring = rb;
  return 0;
}

/**
 * @brief Free a message ring buffer and its contents.
 * @param ring Pointer to ring buffer to free.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_message_ring_buffer_free(libnngio_message_ring_buffer *ring) {
  if (!ring) return LIBNNGIO_MESSAGE_RING_BUFFER_UNINITIALIZED;
  // Free any messages still in the buffer
  for (size_t i = 0; i < ring->current_size; ++i) {
    size_t index = (ring->head + i) % ring->max_size;
    if (ring->buffer[index]) {
      libnngio_message_free(ring->buffer[index]);
    }
  }
  free(ring->buffer);
  free(ring);
  return LIBNNGIO_MESSAGE_RING_BUFFER_OK;
}

/**
 * @brief Push a message onto the ring buffer.
 * @param ring Pointer to ring buffer.
 * @param msg Pointer to message to push.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_message_ring_buffer_push(libnngio_message_ring_buffer *ring,
                                      libnngio_message *msg) {
  if (!ring || !msg) return LIBNNGIO_MESSAGE_RING_BUFFER_UNINITIALIZED;
  if (ring->current_size == ring->max_size) {
    return LIBNNGIO_MESSAGE_RING_BUFFER_FULL;  // Buffer is full
  }
  ring->buffer[ring->tail] = msg;
  ring->tail = (ring->tail + 1) % ring->max_size;
  ring->current_size++;
  return LIBNNGIO_MESSAGE_RING_BUFFER_OK;
}

/**
 * @brief Pop a message from the ring buffer.
 * @param ring Pointer to ring buffer.
 * @param msg Pointer to receive popped message.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_message_ring_buffer_pop(libnngio_message_ring_buffer *ring,
                                     libnngio_message **msg) {
  if (!ring || !msg) return LIBNNGIO_MESSAGE_RING_BUFFER_UNINITIALIZED;
  libnngio_log("DBG", "MOCK_LIBNNGIO_MESSAGE_RING_BUFFER_POP", __FILE__,
               __LINE__, 0, "Popping message from ring buffer of size %zu",
               ring->current_size);
  if (ring->current_size == 0) {
    return LIBNNGIO_MESSAGE_RING_BUFFER_EMPTY;  // Buffer is empty
  }
  *msg = ring->buffer[ring->head];
  libnngio_log("DBG", "MOCK_LIBNNGIO_MESSAGE_RING_BUFFER_POP", __FILE__,
               __LINE__, 0, "Popped message: %s", (char *)(*msg)->data);
  ring->head = (ring->head + 1) % ring->max_size;
  ring->current_size--;
  return LIBNNGIO_MESSAGE_RING_BUFFER_OK;
}

struct libnngio_context {
  libnngio_transport *transport; /**< Associated transport */
  int id;                        /**< Context ID */
  void *user_data;               /**< User data pointer */
  const libnngio_config *config; /**< Configuration used */
  libnngio_ctx_cb cb;            /**< Context callback */
  int transport_err;             /**< Last transport error */
  libnngio_message_ring_buffer
      *recv_buffer;        /**< Ring buffer for received messages */
  size_t recv_buffer_size; /**< Capacity of receive ring buffer */
  libnngio_message_ring_buffer
      *send_buffer;        /**< Ring buffer for messages to send */
  size_t send_buffer_size; /**< Capacity of send ring buffer */
  int buffer_err;          /**< Last buffer operation error */
};
static int free_context_id = 0; /**< Simple ID generator */

int libnngio_context_init(libnngio_context **ctxp,
                          libnngio_transport *transport,
                          const libnngio_config *config, libnngio_ctx_cb cb,
                          void *user_data) {
  if (!ctxp || !transport || !config) {
    return NNG_EINVAL;
  }

  libnngio_context *ctx = calloc(1, sizeof(libnngio_context));
  if (!ctx) {
    return NNG_ENOMEM;
  }

  ctx->transport = transport;
  ctx->id = free_context_id++;  // Assign a random ID for simplicity
  ctx->config = config;
  ctx->user_data = user_data;
  ctx->cb = cb;
  *ctxp = ctx;

  // Create send/recv buffers
  if (config->send_buffer_size != 0) {
    libnngio_message_ring_buffer_init(&ctx->send_buffer,
                                      config->send_buffer_size);
  }
  if (config->recv_buffer_size != 0) {
    libnngio_message_ring_buffer_init(&ctx->recv_buffer,
                                      config->recv_buffer_size);
  }

  return 0;
}

int libnngio_context_id(libnngio_context *ctx) {
  if (!ctx) return -1;
  return ctx->id;
}

const libnngio_config *libnngio_context_get_config(libnngio_context *ctx) {
  if (!ctx || !ctx->config) return NULL;
  return ctx->config;
}

void libnngio_context_start(libnngio_context *ctx) {
  if (!ctx) return;
  libnngio_log("DBG", "MOCK_LIBNNGIO_CONTEXT_START", __FILE__, __LINE__,
               ctx->id, "Starting context with ID %d", ctx->id);
  if (ctx->cb) {
    libnngio_log("DBG", "MOCK_LIBNNGIO_CONTEXT_START", __FILE__, __LINE__,
                 ctx->id, "Invoking context callback for ID %d", ctx->id);
    ctx->cb(ctx);  // Call the user-defined callback
  } else {
    libnngio_log("DBG", "MOCK_LIBNNGIO_CONTEXT_START", __FILE__, __LINE__,
                 ctx->id, "No callback defined for context ID %d", ctx->id);
  }
}

int libnngio_context_send(libnngio_context *ctx, const void *buf, size_t len) {
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
  if (!ctx || !ctx->transport->is_open) {
    libnngio_log("ERR", "MOCK_LIBNNGIO_TRANSPORT_SEND", __FILE__, __LINE__, 0,
                 "Invalid context or context not open");
    return -1;
  }
  libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_SEND", __FILE__, __LINE__, 0,
               "Sent %zu bytes successfully", len);
  return 0;
}

int libnngio_context_recv(libnngio_context *ctx, void *buf, size_t *len) {
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
  if (!ctx || !ctx->transport->is_open || !buf || !len) {
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

int libnngio_context_recv_into_buffer(libnngio_context *ctx) {
  if (!ctx || !ctx->recv_buffer) return NNG_EINVAL;
  libnngio_message *msg = NULL;
  int rv = 0;
  void *data = NULL;
  size_t len = ctx->config->max_msg_size > 0 ? ctx->config->max_msg_size
                                             : LIBNNGIO_DEFAULT_MAX_MSG_SIZE;
  data = malloc(len);
  if (!data) {
    libnngio_log("ERR", "MOCK_LIBNNGIO_CONTEXT_RECV_INTO_BUFFER", __FILE__,
                 __LINE__, ctx->id,
                 "Failed to allocate memory for receive buffer.");
    return NNG_ENOMEM;
  }

  rv = libnngio_context_recv(ctx, data, &len);
  if (rv != 0) {
    libnngio_log("ERR", "MOCK_LIBNNGIO_CONTEXT_RECV_INTO_BUFFER", __FILE__,
                 __LINE__, ctx->id, "Failed to receive message with error %d.",
                 rv);
    free(data);
    ctx->transport_err = rv;
    return rv;
  }

  rv = libnngio_message_init(&msg, data, len);
  free(data);
  if (rv != 0) {
    libnngio_log("ERR", "MOCK_LIBNNGIO_CONTEXT_RECV_INTO_BUFFER", __FILE__,
                 __LINE__, ctx->id,
                 "Failed to initialize message with error %d.", rv);
    return NNG_ENOMEM;
  }

  rv = libnngio_message_ring_buffer_push(ctx->recv_buffer, msg);
  if (rv != 0) {
    libnngio_log("ERR", "MOCK_LIBNNGIO_CONTEXT_RECV_INTO_BUFFER", __FILE__,
                 __LINE__, ctx->id,
                 "Failed to push message to buffer with error %d.", rv);
    libnngio_message_free(msg);
    ctx->buffer_err = rv;
    return rv;
  }

  libnngio_log("DBG", "MOCK_LIBNNGIO_CONTEXT_RECV_INTO_BUFFER", __FILE__,
               __LINE__, ctx->id, "Received message into buffer successfully.");
  return rv;
}

int libnngio_context_send_async(libnngio_context *ctx, const void *buf,
                                size_t len, libnngio_async_cb cb,
                                void *user_data) {
  mock_stats.send_async_calls++;
  mock_stats.last_send_async_result = forced_send_async_result;
  mock_stats.last_send_async.ctx = ctx;
  mock_stats.last_send_async.buf = buf;
  mock_stats.last_send_async.len = len;
  mock_stats.last_send_async.cb = cb;
  mock_stats.last_send_async.user_data = user_data;

  libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_SEND_ASYNC", __FILE__, __LINE__,
               0, "Sending %zu bytes asynchronously", len);
  if (forced_send_async_result != 0) {
    libnngio_log("ERR", "MOCK_LIBNNGIO_TRANSPORT_SEND_ASYNC", __FILE__,
                 __LINE__, 0, "Forced send async error: %d",
                 forced_send_async_result);
    return forced_send_async_result;
  }
  int rv = libnngio_context_send(ctx, buf, len);
  if (cb) {
    libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_SEND_ASYNC", __FILE__,
                 __LINE__, 0, "Calling async callback with result %d", rv);
    cb(ctx, rv, (void *)buf, len, user_data);
    libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_SEND_ASYNC", __FILE__,
                 __LINE__, 0, "Async callback completed");
  } else {
    libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_SEND_ASYNC", __FILE__,
                 __LINE__, 0, "No async callback provided, returning result %d",
                 rv);
  }
  return rv;
}

int libnngio_context_send_from_buffer_async(libnngio_context *ctx,
                                            libnngio_async_cb cb,
                                            void *user_data) {
  mock_stats.send_async_calls++;
  mock_stats.last_send_async_result = forced_send_async_result;
  mock_stats.last_send_async.ctx = ctx;
  mock_stats.last_send_async.cb = cb;
  mock_stats.last_send_async.user_data = user_data;

  libnngio_message *msg = NULL;
  int rv = 0;

  rv = libnngio_message_ring_buffer_pop(ctx->send_buffer, &msg);
  if (rv != 0) {
    libnngio_log("INF", "LIBNNGIO_CONTEXT_SEND_FROM_BUFFER", __FILE__, __LINE__,
                 ctx->id, "Error in buffer operation: %d", rv);
    libnngio_message_free(msg);
    ctx->buffer_err = rv;
    return rv;
  }

  libnngio_log("DBG", "MOCK_LIBNNGIO_CONTEXT_SEND_FROM_BUFFER_ASYNC", __FILE__, __LINE__,
               0, "Sending %zu bytes asynchronously", msg->len);
  if (forced_send_async_result != 0) {
    libnngio_log("ERR", "MOCK_LIBNNGIO_CONTEXT_SEND_FROM_BUFFER_ASYNC", __FILE__,
                 __LINE__, 0, "Forced send async error: %d",
                 forced_send_async_result);
    return forced_send_async_result;
  }
  rv = libnngio_context_send(ctx, msg->data, msg->len);
  if (cb) {
    libnngio_log("DBG", "MOCK_LIBNNGIO_CONTEXT_SEND_FROM_BUFFER_ASYNC", __FILE__,
                 __LINE__, 0, "Calling async callback with result %d", rv);
    cb(ctx, rv, (void *)msg->data, msg->len, user_data);
    libnngio_log("DBG", "MOCK_LIBNNGIO_CONTEXT_SEND_FROM_BUFFER_ASYNC", __FILE__,
                 __LINE__, 0, "Async callback completed");
  } else {
    libnngio_log("DBG", "MOCK_LIBNNGIO_CONTEXT_SEND_FROM_BUFFER_ASYNC", __FILE__,
                 __LINE__, 0, "No async callback provided, returning result %d",
                 rv);
  }
  libnngio_message_free(msg);
  return rv;
}

int libnngio_context_recv_async(libnngio_context *ctx, void *buf, size_t *len,
                                libnngio_async_cb cb, void *user_data) {
  mock_stats.recv_async_calls++;
  mock_stats.last_recv_async_result = forced_recv_async_result;
  mock_stats.last_recv_async.ctx = ctx;
  mock_stats.last_recv_async.buf = buf;
  mock_stats.last_recv_async.len_ptr = len;
  mock_stats.last_recv_async.cb = cb;
  mock_stats.last_recv_async.user_data = user_data;

  libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_RECV_ASYNC", __FILE__, __LINE__,
               0, "Receiving data asynchronously");
  if (forced_recv_async_result != 0) {
    libnngio_log("ERR", "MOCK_LIBNNGIO_TRANSPORT_RECV_ASYNC", __FILE__,
                 __LINE__, 0, "Forced receive async error: %d",
                 forced_recv_async_result);
    return forced_recv_async_result;
  }

  int rv = libnngio_context_recv(ctx, buf, len);
  if (cb) {
    libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_RECV_ASYNC", __FILE__,
                 __LINE__, 0, "Calling async callback with result %d", rv);
    cb(ctx, rv, buf, len ? *len : 0, user_data);
    libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_RECV_ASYNC", __FILE__,
                 __LINE__, 0, "Async callback completed");
  } else {
    libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_RECV_ASYNC", __FILE__,
                 __LINE__, 0, "No async callback provided, returning result %d",
                 rv);
  }
  return rv;
}

int libnngio_context_recv_into_buffer_async(libnngio_context *ctx,
                                            libnngio_async_cb cb, 
                                            void *user_data) {
  mock_stats.recv_async_calls++;
  mock_stats.last_recv_async_result = forced_recv_async_result;
  mock_stats.last_recv_async.ctx = ctx;
  mock_stats.last_recv_async.cb = cb;
  mock_stats.last_recv_async.user_data = user_data;
  size_t len = ctx->config->max_msg_size > 0 ? ctx->config->max_msg_size
                                             : LIBNNGIO_DEFAULT_MAX_MSG_SIZE;
  void* buf = malloc(len);

  libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_RECV_INTO_BUFFER_ASYNC", __FILE__, __LINE__,
               0, "Receiving data asynchronously");
  if (forced_recv_async_result != 0) {
    libnngio_log("ERR", "MOCK_LIBNNGIO_TRANSPORT_RECV_INTO_BUFFER_ASYNC", __FILE__,
                 __LINE__, 0, "Forced receive async error: %d",
                 forced_recv_async_result);
    return forced_recv_async_result;
  }

  int rv = libnngio_context_recv(ctx, buf, &len);

  libnngio_message *msg = NULL;
  rv = libnngio_message_init(&msg, buf, len);
  free(buf);
  if (rv != 0) {
    libnngio_log("ERR", "MOCK_LIBNNGIO_TRANSPORT_RECV_INTO_BUFFER_ASYNC", __FILE__,
                 __LINE__, ctx->id,
                 "Failed to initialize message with error %d.", rv);
    return NNG_ENOMEM;
  }

  rv = libnngio_message_ring_buffer_push(ctx->recv_buffer, msg);
  if (rv != 0) {
    libnngio_log("ERR", "MOCK_LIBNNGIO_TRANSPORT_RECV_INTO_BUFFER_ASYNC", __FILE__,
                 __LINE__, ctx->id,
                 "Failed to push message to buffer with error %d.", rv);
    libnngio_message_free(msg);
    ctx->buffer_err = rv;
    return rv;
  }

  libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_RECV_INTO_BUFFER_ASYNC", __FILE__,
               __LINE__, ctx->id, "Received message into buffer successfully.");

  if (cb) {
    libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_RECV_INTO_BUFFER_ASYNC", __FILE__,
                 __LINE__, 0, "Calling async callback with result %d", rv);
    cb(ctx, rv, buf, len ? len : 0, user_data);
    libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_RECV_INTO_BUFFER_ASYNC", __FILE__,
                 __LINE__, 0, "Async callback completed");
  } else {
    libnngio_log("DBG", "MOCK_LIBNNGIO_TRANSPORT_RECV_INTO_BUFFER_ASYNC", __FILE__,
                 __LINE__, 0, "No async callback provided, returning result %d",
                 rv);
  }
  return rv;
}

void libnngio_context_set_user_data(libnngio_context *ctx, void *user_data) {
  if (ctx) {
    libnngio_log("DBG", "MOCK_LIBNNGIO_CONTEXT_SET_USER_DATA", __FILE__,
                 __LINE__, ctx->id, "Setting user data for context ID %d",
                 ctx->id);
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
    libnngio_log("DBG", "MOCK_LIBNNGIO_CONTEXT_FREE", __FILE__, __LINE__,
                 ctx->id, "Freeing context with ID %d", ctx->id);
    if (ctx->recv_buffer) libnngio_message_ring_buffer_free(ctx->recv_buffer);
    if (ctx->send_buffer) libnngio_message_ring_buffer_free(ctx->send_buffer);
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

libnngio_message_ring_buffer *libnngio_context_get_send_buffer(
    libnngio_context *ctx) {
  if (!ctx) return NULL;
  return ctx->send_buffer;
}

int libnngio_context_send_buffer_push(libnngio_context *ctx,
                                      libnngio_message *msg) {
  if (!ctx || !ctx->send_buffer) return NNG_EINVAL;
  return libnngio_message_ring_buffer_push(ctx->send_buffer, msg);
}

int libnngio_context_send_from_buffer(libnngio_context *ctx) {
  if (!ctx || !ctx->send_buffer) return NNG_EINVAL;
  libnngio_message *msg = NULL;
  int rv = 0;

  rv = libnngio_message_ring_buffer_pop(ctx->send_buffer, &msg);
  if (rv != 0) {
    libnngio_log("INF", "LIBNNGIO_CONTEXT_SEND_FROM_BUFFER", __FILE__, __LINE__,
                 ctx->id, "Error in buffer operation: %d", rv);
    libnngio_message_free(msg);
    ctx->buffer_err = rv;
    return rv;
  }

  rv = libnngio_context_send(ctx, msg->data, msg->len);
  libnngio_message_free(msg);
  if (rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_CONTEXT_SEND_FROM_BUFFER", __FILE__, __LINE__,
                 ctx->id, "Failed to send message from buffer with error %d.",
                 rv);
    ctx->transport_err = rv;
    return rv;
  }

  return 0;
}

int libnngio_context_send_buffer_flush(libnngio_context *ctx) {
  if (!ctx || !ctx->send_buffer) return NNG_EINVAL;
  int rv = 0;
  while (ctx->send_buffer->current_size != 0) {
    libnngio_log("DBG", "LIBNNGIO_CONTEXT_SEND_BUFFER_FLUSH", __FILE__,
                 __LINE__, ctx->id,
                 "Preparing to send from buffer. (current size %d)",
                 ctx->send_buffer->current_size);
    rv = libnngio_context_send_from_buffer(ctx);
    if (rv != 0) {
      libnngio_log("ERR", "LIBNNGIO_CONTEXT_SEND_BUFFER_FLUSH", __FILE__,
                   __LINE__, ctx->id,
                   "Failed to send message from buffer with error %d.", rv);
      libnngio_log("ERR", "LIBNNGIO_CONTEXT_SEND_BUFFER_FLUSH", __FILE__,
                   __LINE__, ctx->id, "transport err %d.", ctx->transport_err);
      libnngio_log("ERR", "LIBNNGIO_CONTEXT_SEND_BUFFER_FLUSH", __FILE__,
                   __LINE__, ctx->id, "buffer err %d.", ctx->buffer_err);
      return rv;
    }
  }
  return 0;
}

libnngio_message_ring_buffer *libnngio_context_get_recv_buffer(
    libnngio_context *ctx) {
  if (!ctx) return NULL;
  return ctx->recv_buffer;
}

int libnngio_context_recv_buffer_pop(libnngio_context *ctx,
                                     libnngio_message **msg) {
  if (!ctx || !ctx->recv_buffer) return NNG_EINVAL;
  return libnngio_message_ring_buffer_pop(ctx->recv_buffer, msg);
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

/**
 * @brief Set forced results for various operations in the mock library.
 * These functions allow tests to simulate different scenarios by forcing
 * specific return values for initialization, sending, receiving, and
 * asynchronous operations.
 *
 * @param result The result code to force for the respective operation.
 */
void libnngio_mock_set_init_result(int result) { forced_init_result = result; }

/**
 * @brief Set forced results for various operations in the mock library.
 * These functions allow tests to simulate different scenarios by forcing
 * specific return values for initialization, sending, receiving, and
 * asynchronous operations.
 *
 * @param result The result code to force for the respective operation.
 */
void libnngio_mock_set_send_result(int result) { forced_send_result = result; }

/**
 * @brief Set forced results for various operations in the mock library.
 * These functions allow tests to simulate different scenarios by forcing
 * specific return values for initialization, sending, receiving, and
 * asynchronous operations.
 *
 * @param result The result code to force for the respective operation.
 */
void libnngio_mock_set_recv_result(int result) { forced_recv_result = result; }

/**
 * @brief Set forced results for various operations in the mock library.
 * These functions allow tests to simulate different scenarios by forcing
 * specific return values for initialization, sending, receiving, and
 * asynchronous operations.
 *
 * @param result The result code to force for the respective operation.
 */
void libnngio_mock_set_send_async_result(int result) {
  forced_send_async_result = result;
}

/**
 * @brief Set forced results for various operations in the mock library.
 * These functions allow tests to simulate different scenarios by forcing
 * specific return values for initialization, sending, receiving, and
 * asynchronous operations.
 *
 * @param result The result code to force for the respective operation.
 */
void libnngio_mock_set_recv_async_result(int result) {
  forced_recv_async_result = result;
}

/**
 * @brief Set the buffer to be used for mocked receive operations.
 * This function allows tests to define the data that will be "received"
 * by the mock library when a receive operation is performed.
 *
 * @param buf Pointer to the buffer containing the data to be used for
 *            receiving.
 * @param len Length of the data in the buffer.
 */
void libnngio_mock_set_recv_buffer(const void *buf, size_t len) {
  size_t copy_len =
      len < sizeof(mock_recv_buffer) ? len : sizeof(mock_recv_buffer);
  memcpy(mock_recv_buffer, buf, copy_len);
  mock_recv_buffer_len = copy_len;
}

/**
 * @brief Reset the mock library state.
 * This function clears all statistics, buffers, and forced results,
 * returning the mock library to its initial state. It is useful for
 * ensuring a clean slate between tests.
 */
void libnngio_mock_reset(void) {
  memset(&mock_stats, 0, sizeof(mock_stats));
  memset(mock_recv_buffer, 0, sizeof(mock_recv_buffer));
  mock_recv_buffer_len = 0;
  forced_init_result = forced_send_result = forced_recv_result = 0;
  forced_send_async_result = forced_recv_async_result = 0;
}
