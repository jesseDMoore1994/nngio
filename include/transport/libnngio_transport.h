#ifndef LIBNNGIO_TRANSPORT_H
#define LIBNNGIO_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

// ========================
// libnngio public API
// ========================

// 64 KB
#define LIBNNGIO_DEFAULT_MAX_MSG_SIZE 65536

/**
 * @brief Supported NNG protocols.
 */
typedef enum {
  LIBNNGIO_PROTO_PAIR = 0,   /**< Pair protocol. */
  LIBNNGIO_PROTO_REQ,        /**< Request protocol. */
  LIBNNGIO_PROTO_REP,        /**< Reply protocol. */
  LIBNNGIO_PROTO_PUB,        /**< Publish protocol. */
  LIBNNGIO_PROTO_SUB,        /**< Subscribe protocol. */
  LIBNNGIO_PROTO_PUSH,       /**< Push protocol. */
  LIBNNGIO_PROTO_PULL,       /**< Pull protocol. */
  LIBNNGIO_PROTO_SURVEYOR,   /**< Surveyor protocol. */
  LIBNNGIO_PROTO_RESPONDENT, /**< Respondent protocol. */
  LIBNNGIO_PROTO_BUS,        /**< Bus protocol. */
} libnngio_proto;

/**
 * @brief Transport mode: dial or listen.
 */
typedef enum {
  LIBNNGIO_MODE_DIAL = 0,  /**< Dial (outbound) mode. */
  LIBNNGIO_MODE_LISTEN = 1 /**< Listen (inbound) mode. */
} libnngio_mode;

/**
 * @brief Structure representing an arbitrary socket option.
 */
typedef struct {
  const char *key;   /**< Option name. */
  const char *value; /**< Option value as string. */
} libnngio_option;

/** Opaque handle for a transport instance. */
typedef struct libnngio_transport libnngio_transport;

/**
 * @brief User configuration for initializing a libnngio transport.
 */
typedef struct {
  char *name;           /**< Name for the transport (for logging). */
  libnngio_mode mode;   /**< Dial or listen mode. */
  libnngio_proto proto; /**< Protocol to use. */
  const char *url;      /**< URL to dial or listen on. */

  /** TLS options: paths to certificate/key/CA PEM files */
  const char *tls_cert;    /**< (Optional) Path to TLS certificate file. */
  const char *tls_key;     /**< (Optional) Path to TLS private key file. */
  const char *tls_ca_cert; /**< (Optional) Path to TLS CA certificate file. */

  uint32_t recv_timeout_ms; /**< Receive timeout in milliseconds, or -1 for
                               default.*/
  uint32_t
      send_timeout_ms; /**< Send timeout in milliseconds, or -1 for default. */
  size_t max_msg_size; /**< Maximum receive message size, or 0 for unlimited. */

  size_t send_buffer_size; /**< Send buffer size, 0 to disable send buffer */
  size_t
      recv_buffer_size; /**< Receive buffer size, 0 to disable receive buffer */

  /** Arbitrary nng socket options */
  const libnngio_option
      *options;        /**< Pointer to array of additional options. */
  size_t option_count; /**< Number of options provided. */
} libnngio_config;

/**
 * @brief Initialize logging for libnngio.
 *
 * @param level Logging level as a string ("debug", "info", etc).
 */
void libnngio_log_init(const char *level);

/**
 * @brief Log a message using libnngio's logging subsystem.
 *
 * @param level   Logging level ("debug", "info", etc).
 * @param tag     Tag for the log message.
 * @param file    Source file name.
 * @param line    Source line number.
 * @param id      Context or transport id.
 * @param fmt     printf-style format string.
 * @param ...     Arguments for format string.
 */
void libnngio_log(const char *level, const char *tag, const char *file,
                  int line, int id, const char *fmt, ...);

/**
 * @brief Initialize a libnngio transport.
 *
 * @param[out] tp      Pointer to receive allocated transport pointer.
 * @param[in]  config  Configuration structure pointer.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_transport_init(libnngio_transport **tp,
                            const libnngio_config *config);

/**
 * @brief retrieve the config used to create a transport. Useful for
 * introspection.
 *
 * @param t Transport handle.
 * @return Pointer to the config used to create the transport.
 */
const libnngio_config *libnngio_transport_get_config(libnngio_transport *t);

/**
 * @brief Free a transport and release resources.
 *
 * @param t Transport handle to free.
 */
void libnngio_transport_free(libnngio_transport *t);

/**
 * @brief Opaque transport message storage structure
 */
typedef struct libnngio_message libnngio_message;

/**
 * @brief Create a libnngio message with the given data.
 * @param msg Pointer to pointer to receive allocated message.
 * @param data Pointer to data buffer.
 * @param len Length of data buffer in bytes.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_message_init(libnngio_message **msg, const void *data, size_t len);

/**
 * @brief Get the data buffer and length from a libnngio message.
 * @param msg Pointer to message.
 * @param data Pointer to receive data buffer pointer.
 * @param len Pointer to receive length of data buffer.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_message_get(libnngio_message *msg, void **data, size_t *len);

/**
 * @brief Free a libnngio message and release resources.
 * @param msg Pointer to message to free.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_message_free(libnngio_message *msg);

typedef enum {
  LIBNNGIO_MESSAGE_RING_BUFFER_OK = 0,
  LIBNNGIO_MESSAGE_RING_BUFFER_FULL = 1,
  LIBNNGIO_MESSAGE_RING_BUFFER_EMPTY = 2,
  LIBNNGIO_MESSAGE_RING_BUFFER_TRANSPORT_ERR = 3,
  LIBNNGIO_MESSAGE_RING_BUFFER_UNINITIALIZED = 4,
} libnngio_message_ring_buffer_err;

/**
 * @brief A ring buffer implementation for holding messages.
 */
typedef struct libnngio_message_ring_buffer {
  libnngio_message **buffer; /**< Array of message pointers. */
  size_t head;               /**< Index of the head of the buffer. */
  size_t tail;               /**< Index of the tail of the buffer. */
  size_t max_size;           /**< Maximum number of messages in the buffer. */
  size_t current_size;       /**< Current number of messages in the buffer. */
} libnngio_message_ring_buffer;

/**
 * @brief Initialize a message ring buffer.
 * @param ring Pointer to pointer to receive ring buffer structure.
 * @param max_size Maximum number of messages the buffer can hold.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_message_ring_buffer_init(libnngio_message_ring_buffer **ring,
                                      size_t max_size);

/**
 * @brief Free a message ring buffer and its contents.
 * @param ring Pointer to ring buffer to free.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_message_ring_buffer_free(libnngio_message_ring_buffer *ring);

/**
 * @brief Push a message onto the ring buffer.
 * @param ring Pointer to ring buffer.
 * @param msg Pointer to message to push.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_message_ring_buffer_push(libnngio_message_ring_buffer *ring,
                                      libnngio_message *msg);

/**
 * @brief Pop a message from the ring buffer.
 * @param ring Pointer to ring buffer.
 * @param msg Pointer to pointer to receive popped message.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_message_ring_buffer_pop(libnngio_message_ring_buffer *ring,
                                     libnngio_message **msg);

/**
 * @brief Opaque handle for a libnngio context.
 */
typedef struct libnngio_context libnngio_context;

/**
 * @brief Context setup callback type.
 * @param args User data pointer.
 */
typedef void (*libnngio_ctx_cb)(void *args);

/**
 * @brief Asynchronous operation callback type.
 *
 * @param ctx       Context handle.
 * @param result    Result code of the operation (0 on success).
 * @param data      Data buffer pointer (for recv).
 * @param len       Length of data (for recv).
 * @param user_data User data pointer provided at call time.
 */
typedef void (*libnngio_async_cb)(libnngio_context *ctx, int result, void *data,
                                  size_t len, void *user_data);

/**
 * @brief Initialize a libnngio context.
 *
 * @param[out] ctxp      Pointer to receive allocated context pointer.
 * @param[in]  t         Associated transport.
 * @param[in]  config    Configuration struct pointer (may be NULL for
 * defaults).
 * @param[in]  cb        Optional callback to invoke after context setup.
 * @param[in]  user_data User data pointer for callback.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_context_init(libnngio_context **ctxp, libnngio_transport *t,
                          const libnngio_config *config, libnngio_ctx_cb cb,
                          void *user_data);

/**
 * @brief Get the id of a context (for logging).
 * @param ctx Context handle.
 * @return Context id (non-negative integer).
 */
int libnngio_context_id(libnngio_context *ctx);

/**
 * @brief Get the config used to create a context. Useful for introspection.
 *
 * @param ctx Context handle.
 * @return Pointer to the config used to create the context.
 */
const libnngio_config *libnngio_context_get_config(libnngio_context *ctx);

/**
 * @brief Send a message synchronously using a context.
 *
 * @param ctx Context handle.
 * @param buf Data buffer to send.
 * @param len Number of bytes to send.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_context_send(libnngio_context *ctx, const void *buf, size_t len);

/**
 * @brief Send a message synchronously from a context send buffer
 *
 * @param ctx Context handle
 * @return 0 on success, nonzero on failure
 */
int libnngio_context_send_from_buffer(libnngio_context *ctx);

/**
 * @brief Receive a message synchronously using a context.
 *
 * @param ctx  Context handle.
 * @param buf  Buffer to receive into.
 * @param len  Pointer to size; set to buffer capacity on input, actual length
 * on output.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_context_recv(libnngio_context *ctx, void *buf, size_t *len);

/**
 * @brief Receive a message synchronously into a context receive buffer
 *
 * @param ctx Context handle
 * @return 0 on success, nonzero on failure
 */
int libnngio_context_recv_into_buffer(libnngio_context *ctx);

/**
 * @brief Start a context (e.g. begin async operations).
 *
 * @param ctx Context to start.
 */
void libnngio_context_start(libnngio_context *ctx);

/**
 * @brief Receive a message asynchronously using a context.
 *
 * @param ctx       Context handle.
 * @param buf       Buffer to receive into.
 * @param len       Pointer to size; set to buffer capacity on input, actual
 * length on output.
 * @param cb        Callback to invoke upon completion.
 * @param user_data User data for callback.
 * @return 0 on submission, nonzero on failure.
 */
int libnngio_context_recv_async(libnngio_context *ctx, void *buf, size_t *len,
                                libnngio_async_cb cb, void *user_data);

/**
 * @brief Asynchronously receive data into a libnngio context receive buffer.
 * @param ctx Pointer to libnngio context.
 * @param cb User-defined callback function to invoke when the receive operation
 *           completes.
 * @param user_data Opaque user data pointer to pass to the callback.
 * @return 0 on success, nonzero error code on failure.
 */
int libnngio_context_recv_into_buffer_async(libnngio_context *ctx,
                                            libnngio_async_cb cb,
                                            void *user_data);

/**
 * @brief Send a message asynchronously using a context.
 *
 * @param ctx       Context handle.
 * @param buf       Data buffer to send.
 * @param len       Number of bytes to send.
 * @param cb        Callback to invoke upon completion.
 * @param user_data User data for callback.
 * @return 0 on submission, nonzero on failure.
 */
int libnngio_context_send_async(libnngio_context *ctx, const void *buf,
                                size_t len, libnngio_async_cb cb,
                                void *user_data);

/**
 * @brief Asynchronously send data from libnngio context send buffer.
 * @param ctx Pointer to libnngio context.
 * @param cb User-defined callback function to invoke when the send operation
 *           completes.
 * @param user_data Opaque user data pointer to pass to the callback.
 * @return 0 on success, nonzero error code on failure.
 */
int libnngio_context_send_from_buffer_async(libnngio_context *ctx,
                                            libnngio_async_cb cb,
                                            void *user_data);

/**
 * @brief Set the user data pointer for a context.
 *
 * @param ctx       Context handle.
 * @param user_data User data pointer to associate.
 */
void libnngio_context_set_user_data(libnngio_context *ctx, void *user_data);

/**
 * @brief Get the user data pointer associated with a context.
 *
 * @param ctx Context handle.
 * @return User data pointer.
 */
void *libnngio_context_get_user_data(libnngio_context *ctx);

/**
 * @brief Free a context and release resources.
 *
 * @param ctx Context handle to free.
 */
void libnngio_context_free(libnngio_context *ctx);

/**
 * @brief Initialize multiple contexts in a batch.
 *
 * @param[out] ctxs       Array of allocated context pointers.
 * @param n               Number of contexts to initialize.
 * @param t               Associated transport.
 * @param config          Configuration for each context.
 * @param cb              Callback for each context.
 * @param user_datas      Array of user data pointers.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_contexts_init(libnngio_context ***ctxs, size_t n,
                           libnngio_transport *t, const libnngio_config *config,
                           libnngio_ctx_cb cb, void **user_datas);

/**
 * @brief Free an array of contexts.
 *
 * @param ctxs Array of context pointers.
 * @param n    Number of contexts.
 */
void libnngio_contexts_free(libnngio_context **ctxs, size_t n);

/**
 * @brief Start an array of contexts.
 *
 * @param ctxs Array of context pointers.
 * @param n    Number of contexts.
 */
void libnngio_contexts_start(libnngio_context **ctxs, size_t n);

/**
 * @brief Get the send buffer from a context
 *
 * @param ctx Context handle
 * @return Send buffer handle, NULL if there isn't one.
 */
libnngio_message_ring_buffer *libnngio_context_get_send_buffer(
    libnngio_context *ctx);

/**
 * @brief push message onto the send buffer in a context
 *
 * @param ctx Context handle
 * @return 0 on success, nonzero on failure
 */
int libnngio_context_send_buffer_push(libnngio_context *ctx,
                                      libnngio_message *msg);

/**
 * @brief flush send buffer out of a context onto the transport
 *
 * @param ctx Context handle
 * @return 0 on success, nonzero on failure
 */
int libnngio_context_send_buffer_flush(libnngio_context *ctx);

/**
 * @brief Get the receive buffer from a context
 *
 * @param ctx Context handle
 * @return Send buffer handle, NULL if there isn't one.
 */
libnngio_message_ring_buffer *libnngio_context_get_recv_buffer(
    libnngio_context *ctx);

/**
 * @brief push message onto the receive buffer in a context
 *
 * @param ctx Context handle
 * @param msg Pointer to address to receive popped message.
 * @return 0 on success, nonzero on failure
 */
int libnngio_context_recv_buffer_pop(libnngio_context *ctx,
                                     libnngio_message **msg);

/**
 * @brief flush receive buffer out of a context from the transport
 *
 * @param ctx Context handle
 * @param max_n_msgs Maximum number of messages allowed for flush
 * @param n_msgs Pointer to receive number of messages flushed
 * @param array of pointers to messages flushed
 * @return 0 on success, nonzero on failure
 */
int libnngio_context_recv_buffer_flush(libnngio_context *ctx, size_t max_n_msgs,
                                       size_t *n_msgs, libnngio_message **msgs);

/**
 * @brief Cleanup global NNG state (calls nng_fini).
 *
 * Safe to call multiple times. After this, no more libnngio functions should be
 * called.
 */
void libnngio_cleanup(void);

// ===============================================================================
// MOCKING SUPPORT BELOW -- These APIs are only available if using the mock
// library (define NNGIO_MOCK_TRANSPORT)
// ===============================================================================

#ifdef NNGIO_MOCK_TRANSPORT

/**
 * @brief Stores all function parameters for the most recent mock transport
 * calls.
 */
typedef struct libnngio_mock_call {
  libnngio_context *ctx; /**< Transport used. */
  const void *buf;       /**< Message buffer. */
  size_t len;            /**< Buffer length. */
  size_t *len_ptr;       /**< Pointer to buffer length (for recv). */
  libnngio_async_cb cb;  /**< Async callback. */
  void *user_data;       /**< User data. */
} libnngio_mock_call;

/**
 * @brief Stores all function parameters for the most recent mock context calls.
 */
typedef struct libnngio_mock_ctx_call {
  libnngio_context *ctx; /**< Context used. */
  const void *buf;       /**< Message buffer. */
  size_t len;            /**< Buffer length. */
  size_t *len_ptr;       /**< Pointer to buffer length (for recv). */
  libnngio_async_cb cb;  /**< Async callback. */
  void *user_data;       /**< User data. */
} libnngio_mock_ctx_call;

/**
 * @brief Structure holding statistics and results for mock API calls.
 */
typedef struct libnngio_mock_stats {
  int init_calls;               /**< Number of times init was called. */
  int send_calls;               /**< Number of times send was called. */
  int recv_calls;               /**< Number of times recv was called. */
  int free_calls;               /**< Number of times free was called. */
  int send_async_calls;         /**< Number of times send_async was called. */
  int recv_async_calls;         /**< Number of times recv_async was called. */
  int last_init_result;         /**< Last return value set for init. */
  int last_send_result;         /**< Last return value set for send. */
  int last_recv_result;         /**< Last return value set for recv. */
  int last_send_async_result;   /**< Last return value set for send_async. */
  int last_recv_async_result;   /**< Last return value set for recv_async. */
  libnngio_mock_call last_init; /**< Last parameters for init call. */
  libnngio_mock_call last_send; /**< Last parameters for send call. */
  libnngio_mock_call last_recv; /**< Last parameters for recv call. */
  libnngio_mock_ctx_call
      last_send_async; /**< Last parameters for send_async. */
  libnngio_mock_ctx_call
      last_recv_async; /**< Last parameters for recv_async. */
} libnngio_mock_stats;

/**
 * @brief Exposed statistics object for mock assertions and inspection.
 */
extern libnngio_mock_stats mock_stats;

/**
 * @brief Set the forced return value for mock transport init calls.
 *
 * @param result The value libnngio_transport_init should return.
 */
void libnngio_mock_set_init_result(int result);

/**
 * @brief Set the forced return value for mock transport send calls.
 *
 * @param result The value libnngio_transport_send should return.
 */
void libnngio_mock_set_send_result(int result);

/**
 * @brief Set the forced return value for mock transport recv calls.
 *
 * @param result The value libnngio_transport_recv should return.
 */
void libnngio_mock_set_recv_result(int result);

/**
 * @brief Set the forced return value for mock context send_async calls.
 *
 * @param result The value libnngio_context_send_async should return.
 */
void libnngio_mock_set_send_async_result(int result);

/**
 * @brief Set the forced return value for mock context recv_async calls.
 *
 * @param result The value libnngio_context_recv_async should return.
 */
void libnngio_mock_set_recv_async_result(int result);

/**
 * @brief Set the buffer to be returned by mock recv/recv_async calls.
 *
 * @param buf Buffer to copy on recv.
 * @param len Length of buffer.
 */
void libnngio_mock_set_recv_buffer(const void *buf, size_t len);

/**
 * @brief Reset all mock statistics and buffers.
 */
void libnngio_mock_reset(void);

#endif  // NNGIO_MOCK_TRANSPORT

#endif  // LIBNNGIO_TRANSPORT_H
