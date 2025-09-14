/**
 * @file libnngio_protobuf.h
 * @brief Protobuf message definitions for libnngio.
 *      This file defines an API for working with protobuf messages over nng
 *       transports. It includes message structures for service discovery,
 *      RPC requests/responses, and raw messages, along with functions for
 *      serialization and deserialization.
 *
 *      The API is designed to be used with the nng messaging library and
 *      protobuf-c for encoding/decoding protobuf messages.
 *
 *      The protocol on the wire is also convenviently implemented using
 *      protobuf, with a top-level NngioMessage that can encapsulate any of
 *      the defined message types.
 */

#ifndef LIBNNGIO_PROTOBUF_H
#define LIBNNGIO_PROTOBUF_H
#include "main/libnngio_main.h"
#include "nngio_protobuf.pb-c.h"

/**
 * @brief Enum indicating which type of message is contained in a NngioMessage.
 */
typedef enum {
  LIBNNGIO_PROTOBUF_MSG_NOT_SET = 0,
  LIBNNGIO_PROTOBUF_MSG_RAW_MESSAGE = 1,
  LIBNNGIO_PROTOBUF_MSG_RPC_REQUEST = 2,
  LIBNNGIO_PROTOBUF_MSG_RPC_RESPONSE = 3,
  LIBNNGIO_PROTOBUF_MSG_SERVICE_DISCOVERY_REQUEST = 4,
  LIBNNGIO_PROTOBUF_MSG_SERVICE_DISCOVERY_RESPONSE = 5
} libnngio_protobuf_msg_case;

/**
 * @brief Union type representing a protobuf message of any defined type.
 */
typedef struct {
  libnngio_protobuf_msg_case msg_case;
  union {
    NngioProtobuf__RawMessage *raw_message;
    NngioProtobuf__RpcRequestMessage *rpc_request;
    NngioProtobuf__RpcResponseMessage *rpc_response;
    NngioProtobuf__ServiceDiscoveryRequest *service_discovery_request;
    NngioProtobuf__ServiceDiscoveryResponse *service_discovery_response;
  } msg;
} libnngio_protobuf_message;

// define init and free function for message

/**
 * @brief Initialize a libnngio_protobuf_message structure.
 * @param message   Pointer to the message to initialize.
 */
void libnngio_protobuf_message_init(libnngio_protobuf_message *message);

/**
 * @brief Free a libnngio_protobuf_message and its contents.
 * @param message   Pointer to the message to free.
 */
void libnngio_protobuf_message_free(libnngio_protobuf_message *message);

// Define serialization/deserialization functions

/**
 * @brief Serialize a libnngio_protobuf_message into a buffer.
 *
 * @param message   Pointer to the message to serialize.
 * @param out_buf   Pointer to receive allocated buffer with serialized data.
 * @param out_len   Pointer to receive length of serialized data.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_protobuf_serialize(const libnngio_protobuf_message *message,
                                uint8_t **out_buf, size_t *out_len);

/**
 * @brief Deserialize a buffer into a libnngio_protobuf_message.
 *
 * @param buf       Pointer to buffer with serialized data.
 * @param len       Length of the buffer.
 * @param message   Pointer to receive allocated message structure.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_protobuf_deserialize(const uint8_t *buf, size_t len,
                                  libnngio_protobuf_message **message);

typedef struct linbnngio_proto_ctx libnngio_protobuf_ctx;

// Define context init/free functions
/**
 * @brief Initialize a libnngio_protobuf context.
 *
 * @param[out] proto_ctx      Pointer to receive allocated context pointer.
 * @param[in]  ctx            Pointer to the underlying libnngio context to use.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_protobuf_context_init(libnngio_protobuf_ctx **proto_ctx,
                                   libnngio_context *ctx);

/**
 * @brief Free a libnngio_protobuf context and release resources.
 *
 * @param ctx Context handle to free.
 */
void libnngio_protobuf_context_free(libnngio_protobuf_ctx *ctx);

// Define sync/async for sending/receiving each message type
// Should define the following functions:
// -send (sync and async) service discovery request
// -recv (sync and async) service discovery request
// -send (sync and async) service discovery response
// -recv (sync and async) service discovery response
// -send (sync and async) rpc request
// -recv (sync and async) rpc request
// -send (sync and async) rpc response
// -recv (sync and async) rpc response
// -send (sync and async) raw message
// -recv (sync and async) raw message

/**
 * @brief Send a service discovery request and wait for the response.
 *
 * @param ctx           Context to use for sending/receiving.
 * @param request       Pointer to the service discovery request message.
 * @param response      Pointer to receive allocated service discovery response
 * message.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_protobuf_send_service_discovery_request(
    libnngio_protobuf_ctx *ctx,
    const NngioProtobuf__ServiceDiscoveryRequest *request,
    NngioProtobuf__ServiceDiscoveryResponse **response);

/**
 * @brief Send a service discovery request asynchronously.
 *
 * @param ctx           Context to use for sending/receiving.
 * @param request       Pointer to the service discovery request message.
 * @param cb            Callback to invoke upon completion.
 * @param user_data     User data for callback.
 * @return 0 on submission, nonzero on failure.
 */
int libnngio_protobuf_send_service_discovery_request_async(
    libnngio_protobuf_ctx *ctx,
    const NngioProtobuf__ServiceDiscoveryRequest *request, libnngio_async_cb cb,
    void *user_data);

/**
 * @brief Receive a service discovery request.
 *
 * @param ctx           Context to use for receiving.
 * @param request       Pointer to receive allocated service discovery request
 * message.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_protobuf_recv_service_discovery_request(
    libnngio_protobuf_ctx *ctx,
    NngioProtobuf__ServiceDiscoveryRequest **request);

/**
 * @brief Receive a service discovery request asynchronously.
 *
 * @param ctx           Context to use for receiving.
 * @param cb            Callback to invoke upon completion.
 * @param user_data     User data for callback.
 * @return 0 on submission, nonzero on failure.
 */
int libnngio_protobuf_recv_service_discovery_request_async(
    libnngio_protobuf_ctx *ctx, libnngio_async_cb cb, void *user_data);

/**
 * @brief Send a service discovery response.
 *
 * @param ctx           Context to use for sending.
 * @param response      Pointer to the service discovery response message.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_protobuf_send_service_discovery_response(
    libnngio_protobuf_ctx *ctx,
    const NngioProtobuf__ServiceDiscoveryResponse *response);

/**
 * @brief Send a service discovery response asynchronously.
 *
 * @param ctx           Context to use for sending.
 * @param response      Pointer to the service discovery response message.
 * @param cb            Callback to invoke upon completion.
 * @param user_data     User data for callback.
 * @return 0 on submission, nonzero on failure.
 */
int libnngio_protobuf_send_service_discovery_response_async(
    libnngio_protobuf_ctx *ctx,
    const NngioProtobuf__ServiceDiscoveryResponse *response,
    libnngio_async_cb cb, void *user_data);

/**
 * @brief Receive a service discovery response.
 *
 * @param ctx           Context to use for receiving.
 * @param response      Pointer to receive allocated service discovery response
 * message.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_protobuf_recv_service_discovery_response(
    libnngio_protobuf_ctx *ctx,
    NngioProtobuf__ServiceDiscoveryResponse **response);

/**
 * @brief Receive a service discovery response asynchronously.
 *
 * @param ctx           Context to use for receiving.
 * @param cb            Callback to invoke upon completion.
 * @param user_data     User data for callback.
 * @return 0 on submission, nonzero on failure.
 */
int libnngio_protobuf_recv_service_discovery_response_async(
    libnngio_protobuf_ctx *ctx, libnngio_async_cb cb, void *user_data);

/**
 * @brief Send an RPC request and wait for the response.
 *
 * @param ctx           Context to use for sending/receiving.
 * @param request       Pointer to the RPC request message.
 * @param response      Pointer to receive allocated RPC response message.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_protobuf_send_rpc_request(
    libnngio_protobuf_ctx *ctx, const NngioProtobuf__RpcRequestMessage *request,
    NngioProtobuf__RpcResponseMessage **response);

/**
 * @brief Send an RPC request asynchronously.
 *
 * @param ctx           Context to use for sending/receiving.
 * @param request       Pointer to the RPC request message.
 * @param cb            Callback to invoke upon completion.
 * @param user_data     User data for callback.
 * @return 0 on submission, nonzero on failure.
 */
int libnngio_protobuf_send_rpc_request_async(
    libnngio_protobuf_ctx *ctx, const NngioProtobuf__RpcRequestMessage *request,
    libnngio_async_cb cb, void *user_data);

/**
 * @brief Receive an RPC request.
 *
 * @param ctx           Context to use for receiving.
 * @param request       Pointer to receive allocated RPC request message.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_protobuf_recv_rpc_request(
    libnngio_protobuf_ctx *ctx, NngioProtobuf__RpcRequestMessage **request);

/**
 * @brief Receive an RPC request asynchronously.
 *
 * @param ctx           Context to use for receiving.
 * @param cb            Callback to invoke upon completion.
 * @param user_data     User data for callback.
 * @return 0 on submission, nonzero on failure.
 */
int libnngio_protobuf_recv_rpc_request_async(libnngio_protobuf_ctx *ctx,
                                             libnngio_async_cb cb,
                                             void *user_data);

/**
 * @brief Send an RPC response.
 *
 * @param ctx           Context to use for sending.
 * @param response      Pointer to the RPC response message.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_protobuf_send_rpc_response(
    libnngio_protobuf_ctx *ctx,
    const NngioProtobuf__RpcResponseMessage *response);

/**
 * @brief Send an RPC response asynchronously.
 *
 * @param ctx           Context to use for sending.
 * @param response      Pointer to the RPC response message.
 * @param cb            Callback to invoke upon completion.
 * @param user_data     User data for callback.
 * @return 0 on submission, nonzero on failure.
 */
int libnngio_protobuf_send_rpc_response_async(
    libnngio_protobuf_ctx *ctx,
    const NngioProtobuf__RpcResponseMessage *response, libnngio_async_cb cb,
    void *user_data);

/**
 * @brief Receive an RPC response.
 *
 * @param ctx           Context to use for receiving.
 * @param response      Pointer to receive allocated RPC response message.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_protobuf_recv_rpc_response(
    libnngio_protobuf_ctx *ctx, NngioProtobuf__RpcResponseMessage **response);

/**
 * @brief Receive an RPC response asynchronously.
 *
 * @param ctx           Context to use for receiving.
 * @param cb            Callback to invoke upon completion.
 * @param user_data     User data for callback.
 * @return 0 on submission, nonzero on failure.
 */
int libnngio_protobuf_recv_rpc_response_async(libnngio_protobuf_ctx *ctx,
                                              libnngio_async_cb cb,
                                              void *user_data);

/**
 * @brief Send a raw message.
 *
 * @param ctx           Context to use for sending.
 * @param message       Pointer to the raw message to send.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_protobuf_send_raw_message(
    libnngio_protobuf_ctx *ctx, const NngioProtobuf__RawMessage *message);

/**
 * @brief Send a raw message asynchronously.
 *
 * @param ctx           Context to use for sending.
 * @param message       Pointer to the raw message to send.
 * @param cb            Callback to invoke upon completion.
 * @param user_data     User data for callback.
 * @return 0 on submission, nonzero on failure.
 */
int libnngio_protobuf_send_raw_message_async(
    libnngio_protobuf_ctx *ctx, const NngioProtobuf__RawMessage *message,
    libnngio_async_cb cb, void *user_data);

/**
 * @brief Receive a raw message.
 *
 * @param ctx           Context to use for receiving.
 * @param message       Pointer to receive allocated raw message.
 * @return 0 on success, nonzero on failure.
 */
int libnngio_protobuf_recv_raw_message(libnngio_protobuf_ctx *ctx,
                                       NngioProtobuf__RawMessage **message);

/**
 * @brief Receive a raw message asynchronously.
 *
 * @param ctx           Context to use for receiving.
 * @param cb            Callback to invoke upon completion.
 * @param user_data     User data for callback.
 * @return 0 on submission, nonzero on failure.
 */
int libnngio_protobuf_recv_raw_message_async(libnngio_protobuf_ctx *ctx,
                                             libnngio_async_cb cb,
                                             void *user_data);

#endif  // LIBNNGIO_PROTOBUF_H
