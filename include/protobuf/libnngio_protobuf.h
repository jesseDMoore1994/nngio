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
 *      protobuf, with a top-level LibnngioMessage that can encapsulate any of
 *      the defined message types.
 */

#ifndef LIBNNGIO_PROTOBUF_H
#define LIBNNGIO_PROTOBUF_H
#include "libnngio_protobuf.pb-c.h"
#include "transport/libnngio_transport.h"

#define LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE \
  65535  ///< Max message size (64k bytes)

/**
 * @brief define error codes for rpc software errors
 * These are distinct from nng error codes which indicate transport or protocol
 * errors
 */

typedef enum {
  LIBNNGIO_PROTOBUF_ERR_NONE = 0,               ///< No error
  LIBNNGIO_PROTOBUF_ERR_UNKNOWN = 1,            ///< Unknown error
  LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT = 2,    ///< Invalid context
  LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE = 3,    ///< Invalid message format
  LIBNNGIO_PROTOBUF_ERR_SERVICE_NOT_FOUND = 4,  ///< Requested service not found
  LIBNNGIO_PROTOBUF_ERR_METHOD_NOT_FOUND = 5,   ///< Requested method not found
  LIBNNGIO_PROTOBUF_ERR_INTERNAL_ERROR = 6,     ///< Method cannot be honored
  LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED =
      7,  ///< Message serialization failed
  LIBNNGIO_PROTOBUF_ERR_DESERIALIZATION_FAILED =
      8,  ///< Message deserialization failed
  LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR = 9,  ///< Underlying transport error
} libnngio_protobuf_error_code;

/**
 * @brief Opaque context structure for managing libnngio_protobuf state.
 */
typedef struct libnngio_protobuf_context libnngio_protobuf_context;

// Service implementation structures and functions

// forward declare the typedef'd server and client structs
// so we can reference them in callbacks
struct libnngio_server;
struct libnngio_client;

/**
 * @brief RPC method handler callback type.
 *
 * This callback is invoked when an RPC request is received for a registered
 * method.
 *
 * @param request_payload Input payload for the RPC call.
 * @param request_payload_len Length of the input payload.
 * @param response_payload Pointer to receive allocated response payload.
 * @param response_payload_len Pointer to receive length of response payload.
 * @param user_data User data pointer provided during service registration.
 * @return LibnngioProtobuf__RpcResponse__Status indicating the result.
 */
typedef LibnngioProtobuf__RpcResponse__Status (
    *libnngio_protobuf_method_handler)(struct libnngio_server *server,
                                       const void *request_payload,
                                       size_t request_payload_len,
                                       void **response_payload,
                                       size_t *response_payload_len,
                                       void *user_data);

/**
 * @brief Service method registration structure.
 */
typedef struct {
  char *method_name;  ///< Name of the method
  libnngio_protobuf_method_handler
      handler;      ///< Handler function for the method
  void *user_data;  ///< User data for the handler
} libnngio_service_method;

/**
 * @brief Service registration structure.
 */
typedef struct {
  char *service_name;                ///< Name of the service
  libnngio_service_method *methods;  ///< Array of methods for this service
  size_t n_methods;                  ///< Number of methods
} libnngio_service_registration;

/**
 * @brief Hold a server transport entity
 */
typedef struct {
  libnngio_config *cfg;           ///< Transport config
  libnngio_transport *transport;  ///< Transport handle
  libnngio_context *t_ctx;        ///< Array of context handles
  libnngio_protobuf_context *proto_ctx;  ///< Protobuf context for this
                                         /// transport
} libnngio_server_transport;

/**
 * @brief Server structure that encapsulates protobuf context and service logic.
 */
typedef struct libnngio_server {
  libnngio_protobuf_context *mgmt_ctx;        ///< Protobuf context for management
  libnngio_server_transport **transports;     ///< Array of transport contexts
  size_t n_transports;                        ///< Number of transport contexts
  libnngio_service_registration *services;    ///< Array of registered services
  size_t n_services;                          ///< Number of registered services
  int running;                                ///< Server running flag
  void *server_storage;                       ///< Pointer to server storage (can be used to retrieve
                                              /// store server callback data, etc)
} libnngio_server;

/**
 * @brief Client structure that encapsulates protobuf context and discovered
 * services.
 */
typedef struct libnngio_client {
  libnngio_protobuf_context *proto_ctx;  ///< Protobuf context for client
  LibnngioProtobuf__Service *
      *discovered_services;      ///< Array of discovered services
  size_t n_discovered_services;  ///< Number of discovered services
  void *client_storage;  ///< Pointer to client storage (can be used to retrieve
                         /// store client callback data, etc)
} libnngio_client;

/**
 * @brief Asynchronous operation send callback type.
 *
 * @param ctx       Context handle.
 * @param result    Result code of the operation (0 on success).
 * @param msg       Pointer to the message involved in the operation.
 * @param user_data User data pointer provided at call time.
 */
typedef void (*libnngio_protobuf_send_async_cb)(
    libnngio_protobuf_context *ctx, int result,
    LibnngioProtobuf__LibnngioMessage *msg, void *user_data);

/**
 * @brief Asynchronous operation recv callback type.
 *
 * @param ctx       Context handle.
 * @param result    Result code of the operation (0 on success).
 * @param msg       Pointer to the location to store the received message.
 * @param user_data User data pointer provided at call time.
 */
typedef void (*libnngio_protobuf_recv_async_cb)(
    libnngio_protobuf_context *ctx, int result,
    LibnngioProtobuf__LibnngioMessage **msg, void *user_data);

/**
 * @brief Asynchronous operation send callback for server updates.
 *
 * @param server    Server handle.
 * @param result    Result code of the operation (0 on success).
 * @param msg       Pointer to the message involved in the operation.
 * @param user_data User data pointer provided at call time.
 */
typedef void (*libnngio_protobuf_server_send_async_cb)(
    libnngio_server *server, int result, LibnngioProtobuf__LibnngioMessage *msg,
    void *user_data);

/**
 * @brief Asynchronous operation recv callback for server updates.
 *
 * @param server    Server handle.
 * @param result    Result code of the operation (0 on success).
 * @param msg       Pointer to the location to store the received message.
 * @param user_data User data pointer provided at call time.
 */
typedef void (*libnngio_protobuf_server_recv_async_cb)(
    libnngio_server *server, int result,
    LibnngioProtobuf__LibnngioMessage **msg, void *user_data);

/**
 * @brief Asynchronous operation send callback for client updates.
 *
 * @param client    Client handle.
 * @param result    Result code of the operation (0 on success).
 * @param msg       Pointer to the message involved in the operation.
 * @param user_data User data pointer provided at call time.
 */
typedef void (*libnngio_protobuf_client_send_async_cb)(
    libnngio_client *client, int result, LibnngioProtobuf__LibnngioMessage *msg,
    void *user_data);

/**
 * @brief Asynchronous operation recv callback for client updates.
 *
 * @param client    Client handle.
 * @param result    Result code of the operation (0 on success).
 * @param msg       Pointer to the location to store the received message.
 * @param user_data User data pointer provided at call time.
 */
typedef void (*libnngio_protobuf_client_recv_async_cb)(
    libnngio_client *client, int result,
    LibnngioProtobuf__LibnngioMessage **msg, void *user_data);

/**
 * @brief send callback wrapper structure. Convenience for passing a bundle
 * of send callback info around.
 */
typedef struct {
  libnngio_protobuf_send_async_cb user_cb;           ///< Callback function
  libnngio_protobuf_context *ctx;                    ///< Context
  libnngio_protobuf_server_send_async_cb server_cb;  ///< Server callback
  libnngio_server *server;                           ///< Server (if applicable)
  libnngio_protobuf_client_send_async_cb client_cb;  ///< Client callback
  libnngio_client *client;                           ///< Client (if applicable)
  void *user_data;                                   ///< User data
} libnngio_protobuf_send_cb_info;

/**
 * @brief recv callback wrapper structure. Convenience for passing a bundle
 * of recv callback info around.
 */
typedef struct {
  libnngio_protobuf_recv_async_cb user_cb;           ///< Callback function
  libnngio_protobuf_context *ctx;                    ///< Context
  libnngio_protobuf_server_recv_async_cb server_cb;  ///< Server callback
  libnngio_server *server;                           ///< Server (if applicable)
  libnngio_protobuf_client_recv_async_cb client_cb;  ///< Client callback
  libnngio_client *client;                           ///< Client (if applicable)
  void *user_data;                                   ///< User data
} libnngio_protobuf_recv_cb_info;

/*
 * @brief Define function to convert LibnngioProtobuf__LibnngioMessage__MsgCase
 * enum to string
 */
char *libnngio_protobuf_nngio_msg_case_str(
    LibnngioProtobuf__LibnngioMessage__MsgCase msg_case);

/*
 * @brief Define helper function to write a UUIDv4 into a char buffer
 * in standard string format. The caller is responsible for freeing
 * the returned buffer.
 *
 * @return Pointer to the uuid_buf on success, NULL on failure.
 */
char *libnngio_protobuf_gen_uuid(void);

/*
 * @brief Define function to convert error codes to strings
 */
char *libnngio_protobuf_strerror(libnngio_protobuf_error_code code);

// Define context init/free functions
/**
 * @brief Initialize a libnngio_protobuf context.
 *
 * @param out proto_ctx Pointer to receive allocated context pointer.
 * @param in ctx Pointer to the underlying libnngio context to use.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_context_init(
    libnngio_protobuf_context **proto_ctx, libnngio_context *ctx);

/**
 * @brief Free a libnngio_protobuf context and release resources.
 *
 * @param ctx Context handle to free.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_context_free(
    libnngio_protobuf_context *ctx);

/**
 * @brief Get the last transport error code from the underlying libnngio
 * context.
 * @param ctx Pointer to the libnngio_protobuf context.
 * @return The last transport error code, or 0 if no error.
 */
int libnngio_protobuf_context_get_transport_rv(libnngio_protobuf_context *ctx);

// Define helper functions for us to create and release each message type
// These functions should allocate/free the message structs and any nested
// fields as needed
//
/**
 * @brief Create a LibnngioProtobuf__Service structure and populate its fields.
 *
 * Allocates and initializes a LibnngioProtobuf__Service with the given name and
 * methods. All strings are deep-copied.
 *
 * @param name Name of the service.
 * @param methods Array of method names.
 * @param n_methods Number of methods.
 * @return Pointer to the allocated LibnngioProtobuf__Service, or NULL on
 * failure.
 */
LibnngioProtobuf__Service *nngio_create_service(const char *name,
                                                const char **methods,
                                                size_t n_methods);

/**
 * @brief Free a LibnngioProtobuf__Service structure and its contents.
 *
 * Frees all allocated memory associated with the service, including method
 * strings.
 *
 * @param svc Pointer to the service to free.
 */
void nngio_free_service(LibnngioProtobuf__Service *svc);

/**

 * @brief Create a LibnngioProtobuf__ServiceDiscoveryResponse structure and
 * populate its fields.
 *
 * Allocates and initializes a LibnngioProtobuf__ServiceDiscoveryResponse with
 the
 * given services. Takes ownership of the provided service pointers.
 *
 * @param services Array of pointers to LibnngioProtobuf__Service.
 * @param n_services Number of services.
 * @return Pointer to the allocated response, or NULL on failure.
 */
LibnngioProtobuf__ServiceDiscoveryResponse *
nngio_create_service_discovery_response(LibnngioProtobuf__Service **services,
                                        size_t n_services);

/**
 * @brief Free a LibnngioProtobuf__ServiceDiscoveryResponse structure and its
 * contents.
 *
 * Frees all allocated memory associated with the response and its services.
 *
 * @param resp Pointer to the response to free.
 */
void nngio_free_service_discovery_response(
    LibnngioProtobuf__ServiceDiscoveryResponse *resp);

/**
 * @brief Create a LibnngioProtobuf__RpcRequest with the given parameters.
 *
 * Allocates and initializes a request message. Deep-copies strings and payload.
 *
 * @param service_name Name of the target service.
 * @param method_name Name of the method to call.
 * @param payload Pointer to the payload data.
 * @param payload_len Size of the payload data.
 * @return Pointer to the allocated request message, or NULL on failure.
 */
LibnngioProtobuf__RpcRequest *nngio_create_rpc_request(const char *service_name,
                                                       const char *method_name,
                                                       const void *payload,
                                                       size_t payload_len);

/**
 * @brief Free a LibnngioProtobuf__RpcRequest and its contents.
 *
 * Frees all allocated memory associated with the request message.
 *
 * @param msg Pointer to the request message to free.
 */
void nngio_free_rpc_request(LibnngioProtobuf__RpcRequest *msg);

/**
 * @brief Create a LibnngioProtobuf__RpcResponse with the given parameters.
 *
 * Allocates and initializes a response message. Deep-copies payload and error
 * message.
 *
 * @param status Status of the RPC response.
 * @param payload Pointer to the payload data.
 * @param payload_len Size of the payload data.
 * @param error_message Error message string (may be NULL).
 * @return Pointer to the allocated response message, or NULL on failure.
 */
LibnngioProtobuf__RpcResponse *nngio_create_rpc_response(
    LibnngioProtobuf__RpcResponse__Status status, const void *payload,
    size_t payload_len, const char *error_message);

/**
 * @brief Free a LibnngioProtobuf__RpcResponse and its contents.
 *
 * Frees all allocated memory associated with the response message.
 *
 * @param msg Pointer to the response message to free.
 */
void nngio_free_rpc_response(LibnngioProtobuf__RpcResponse *msg);

/**
 * @brief Create a LibnngioProtobuf__Raw with the given binary data.
 *
 * Allocates and initializes a raw message with deep-copied data.
 *
 * @param data Pointer to the binary data.
 * @param data_len Length of the binary data.
 * @return Pointer to the allocated raw message, or NULL on failure.
 */
LibnngioProtobuf__Raw *nngio_create_raw_message(const void *data,
                                                size_t data_len);

/**
 * @brief Free a LibnngioProtobuf__Raw and its contents.
 *
 * Frees all allocated memory associated with the raw message.
 *
 * @param msg Pointer to the raw message to free.
 */
void nngio_free_raw_message(LibnngioProtobuf__Raw *msg);

/**
 * @brief Create a LibnngioProtobuf__Transport and populate its fields.
 *
 * Allocates and initializes a transport message with the given type and
 * address. Deep-copies strings.
 *
 * @param type Transport type string.
 * @param config Transport configuration
 * @return Pointer to the allocated transport message, or NULL on failure.
 */
LibnngioProtobuf__Transport *nngio_create_transport(libnngio_config *config);

/**
 * @brief Free a LibnngioProtobuf__Transport and its contents.
 *
 * Frees all allocated memory associated with the transport message.
 *
 * @param msg Pointer to the transport message to free.
 */
void nngio_free_transport(LibnngioProtobuf__Transport *transport);

/**
 * @brief Create a LibnngioProtobuf__AddTransportRequest message.
 *
 * Allocates and initializes an AddTransportRequest with the given transport.
 * Takes ownership of the provided transport pointer.
 *
 * @param transport Pointer to a libnngio_config structure.
 * @return Pointer to the allocated request, or NULL on failure.
 */
LibnngioProtobuf__AddTransportRequest *nngio_create_add_transport_request(
    libnngio_config *transport);

/**
 * @brief Free a LibnngioProtobuf__AddTransportRequest and its contents.
 *
 * Frees all allocated memory associated with the request message.
 *
 * @param msg Pointer to the request message to free.
 */
void nngio_free_add_transport_request(
    LibnngioProtobuf__AddTransportRequest *msg);

/**
 * @brief Create a GetTransportsResponse message.
 *
 * Allocates and initializes a GetTransportsResponse with the given transports.
 * Takes ownership of the provided transport pointers.
 *
 * @param configs Array of pointers to libnngio_config structures.
 * @param n_configs Number of configs.
 * @return Pointer to the allocated response, or NULL on failure.
 */
LibnngioProtobuf__GetTransportsResponse *
nngio_create_get_transports_response(libnngio_config **configs,
                                     size_t n_configs);


/**
 * @brief Free a LibnngioProtobuf__GetTransportsResponse and its contents.
 *
 * Frees all allocated memory associated with the response message.
 *
 * @param msg Pointer to the response message to free.
 */
void nngio_free_get_transports_response(
    LibnngioProtobuf__GetTransportsResponse *msg);


/**
 * @brief Create a LibnngioProtobuf__RemoveTransportRequest message.
 *
 * Allocates and initializes a RemoveTransportRequest with the given transport.
 *
 * @param mode Transport mode
 * @param protocol Transport protocol
 * @param url Transport address
 * @return Pointer to the allocated request, or NULL on failure.
 */
LibnngioProtobuf__RemoveTransportRequest *nngio_create_remove_transport_request(
     libnngio_mode mode, libnngio_proto protocol, const char *url);

/**
 * @brief Free a LibnngioProtobuf__RemoveTransportRequest and its contents.
 *
 * Frees all allocated memory associated with the request message.
 *
 * @param msg Pointer to the request message to free.
 */
void nngio_free_remove_transport_request(
    LibnngioProtobuf__RemoveTransportRequest *msg);

/**
 * @brief Create a LibnngioProtobuf__LibnngioMessage containing a
 * RpcRequestMessage.
 *
 * Allocates and initializes an LibnngioMessage. Takes ownership of the
 * rpc_request pointer.
 *
 * @param uuid Unique identifier string for the message.
 * @param rpc_request Pointer to a LibnngioProtobuf__RpcRequest.
 * @return Pointer to the allocated LibnngioMessage, or NULL on failure.
 */
LibnngioProtobuf__LibnngioMessage *nngio_create_nngio_message_with_rpc_request(
    const char *uuid, LibnngioProtobuf__RpcRequest *rpc_request);

/**
 * @brief Create a LibnngioProtobuf__LibnngioMessage containing a
 * RpcResponseMessage.
 *
 * Allocates and initializes an LibnngioMessage. Takes ownership of the
 * rpc_response pointer.
 *
 * @param uuid Unique identifier string for the message.
 * @param rpc_response Pointer to a LibnngioProtobuf__RpcResponse.
 * @return Pointer to the allocated LibnngioMessage, or NULL on failure.
 */
LibnngioProtobuf__LibnngioMessage *nngio_create_nngio_message_with_rpc_response(
    const char *uuid, LibnngioProtobuf__RpcResponse *rpc_response);

/**
 * @brief Create a LibnngioProtobuf__LibnngioMessage containing a RawMessage.
 *
 * Allocates and initializes an LibnngioMessage. Takes ownership of the
 * raw_message pointer.
 *
 * @param uuid Unique identifier string for the message.
 * @param raw_message Pointer to a LibnngioProtobuf__Raw.
 * @return Pointer to the allocated LibnngioMessage, or NULL on failure.
 */
LibnngioProtobuf__LibnngioMessage *nngio_create_nngio_message_with_raw(
    const char *uuid, LibnngioProtobuf__Raw *raw_message);

/**
 * @brief Create a LibnngioProtobuf__LibnngioMessage containing a
 * ServiceDiscoveryRequest.
 *
 * Allocates and initializes an LibnngioMessage. Takes ownership of the req
 * pointer.
 *
 * @param uuid Unique identifier string for the message.
 * @param req Pointer to a LibnngioProtobuf__ServiceDiscoveryRequest.
 * @return Pointer to the allocated LibnngioMessage, or NULL on failure.
 */
LibnngioProtobuf__LibnngioMessage *
nngio_create_nngio_message_with_service_discovery_request(
    const char *uuid, LibnngioProtobuf__ServiceDiscoveryRequest *req);

/**
 * @brief Create a LibnngioProtobuf__LibnngioMessage containing a
 * ServiceDiscoveryResponse.
 *
 * Allocates and initializes an LibnngioMessage. Takes ownership of the resp
 * pointer.
 *
 * @param uuid Unique identifier string for the message.
 * @param resp Pointer to a LibnngioProtobuf__ServiceDiscoveryResponse.
 * @return Pointer to the allocated LibnngioMessage, or NULL on failure.
 */
LibnngioProtobuf__LibnngioMessage *
nngio_create_nngio_message_with_service_discovery_response(
    const char *uuid, LibnngioProtobuf__ServiceDiscoveryResponse *resp);

/**
 * @brief Create a LibnngioProtobuf__LibnngioMessage containing an
 * AddTransportRequest.
 *
 * Allocates and initializes an LibnngioMessage. Takes ownership of the req
 * pointer.
 *
 * @param uuid Unique identifier string for the message.
 * @param req Pointer to a LibnngioProtobuf__AddTransportRequest.
 * @return Pointer to the allocated LibnngioMessage, or NULL on failure.
 */
LibnngioProtobuf__LibnngioMessage *
nngio_create_nngio_message_with_add_transport_request(
    const char *uuid, LibnngioProtobuf__AddTransportRequest *req);

/**
 * @brief Create a LibnngioProtobuf__LibnngioMessage containing a
 * GetTransportsResponse.
 *
 * Allocates and initializes an LibnngioMessage. Takes ownership of the resp
 * pointer.
 *
 * @param uuid Unique identifier string for the message.
 * @param resp Pointer to a LibnngioProtobuf__GetTransportsResponse.
 * @return Pointer to the allocated LibnngioMessage, or NULL on failure.
 */
LibnngioProtobuf__LibnngioMessage *
nngio_create_nngio_message_with_get_transports_response(
    const char *uuid, LibnngioProtobuf__GetTransportsResponse *resp);

/**
 * @brief Create a LibnngioProtobuf__LibnngioMessage containing a
 * RemoveTransportRequest.
 *
 * Allocates and initializes an LibnngioMessage. Takes ownership of the req
 * pointer.
 * @param uuid Unique identifier string for the message.
 * @param req Pointer to a LibnngioProtobuf__RemoveTransportRequest.
 * @return Pointer to the allocated LibnngioMessage, or NULL on failure.
 */
LibnngioProtobuf__LibnngioMessage *
nngio_create_nngio_message_with_remove_transport_request(
    const char *uuid, LibnngioProtobuf__RemoveTransportRequest *req);

/**
 * @brief Free a LibnngioProtobuf__LibnngioMessage and its contents.
 *
 * Frees all memory associated with the LibnngioMessage, including nested
 * messages.
 *
 * @param msg Pointer to the LibnngioMessage to free.
 */
void nngio_free_nngio_message(LibnngioProtobuf__LibnngioMessage *msg);

/**
 * @brief Deep copy a LibnngioProtobuf__Service structure.
 *
 * Allocates and returns a new service whose fields are deep-copied from src.
 *
 * @param src Pointer to the source service to copy.
 * @return Pointer to deep-copied service, or NULL on failure.
 */
LibnngioProtobuf__Service *nngio_copy_service(
    const LibnngioProtobuf__Service *src);

/**
 * @brief Deep copy a LibnngioProtobuf__ServiceDiscoveryResponse structure.
 *
 * Allocates and returns a new response whose fields and services are
 * deep-copied from src.
 *
 * @param src Pointer to the source response to copy.
 * @return Pointer to deep-copied response, or NULL on failure.
 */
LibnngioProtobuf__ServiceDiscoveryResponse *
nngio_copy_service_discovery_response(
    const LibnngioProtobuf__ServiceDiscoveryResponse *src);

/**
 * @brief Deep copy a LibnngioProtobuf__RpcRequest structure.
 *
 * Allocates and returns a new RPC request whose fields are deep-copied from
 * src.
 *
 * @param src Pointer to the source request to copy.
 * @return Pointer to deep-copied request, or NULL on failure.
 */
LibnngioProtobuf__RpcRequest *nngio_copy_rpc_request(
    const LibnngioProtobuf__RpcRequest *src);

/**
 * @brief Deep copy a LibnngioProtobuf__RpcResponse structure.
 *
 * Allocates and returns a new RPC response whose fields are deep-copied from
 * src.
 *
 * @param src Pointer to the source response to copy.
 * @return Pointer to deep-copied response, or NULL on failure.
 */
LibnngioProtobuf__RpcResponse *nngio_copy_rpc_response(
    const LibnngioProtobuf__RpcResponse *src);

/**
 * @brief Deep copy a LibnngioProtobuf__Raw structure.
 *
 * Allocates and returns a new raw message whose data is deep-copied from src.
 *
 * @param src Pointer to the source raw message to copy.
 * @return Pointer to deep-copied raw message, or NULL on failure.
 */
LibnngioProtobuf__Raw *nngio_copy_raw_message(const LibnngioProtobuf__Raw *src);

/**
 * @brief Deep copy a LibnngioProtobuf__Transport structure.
 *
 * Allocates and returns a new transport whose fields are deep-copied from src.
 *
 * @param src Pointer to the source transport to copy.
 * @return Pointer to deep-copied transport, or NULL on failure.
 */
LibnngioProtobuf__Transport *nngio_copy_transport(
    const LibnngioProtobuf__Transport *src);

/**
 * @brief Deep copy a LibnngioProtobuf__GetTransportsResponse structure.
 *
 * Allocates and returns a new response whose fields and transports are
 * deep-copied from src.
 *
 * @param src Pointer to the source response to copy.
 * @return Pointer to deep-copied response, or NULL on failure.
 */
LibnngioProtobuf__GetTransportsResponse *nngio_copy_get_transports_response(
    const LibnngioProtobuf__GetTransportsResponse *src);

/**
 * @brief Deep copy a LibnngioProtobuf__LibnngioMessage structure.
 *
 * Allocates and returns a new LibnngioMessage, deep-copying its uuid and the
 * message in the union (using the appropriate helper functions).
 *
 * @param src Pointer to the source LibnngioMessage to copy.
 * @return Pointer to deep-copied LibnngioMessage, or NULL on failure.
 */
LibnngioProtobuf__LibnngioMessage *nngio_copy_nngio_message(
    const LibnngioProtobuf__LibnngioMessage *src);

// Define sync/async for sending/receiving each message type
// Should define the following functions:
// -send (sync and async) raw message
// -recv (sync and async) raw message
// -send (sync and async) rpc request
// -recv (sync and async) rpc request
// -send (sync and async) rpc response
// -recv (sync and async) rpc response
// -send (sync and async) service discovery request
// -recv (sync and async) service discovery request
// -send (sync and async) service discovery response
// -recv (sync and async) service discovery response

/**
 * @brief Send a raw message.
 *
 * @param ctx           Context to use for sending.
 * @param message       Pointer to the raw message to send.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_send_raw_message(
    libnngio_protobuf_context *ctx, const LibnngioProtobuf__Raw *message);

/**
 * @brief Send a raw message asynchronously.
 *
 * @param ctx           Context to use for sending.
 * @param message       Pointer to the raw message to send.
 * @param cb            Callback to invoke upon completion.
 * @param user_data     User data for callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_send_raw_message_async(
    libnngio_protobuf_context *ctx, const LibnngioProtobuf__Raw *message,
    libnngio_protobuf_send_cb_info cb_info);

/**
 * @brief Receive a raw message.
 *
 * @param ctx           Context to use for receiving.
 * @param message       Pointer to receive allocated raw message.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_recv_raw_message(
    libnngio_protobuf_context *ctx, LibnngioProtobuf__Raw **message);

/**
 * @brief Receive a raw message asynchronously.
 *
 * @param ctx           Context to use for receiving.
 * @param cb            Callback to invoke upon completion.
 * @param user_data     User data for callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_recv_raw_message_async(
    libnngio_protobuf_context *ctx, LibnngioProtobuf__Raw **message,
    libnngio_protobuf_recv_cb_info cb_info);

/**
 * @brief Send an RPC request and wait for the response.
 *
 * @param ctx           Context to use for sending/receiving.
 * @param request       Pointer to the RPC request message.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_send_rpc_request(
    libnngio_protobuf_context *ctx,
    const LibnngioProtobuf__RpcRequest *request);

/**
 * @brief Send an RPC request asynchronously.
 *
 * @param ctx           Context to use for sending/receiving.
 * @param request       Pointer to the RPC request message.
 * @param cb            Callback to invoke upon completion.
 * @param user_data     User data for callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_send_rpc_request_async(
    libnngio_protobuf_context *ctx, const LibnngioProtobuf__RpcRequest *request,
    libnngio_protobuf_send_cb_info cb_info);

/**
 * @brief Receive an RPC request.
 *
 * @param ctx           Context to use for receiving.
 * @param request       Pointer to receive allocated RPC request message.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_recv_rpc_request(
    libnngio_protobuf_context *ctx, LibnngioProtobuf__RpcRequest **request);

/**
 * @brief Receive an RPC request asynchronously.
 *
 * @param ctx           Context to use for sending/receiving.
 * @param request       Pointer to the RPC request to retrieve the data.
 * @param cb            Callback to invoke upon completion.
 * @param user_data     User data for callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_recv_rpc_request_async(
    libnngio_protobuf_context *ctx, LibnngioProtobuf__RpcRequest **request,
    libnngio_protobuf_recv_cb_info cb_info);

/**
 * @brief Send an RPC response.
 *
 * @param ctx           Context to use for sending.
 * @param response      Pointer to the RPC response message.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_send_rpc_response(
    libnngio_protobuf_context *ctx,
    const LibnngioProtobuf__RpcResponse *response);

/**
 * @brief Send an RPC response asynchronously.
 *
 * @param ctx           Context to use for sending.
 * @param response      Pointer to the RPC response message.
 * @param cb            Callback to invoke upon completion.
 * @param user_data     User data for callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_send_rpc_response_async(
    libnngio_protobuf_context *ctx,
    const LibnngioProtobuf__RpcResponse *response,
    libnngio_protobuf_send_cb_info cb_info);

/**
 * @brief Receive an RPC response.
 *
 * @param ctx           Context to use for receiving.
 * @param response      Pointer to receive allocated RPC response message.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_recv_rpc_response(
    libnngio_protobuf_context *ctx, LibnngioProtobuf__RpcResponse **response);

/**
 * @brief Receive an RPC response asynchronously.
 *
 * @param ctx           Context to use for receiving.
 * @param response      Pointer to the location where response is stored
 * @param cb            Callback to invoke upon completion.
 * @param user_data     User data for callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_recv_rpc_response_async(
    libnngio_protobuf_context *ctx, LibnngioProtobuf__RpcResponse **response,
    libnngio_protobuf_recv_cb_info cb_info);

/**
 * @brief Send a service discovery request and wait for the response.
 *
 * @param ctx           Context to use for sending/receiving.
 * @param request       Pointer to the service discovery request message.
 * @param response      Pointer to receive allocated service discovery response
 * message.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_send_service_discovery_request(
    libnngio_protobuf_context *ctx,
    const LibnngioProtobuf__ServiceDiscoveryRequest *request);

/**
 * @brief Send a service discovery request asynchronously.
 *
 * @param ctx           Context to use for sending/receiving.
 * @param request       Pointer to the service discovery request message.
 * @param cb            Callback to invoke upon completion.
 * @param user_data     User data for callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code
libnngio_protobuf_send_service_discovery_request_async(
    libnngio_protobuf_context *ctx,
    const LibnngioProtobuf__ServiceDiscoveryRequest *request,
    libnngio_protobuf_send_cb_info cb_info);

/**
 * @brief Receive a service discovery request.
 *
 * @param ctx           Context to use for receiving.
 * @param request       Pointer to receive allocated service discovery request
 * message.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_recv_service_discovery_request(
    libnngio_protobuf_context *ctx,
    LibnngioProtobuf__ServiceDiscoveryRequest **request);

/**
 * @brief Receive a service discovery request asynchronously.
 *
 * @param ctx           Context to use for receiving.
 * @param cb            Callback to invoke upon completion.
 * @param user_data     User data for callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code
libnngio_protobuf_recv_service_discovery_request_async(
    libnngio_protobuf_context *ctx,
    LibnngioProtobuf__ServiceDiscoveryRequest **request,
    libnngio_protobuf_recv_cb_info cb_info);

/**
 * @brief Send a service discovery response.
 *
 * @param ctx           Context to use for sending.
 * @param response      Pointer to the service discovery response message.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_send_service_discovery_response(
    libnngio_protobuf_context *ctx,
    const LibnngioProtobuf__ServiceDiscoveryResponse *response);

/**
 * @brief Send a service discovery response asynchronously.
 *
 * @param ctx           Context to use for sending.
 * @param response      Pointer to the service discovery response message.
 * @param cb            Callback to invoke upon completion.
 * @param user_data     User data for callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code
libnngio_protobuf_send_service_discovery_response_async(
    libnngio_protobuf_context *ctx,
    const LibnngioProtobuf__ServiceDiscoveryResponse *response,
    libnngio_protobuf_send_cb_info cb_info);

/**
 * @brief Receive a service discovery response.
 *
 * @param ctx           Context to use for receiving.
 * @param response      Pointer to receive allocated service discovery response
 * message.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_recv_service_discovery_response(
    libnngio_protobuf_context *ctx,
    LibnngioProtobuf__ServiceDiscoveryResponse **response);

/**
 * @brief Receive a service discovery response asynchronously.
 *
 * @param ctx           Context to use for receiving.
 * @param cb            Callback to invoke upon completion.
 * @param user_data     User data for callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code
libnngio_protobuf_recv_service_discovery_response_async(
    libnngio_protobuf_context *ctx,
    LibnngioProtobuf__ServiceDiscoveryResponse **response,
    libnngio_protobuf_recv_cb_info cb_info);

/**
 * @brief Send a generic LibnngioMessage.
 *
 * @param ctx           Context to use for sending.
 * @param msg           Pointer to the LibnngioMessage to send.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_send(
    libnngio_protobuf_context *ctx,
    const LibnngioProtobuf__LibnngioMessage *msg);

/**
 * @brief Send a generic LibnngioMessage asynchronously.
 *
 * @param ctx           Context to use for sending.
 * @param msg           Pointer to the LibnngioMessage to send.
 * @param cb            Callback to invoke upon completion.
 * @param user_data     User data for callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_send_async(
    libnngio_protobuf_context *ctx,
    const LibnngioProtobuf__LibnngioMessage *msg,
    libnngio_protobuf_send_cb_info cb_info);

/**
 * @brief Receive a generic LibnngioMessage.
 *
 * @param ctx           Context to use for receiving.
 * @param msg           Pointer to receive allocated LibnngioMessage.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_recv(
    libnngio_protobuf_context *ctx, LibnngioProtobuf__LibnngioMessage **msg);

/**
 * @brief Receive a generic LibnngioMessage asynchronously.
 *
 * @param ctx           Context to use for receiving.
 * @param msg           Pointer to the location to store the received message.
 * @param cb            Callback to invoke upon completion.
 * @param user_data     User data for callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_recv_async(
    libnngio_protobuf_context *ctx, LibnngioProtobuf__LibnngioMessage **msg,
    libnngio_protobuf_recv_cb_info cb_info);

/**
 * @brief Initialize a libnngio_server with the given protobuf context.
 *
 * @param server Pointer to receive initialized server structure.
 * @param proto_ctx Protobuf context to use for transport.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_server_init(
    libnngio_server **server, libnngio_protobuf_context *proto_ctx);

/**
 * @brief Free a libnngio_server and its resources.
 *
 * @param server Server to free.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_server_free(libnngio_server *server);

/**
 * @brief Register a service with the server.
 *
 * @param server Server to register service with.
 * @param service_name Name of the service.
 * @param methods Array of method definitions.
 * @param n_methods Number of methods.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_server_register_service(
    libnngio_server *server, const char *service_name,
    const libnngio_service_method *methods, size_t n_methods);

/**
 * @brief Create a service discovery response message with registered services
 *
 * @param server Server containing registered services.
 * @param response Pointer to receive allocated service discovery response.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_server_create_service_discovery_response(
    libnngio_server *server,
    LibnngioProtobuf__ServiceDiscoveryResponse **response);

/**
 * @brief Receive a service discovery request with the server
 *
 * @param server Server to receive request with.
 * @param request Pointer to receive allocated service discovery request.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_server_recv_service_discovery_request(
    libnngio_server *server,
    LibnngioProtobuf__ServiceDiscoveryRequest **request);

/**
 * @brief Receive a service discovery request asynchronously with the server
 *
 * @param server Server to receive request with.
 * @param request Pointer to receive allocated service discovery request.
 * @param cb Callback to invoke upon completion.
 * @param user_data User data for callback.
s * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code
libnngio_server_recv_service_discovery_request_async(
    libnngio_server *server,
    LibnngioProtobuf__ServiceDiscoveryRequest **request,
    libnngio_protobuf_recv_cb_info cb_info);

/**
 * @brief Send a service discovery response with the server
 *
 * @param server Server to send response with.
 * @param response Pointer to the service discovery response message.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_server_send_service_discovery_response(
    libnngio_server *server,
    const LibnngioProtobuf__ServiceDiscoveryResponse *response);

/**
 * @brief Send a service discovery response asynchronously with the server
 *
 * @param server Server to send response with.
 * @param response Pointer to the service discovery response message.
 * @param cb Callback to invoke upon completion.
 * @param user_data User data for callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code
libnngio_server_send_service_discovery_response_async(
    libnngio_server *server,
    const LibnngioProtobuf__ServiceDiscoveryResponse *response,
    libnngio_protobuf_send_cb_info cb_info);

/**
 * @brief Initialize a libnngio_client with the given protobuf context.
 *
 * @param client Pointer to receive initialized client structure.
 * @param proto_ctx Protobuf context to use for transport.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_client_init(
    libnngio_client **client, libnngio_protobuf_context *proto_ctx);

/**
 * @brief Free a libnngio_client and its resources.
 *
 * @param client Client to free.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_client_free(libnngio_client *client);

/**
 * @brief Send a service discovery with the client
 *
 * @param client Client to send request with.
 * @param request Pointer to the service discovery request message.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_client_send_service_discovery_request(
    libnngio_client *client,
    const LibnngioProtobuf__ServiceDiscoveryRequest *request);

/**
 * @brief Send a service discovery request asynchronously with the client
 *
 * @param client Client to send request with.
 * @param request Pointer to the service discovery request message.
 * @param cb Callback to invoke upon completion.
 * @param user_data User data for callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code
libnngio_client_send_service_discovery_request_async(
    libnngio_client *client,
    const LibnngioProtobuf__ServiceDiscoveryRequest *request,
    libnngio_protobuf_send_cb_info cb_info);

/**
 * @brief Receive a service discovery response with the client
 *
 * @param client Client to receive response with.
 * @param response Pointer to receive allocated service discovery response.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_client_recv_service_discovery_response(
    libnngio_client *client,
    LibnngioProtobuf__ServiceDiscoveryResponse **response);

/**
 * @brief Receive a service discovery response asynchronously with the client
 *
 * @param client Client to receive response with.
 * @param response Pointer to receive allocated service discovery response.
 * @param cb Callback to invoke upon completion.
 * @param user_data User data for callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code
libnngio_client_recv_service_discovery_response_async(
    libnngio_client *client,
    LibnngioProtobuf__ServiceDiscoveryResponse **response,
    libnngio_protobuf_recv_cb_info cb_info);

/**
 * @brief Populate a client's discovered services from a service discovery
 * response. if the client already has discovered services, they will be freed
 * first.
 *
 * @param client Client to populate.
 * @param response Service discovery response containing services.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_client_populate_services_from_response(
    libnngio_client *client,
    const LibnngioProtobuf__ServiceDiscoveryResponse *response);

/**
 * @brief Send an RPC request with the client.
 *
 * @param client Client to send request with.
 * @param request Pointer to the RPC request message.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_client_send_rpc_request(
    libnngio_client *client, const LibnngioProtobuf__RpcRequest *request);

/**
 * @brief Send an RPC request asynchronously with the client.
 *
 * @param client Client to send request with.
 * @param request Pointer to the RPC request message.
 * @param cb_info Callback info used when sending the request.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_client_send_rpc_request_async(
    libnngio_client *client, const LibnngioProtobuf__RpcRequest *request,
    libnngio_protobuf_send_cb_info cb_info);

/**
 * @brief Receive an RPC response with the client.
 * @param client Client to receive response with.
 * @param response Pointer to receive allocated RPC response message.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_client_recv_rpc_response(
    libnngio_client *client, LibnngioProtobuf__RpcResponse **response);

/**
 * @brief Receive an RPC response asynchronously with the client.
 * @param client Client to receive response with.
 * @param response Pointer to receive allocated RPC response message.
 * @param cb_info Callback info used when receiving the response.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_client_recv_rpc_response_async(
    libnngio_client *client, LibnngioProtobuf__RpcResponse **response,
    libnngio_protobuf_recv_cb_info cb_info);

/**
 * @brief Take a service discovery request and then generate a service discovery
 * response with the server's registered services.
 *
 * @param server Server containing registered services.
 * @param request Pointer to the service discovery request message.
 * @param response Pointer to receive allocated service discovery response.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_server_handle_service_discovery(
    libnngio_server *server,
    LibnngioProtobuf__ServiceDiscoveryRequest **request,
    LibnngioProtobuf__ServiceDiscoveryResponse **response);

/**
 * @brief Take a service discovery request and then generate a service discovery
 * response with the server's registered services, asynchronously.
 * @param server Server containing registered services.
 * @param request Pointer to the service discovery request message.
 * @param response Pointer to receive allocated service discovery response.
 * @param recv_cb_info Callback info used when receiving the request.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_server_handle_service_discovery_async(
    libnngio_server *server,
    LibnngioProtobuf__ServiceDiscoveryRequest **request,
    LibnngioProtobuf__ServiceDiscoveryResponse **response,
    libnngio_protobuf_recv_cb_info recv_cb_info);

/**
 * @brief Receive an RPC request with the server.
 *
 * @param server Server to receive request with.
 * @param request Pointer to receive allocated RPC request message.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_server_recv_rpc_request(
    libnngio_server *server, LibnngioProtobuf__RpcRequest **request);

/**
 * @brief Receive an RPC request asynchronously with the server.
 *
 * @param server Server to receive request with.
 * @param request Pointer to receive allocated RPC request message.
 * @param cb_info Callback info used when receiving the request.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_server_recv_rpc_request_async(
    libnngio_server *server, LibnngioProtobuf__RpcRequest **request,
    libnngio_protobuf_recv_cb_info cb_info);

/**
 * @brief Create an RPC response message based on the given request.
 *
 * Digest a given RPC request and generate an appropriate response. The response
 * payload is generated by invoking the registered method handler for the
 * requested service/method, if found.
 * @param request Pointer to the RPC request message.
 * @param response Pointer to receive allocated RPC response message.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_server_create_rpc_response(
    libnngio_server *server, const LibnngioProtobuf__RpcRequest *request,
    LibnngioProtobuf__RpcResponse **response);

/**
 * @brief send an RPC response with the server.
 * @param server Server to send response with.
 * @param response Pointer to the RPC response message.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_server_send_rpc_response(
    libnngio_server *server, const LibnngioProtobuf__RpcResponse *response);

/**
 * @brief send an RPC response asynchronously with the server.
 * @param server Server to send response with.
 * @param response Pointer to the RPC response message.
 * @param cb_info Callback info used when sending the response.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_server_send_rpc_response_async(
    libnngio_server *server, const LibnngioProtobuf__RpcResponse *response,
    libnngio_protobuf_send_cb_info cb_info);

/**
 * @brief Take an RPC request and then generate an RPC response by invoking the
 * registered method handler asynchronously.
 *
 * @param server Server containing registered services and method handlers.
 * @param request Pointer to the RPC request message.
 * @param response Pointer to receive allocated RPC response message.
 * @param recv_cb_info Callback info used when receiving the request.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_server_handle_rpc_request_async(
    libnngio_server *server, LibnngioProtobuf__RpcRequest **request,
    LibnngioProtobuf__RpcResponse **response,
    libnngio_protobuf_recv_cb_info recv_cb_info);

#endif  // LIBNNGIO_PROTOBUF_H
