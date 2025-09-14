/**
 * @struct libnngio_protobuf_context
 * @brief Context for sending and receiving protobuf messages over nngio.
 * This wraps a libnngio_context and provides methods for sending and
 * receiving protobuf messages.
 *
 * * The context does not own the underlying libnngio_context and will not free
 * it. The user is responsible for managing the lifecycle of the underlying
 * context.
 *
 * * The context provides methods for sending and receiving each defined message
 * type, both synchronously and asynchronously.
 *
 * * The provides methods for serializing and deserializing messages to/from
 * buffers.
 *
 *   proto_ctx -> ctx: is the underlying libnngio_context used for transport.
 */
#include <nng/nng.h> // for nng_strerror
#include "protobuf/libnngio_protobuf.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * @struct libnngio_protobuf_context
 * @brief Internal structure for libnngio_protobuf_context.
 */
struct libnngio_protobuf_context {
  libnngio_context *ctx;  ///< Underlying libnngio context for transport
  int transport_rv;       ///< Last transport error code
};

/*
 * @brief read len random bytes into buf
 *
 * @param buf Buffer to fill with random bytes.
 * @param len Number of random bytes to generate.
 */
static void get_random_bytes(uint8_t *buf, size_t len) {
    // Use /dev/urandom
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }
    if (fread(buf, 1, len, f) != len) {
        perror("fread");
        exit(EXIT_FAILURE);
    }
    fclose(f);
}

/**
 * @brief Convert NngioProtobuf__NngioMessage__MsgCase to human-readable string.
 *
 * @param msg_case The message case to convert.
 * @return A pointer to a static string describing the message case.
 */
char *libnngio_protobuf_nngio_msg_case_str(
    NngioProtobuf__NngioMessage__MsgCase msg_case) {
  switch (msg_case) {
    case NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG__NOT_SET:
      return "Not set";
    case NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RAW_MESSAGE:
      return "RawMessage";
    case NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RPC_REQUEST:
      return "RpcRequestMessage";
    case NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RPC_RESPONSE:
      return "RpcResponseMessage";
    case NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_REQUEST:
      return "ServiceDiscoveryRequest";
    case NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_RESPONSE:
      return "ServiceDiscoveryResponse";
    default:
      return "Unknown message case";
  }
}

/**
 * @brief Generate a random UUID (version 4) and format it as a string.
 *
 * @return A pointer to a static buffer containing the UUID string on success
 * or NULL on failure. The caller is responsible for freeing the returned
 * buffer.
 */
char* libnngio_protobuf_gen_uuid(void) {
    char *uuid_str = calloc(37, sizeof(char));
    uint8_t uuid[16];
    get_random_bytes(uuid, sizeof(uuid));

    // Set the UUID version (4)
    uuid[6] = (uuid[6] & 0x0F) | 0x40;
    // Set the UUID variant (RFC4122)
    uuid[8] = (uuid[8] & 0x3F) | 0x80;

    // Format: 8-4-4-4-12
    sprintf(uuid_str,
        "%02x%02x%02x%02x-"
        "%02x%02x-"
        "%02x%02x-"
        "%02x%02x-"
        "%02x%02x%02x%02x%02x%02x",
        uuid[0], uuid[1], uuid[2], uuid[3],
        uuid[4], uuid[5],
        uuid[6], uuid[7],
        uuid[8], uuid[9],
        uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]
    );
    return uuid_str;
}

/**
 * @brief Convert a libnngio_protobuf_error_code to a human-readable string.
 *
 * @param code  The error code to convert.
 * @return A pointer to a static string describing the error.
 */
char *libnngio_protobuf_strerror(libnngio_protobuf_error_code code) {
  switch (code) {
    case LIBNNGIO_PROTOBUF_ERR_NONE:
      return "No error";
    case LIBNNGIO_PROTOBUF_ERR_UNKNOWN:
      return "Unknown error";
    case LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT:
      return "Invalid context";
    case LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE:
      return "Invalid message format";
    case LIBNNGIO_PROTOBUF_ERR_SERVICE_NOT_FOUND:
      return "Requested service not found";
    case LIBNNGIO_PROTOBUF_ERR_METHOD_NOT_FOUND:
      return "Requested method not found";
    case LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED:
      return "Message serialization failed";
    case LIBNNGIO_PROTOBUF_ERR_DESERIALIZATION_FAILED:
      return "Message deserialization failed";
    case LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR:
      return "Underlying transport error";
    default:
      return "Unrecognized error code";
  }
}

/**
 * @brief Create a libnngio_protobuf_context by which protobuf messages can be
 * sent and received.
 * @param proto_ctx Pointer to the context to initialize.
 * @param ctx Pointer to the underlying libnngio context to use.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_context_init(
    libnngio_protobuf_context **proto_ctx, libnngio_context *ctx) {
  if (proto_ctx == NULL || ctx == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  struct libnngio_protobuf_context *new_ctx =
      malloc(sizeof(struct libnngio_protobuf_context));

  if (new_ctx == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  new_ctx->ctx = ctx;
  *proto_ctx = new_ctx;
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_CONTEXT_INIT", __FILE__, __LINE__,
               libnngio_context_id(ctx),
               "Initialized libnngio_protobuf context wrapping libnngio context "
               "%d.",
               libnngio_context_id(ctx));
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Free a libnngio_protobuf context and release resources.
 *
 * @param ctx Context handle to free.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_context_free(
    libnngio_protobuf_context *proto_ctx) {
  if (proto_ctx == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_NONE;
  }
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_CONTEXT_FREE", __FILE__, __LINE__,
               libnngio_context_id(proto_ctx->ctx),
               "Freeing libnngio_protobuf context wrapping libnngio context %d.",
               libnngio_context_id(proto_ctx->ctx));
  free(proto_ctx);
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Get the last transport error code from the underlying libnngio context.
 * @param ctx Pointer to the libnngio_protobuf context.
 * @return The last transport error code, or 0 if no error.
 */
int libnngio_protobuf_context_get_transport_rv(
    libnngio_protobuf_context *ctx) {
  if (ctx == NULL || ctx->ctx == NULL) {
    return 0;
  }
  return ctx->transport_rv;
}

/**
 * @brief Create and populate a NngioProtobuf__Service structure.
 *
 * Allocates and initializes a NngioProtobuf__Service with the given name and methods.
 * Deep-copies all strings.
 *
 * @param name Name of the service.
 * @param methods Array of method names.
 * @param n_methods Number of methods in the array.
 * @return Pointer to the allocated service, or NULL on failure.
 */
NngioProtobuf__Service *nngio_create_service(const char *name, const char **methods, size_t n_methods) {
    NngioProtobuf__Service *svc = malloc(sizeof(NngioProtobuf__Service));
    if (!svc) return NULL;
    nngio_protobuf__service__init(svc);
    svc->name = strdup(name ? name : "");
    svc->n_methods = n_methods;
    svc->methods = n_methods ? malloc(sizeof(char*) * n_methods) : NULL;
    for (size_t i = 0; i < n_methods; ++i) {
        svc->methods[i] = strdup(methods[i]);
    }
    return svc;
}

/**
 * @brief Free a NngioProtobuf__Service structure and its contents.
 *
 * Frees memory for the name, methods array, and method strings.
 *
 * @param svc Pointer to the service to free.
 */
void nngio_free_service(NngioProtobuf__Service *svc) {
    if (!svc) return;
    if (svc->name) free(svc->name);
    for (size_t i = 0; i < svc->n_methods; ++i) {
        if (svc->methods[i]) free(svc->methods[i]);
    }
    free(svc->methods);
    free(svc);
}

/**
 * @brief Create and populate a NngioProtobuf__ServiceDiscoveryResponse structure.
 *
 * Allocates and initializes a response containing the provided services.
 * Takes ownership of the service pointers.
 *
 * @param services Array of pointers to NngioProtobuf__Service.
 * @param n_services Number of services.
 * @return Pointer to allocated response, or NULL on failure.
 */
NngioProtobuf__ServiceDiscoveryResponse *nngio_create_service_discovery_response(NngioProtobuf__Service **services, size_t n_services) {
    NngioProtobuf__ServiceDiscoveryResponse *resp = malloc(sizeof(NngioProtobuf__ServiceDiscoveryResponse));
    if (!resp) return NULL;
    nngio_protobuf__service_discovery_response__init(resp);
    resp->n_services = n_services;
    resp->services = n_services ? malloc(sizeof(NngioProtobuf__Service*) * n_services) : NULL;
    for (size_t i = 0; i < n_services; ++i) {
        resp->services[i] = services[i];
    }
    return resp;
}

/**
 * @brief Free a NngioProtobuf__ServiceDiscoveryResponse and its contained services.
 *
 * Frees memory for the response, services array, and each service.
 *
 * @param resp Pointer to the response to free.
 */
void nngio_free_service_discovery_response(NngioProtobuf__ServiceDiscoveryResponse *resp) {
    if (!resp) return;
    if (resp->services) {
        for (size_t i = 0; i < resp->n_services; ++i) {
            nngio_free_service(resp->services[i]);
        }
        free(resp->services);
    }
    free(resp);
}

/**
 * @brief Create and populate a NngioProtobuf__RpcRequestMessage.
 *
 * Allocates and initializes a RPC request, deep-copying all strings and payload.
 *
 * @param service_name Service name string.
 * @param method_name Method name string.
 * @param payload Pointer to payload data.
 * @param payload_len Length of payload data.
 * @return Pointer to allocated request, or NULL on failure.
 */
NngioProtobuf__RpcRequestMessage *nngio_create_rpc_request(const char *service_name, const char *method_name, const void *payload, size_t payload_len) {
    NngioProtobuf__RpcRequestMessage *msg = malloc(sizeof(NngioProtobuf__RpcRequestMessage));
    if (!msg) return NULL;
    nngio_protobuf__rpc_request_message__init(msg);
    msg->service_name = strdup(service_name ? service_name : "");
    msg->method_name = strdup(method_name ? method_name : "");
    msg->payload.len = payload_len;
    msg->payload.data = payload_len ? malloc(payload_len) : NULL;
    if (payload && payload_len) {
        memcpy(msg->payload.data, payload, payload_len);
    }
    return msg;
}

/**
 * @brief Free a NngioProtobuf__RpcRequestMessage and its contents.
 *
 * Frees memory for the service name, method name, and payload.
 *
 * @param msg Pointer to the request to free.
 */
void nngio_free_rpc_request(NngioProtobuf__RpcRequestMessage *msg) {
    if (!msg) return;
    if (msg->service_name) free(msg->service_name);
    if (msg->method_name) free(msg->method_name);
    if (msg->payload.data) free(msg->payload.data);
    free(msg);
}

/**
 * @brief Create and populate a NngioProtobuf__RpcResponseMessage.
 *
 * Allocates and initializes a RPC response, deep-copying payload and error message.
 *
 * @param status Status of the response.
 * @param payload Pointer to payload data.
 * @param payload_len Length of the payload.
 * @param error_message Error message string (may be NULL).
 * @return Pointer to allocated response, or NULL on failure.
 */
NngioProtobuf__RpcResponseMessage *nngio_create_rpc_response(NngioProtobuf__RpcResponseMessage__Status status, const void *payload, size_t payload_len, const char *error_message) {
    NngioProtobuf__RpcResponseMessage *msg = malloc(sizeof(NngioProtobuf__RpcResponseMessage));
    if (!msg) return NULL;
    nngio_protobuf__rpc_response_message__init(msg);
    msg->status = status;
    msg->payload.len = payload_len;
    msg->payload.data = payload_len ? malloc(payload_len) : NULL;
    if (payload && payload_len) {
        memcpy(msg->payload.data, payload, payload_len);
    }
    msg->error_message = strdup(error_message ? error_message : "");
    return msg;
}

/**
 * @brief Free a NngioProtobuf__RpcResponseMessage and its contents.
 *
 * Frees memory for the payload and error message.
 *
 * @param msg Pointer to the response to free.
 */
void nngio_free_rpc_response(NngioProtobuf__RpcResponseMessage *msg) {
    if (!msg) return;
    if (msg->payload.data) free(msg->payload.data);
    if (msg->error_message) free(msg->error_message);
    free(msg);
}

/**
 * @brief Create and populate a NngioProtobuf__RawMessage.
 *
 * Allocates and initializes a raw message with the given binary data.
 * Deep-copies the data.
 *
 * @param data Pointer to binary data.
 * @param data_len Length of binary data.
 * @return Pointer to allocated raw message, or NULL on failure.
 */
NngioProtobuf__RawMessage *nngio_create_raw_message(const void *data, size_t data_len) {
    NngioProtobuf__RawMessage *msg = malloc(sizeof(NngioProtobuf__RawMessage));
    if (!msg) return NULL;
    nngio_protobuf__raw_message__init(msg);
    msg->data.len = data_len;
    msg->data.data = data_len ? malloc(data_len) : NULL;
    if (data && data_len) {
        memcpy(msg->data.data, data, data_len);
    }
    return msg;
}

/**
 * @brief Free a NngioProtobuf__RawMessage and its contents.
 *
 * Frees memory for the binary data.
 *
 * @param msg Pointer to the raw message to free.
 */
void nngio_free_raw_message(NngioProtobuf__RawMessage *msg) {
    if (!msg) return;
    if (msg->data.data) free(msg->data.data);
    free(msg);
}

/**
 * @brief Create a NngioProtobuf__NngioMessage containing a RpcRequestMessage.
 *
 * Allocates and initializes an NngioMessage. Takes ownership of rpc_request.
 *
 * @param uuid Unique identifier string.
 * @param rpc_request Pointer to a RpcRequestMessage.
 * @return Pointer to allocated NngioMessage, or NULL on failure.
 */
NngioProtobuf__NngioMessage *nngio_create_nngio_message_with_rpc_request(const char *uuid, NngioProtobuf__RpcRequestMessage *rpc_request) {
    NngioProtobuf__NngioMessage *msg = malloc(sizeof(NngioProtobuf__NngioMessage));
    if (!msg) return NULL;
    nngio_protobuf__nngio_message__init(msg);
    msg->uuid = strdup(uuid ? uuid : "");
    msg->msg_case = NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RPC_REQUEST;
    msg->rpc_request = rpc_request;
    return msg;
}

/**
 * @brief Create a NngioProtobuf__NngioMessage containing a RpcResponseMessage.
 *
 * Allocates and initializes an NngioMessage. Takes ownership of rpc_response.
 *
 * @param uuid Unique identifier string.
 * @param rpc_response Pointer to a RpcResponseMessage.
 * @return Pointer to allocated NngioMessage, or NULL on failure.
 */
NngioProtobuf__NngioMessage *nngio_create_nngio_message_with_rpc_response(const char *uuid, NngioProtobuf__RpcResponseMessage *rpc_response) {
    NngioProtobuf__NngioMessage *msg = malloc(sizeof(NngioProtobuf__NngioMessage));
    if (!msg) return NULL;
    nngio_protobuf__nngio_message__init(msg);
    msg->uuid = strdup(uuid ? uuid : "");
    msg->msg_case = NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RPC_RESPONSE;
    msg->rpc_response = rpc_response;
    return msg;
}

/**
 * @brief Create a NngioProtobuf__NngioMessage containing a RawMessage.
 *
 * Allocates and initializes an NngioMessage. Takes ownership of raw_message.
 *
 * @param uuid Unique identifier string.
 * @param raw_message Pointer to a RawMessage.
 * @return Pointer to allocated NngioMessage, or NULL on failure.
 */
NngioProtobuf__NngioMessage *nngio_create_nngio_message_with_raw(const char *uuid, NngioProtobuf__RawMessage *raw_message) {
    NngioProtobuf__NngioMessage *msg = malloc(sizeof(NngioProtobuf__NngioMessage));
    if (!msg) return NULL;
    nngio_protobuf__nngio_message__init(msg);
    msg->uuid = strdup(uuid ? uuid : "");
    msg->msg_case = NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RAW_MESSAGE;
    msg->raw_message = raw_message;
    return msg;
}

/**
 * @brief Create a NngioProtobuf__NngioMessage containing a ServiceDiscoveryRequest.
 *
 * Allocates and initializes an NngioMessage. Takes ownership of req.
 *
 * @param uuid Unique identifier string.
 * @param req Pointer to a ServiceDiscoveryRequest.
 * @return Pointer to allocated NngioMessage, or NULL on failure.
 */
NngioProtobuf__NngioMessage *nngio_create_nngio_message_with_service_discovery_request(const char *uuid, NngioProtobuf__ServiceDiscoveryRequest *req) {
    NngioProtobuf__NngioMessage *msg = malloc(sizeof(NngioProtobuf__NngioMessage));
    if (!msg) return NULL;
    nngio_protobuf__nngio_message__init(msg);
    msg->uuid = strdup(uuid ? uuid : "");
    msg->msg_case = NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_REQUEST;
    msg->service_discovery_request = req;
    return msg;
}

/**
 * @brief Create a NngioProtobuf__NngioMessage containing a ServiceDiscoveryResponse.
 *
 * Allocates and initializes an NngioMessage. Takes ownership of resp.
 *
 * @param uuid Unique identifier string.
 * @param resp Pointer to a ServiceDiscoveryResponse.
 * @return Pointer to allocated NngioMessage, or NULL on failure.
 */
NngioProtobuf__NngioMessage *nngio_create_nngio_message_with_service_discovery_response(const char *uuid, NngioProtobuf__ServiceDiscoveryResponse *resp) {
    NngioProtobuf__NngioMessage *msg = malloc(sizeof(NngioProtobuf__NngioMessage));
    if (!msg) return NULL;
    nngio_protobuf__nngio_message__init(msg);
    msg->uuid = strdup(uuid ? uuid : "");
    msg->msg_case = NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_RESPONSE;
    msg->service_discovery_response = resp;
    return msg;
}

/**
 * @brief Free a NngioProtobuf__NngioMessage and all nested messages.
 *
 * Frees memory for the uuid and the contained message (depending on msg_case).
 *
 * @param msg Pointer to the NngioMessage to free.
 */
void nngio_free_nngio_message(NngioProtobuf__NngioMessage *msg) {
    if (!msg) return;
    if (msg->uuid) free(msg->uuid);

    switch (msg->msg_case) {
        case NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_REQUEST:
            if (msg->service_discovery_request) {
                nngio_protobuf__service_discovery_request__free_unpacked(msg->service_discovery_request, NULL);
            }
            break;
        case NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_RESPONSE:
            if (msg->service_discovery_response) {
                nngio_free_service_discovery_response(msg->service_discovery_response);
            }
            break;
        case NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RPC_REQUEST:
            if (msg->rpc_request) {
                nngio_free_rpc_request(msg->rpc_request);
            }
            break;
        case NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RPC_RESPONSE:
            if (msg->rpc_response) {
                nngio_free_rpc_response(msg->rpc_response);
            }
            break;
        case NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RAW_MESSAGE:
            if (msg->raw_message) {
                nngio_free_raw_message(msg->raw_message);
            }
            break;
        default:
            break;
    }
    free(msg);
}

/**
 * @brief Send a raw message.
 * @param ctx           Context to use for sending.
 * @param message       Pointer to the raw message to send.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_send_raw_message(
    libnngio_protobuf_context *ctx, NngioProtobuf__RawMessage *message) {
  libnngio_protobuf_error_code rv;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RAW_MESSAGE", __FILE__,
                 __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (message == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RAW_MESSAGE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid raw message provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Wrap the RawMessage in a NngioMessage
  NngioProtobuf__NngioMessage nngio_msg = NNGIO_PROTOBUF__NNGIO_MESSAGE__INIT;
  nngio_msg.uuid = libnngio_protobuf_gen_uuid();
  nngio_msg.msg_case = NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RAW_MESSAGE;
  // copy raw message into nngio_msg without assignment to avoid ownership issues
  NngioProtobuf__RawMessage raw_msg_copy = NNGIO_PROTOBUF__RAW_MESSAGE__INIT;
  nngio_protobuf__raw_message__init(&raw_msg_copy);
  raw_msg_copy.data.len = message->data.len;
  raw_msg_copy.data.data = malloc(message->data.len);
  if (raw_msg_copy.data.data == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RAW_MESSAGE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for raw message data.");
    free(nngio_msg.uuid);
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }
  memcpy(raw_msg_copy.data.data, message->data.data, message->data.len);
  nngio_msg.raw_message = &raw_msg_copy;

  // Serialize the NngioMessage to a buffer
  size_t packed_size = nngio_protobuf__nngio_message__get_packed_size(&nngio_msg);
  uint8_t *buffer = malloc(packed_size);
  if (buffer == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RAW_MESSAGE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    free(nngio_msg.uuid);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  nngio_protobuf__nngio_message__pack(&nngio_msg, buffer);
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_RAW_MESSAGE", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Serialized raw message (%s) of size %zu bytes.", nngio_msg.uuid,
               packed_size);

  // Send the serialized buffer using the underlying libnngio context
  ctx->transport_rv = libnngio_context_send(ctx->ctx, buffer, packed_size);
  free(buffer);

  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RAW_MESSAGE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to send raw message: %s",
                 nng_strerror(ctx->transport_rv));
    free(raw_msg_copy.data.data);
    free(nngio_msg.uuid);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }
  libnngio_log("INF", "LIBNNGIO_PROTOBUF_SEND_RAW_MESSAGE", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Successfully sent raw message.");
  free(raw_msg_copy.data.data);
  free(nngio_msg.uuid);
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Receive a raw message.
 *
 * @param ctx       Context to use for receiving.
 * @param message   Pointer to receive allocated raw message.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_recv_raw_message(
    libnngio_protobuf_context *ctx, NngioProtobuf__RawMessage *message) {
  libnngio_protobuf_error_code rv;
  uint8_t *buffer = calloc(LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE, sizeof(uint8_t));
  size_t len = LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE;
  NngioProtobuf__NngioMessage *nngio_msg = NULL;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RAW_MESSAGE", __FILE__,
                 __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  ctx->transport_rv = libnngio_context_recv(ctx->ctx, buffer, &len);
  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RAW_MESSAGE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to receive raw message: %s",
                 nng_strerror(ctx->transport_rv));
    free(buffer);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }

  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV_RAW_MESSAGE", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Received raw message of size %zu bytes.", len);
  nngio_msg = nngio_protobuf__nngio_message__unpack(NULL, len, buffer);
  free(buffer);

  if (nngio_msg == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RAW_MESSAGE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to unpack NngioMessage from received buffer.");
    rv = LIBNNGIO_PROTOBUF_ERR_DESERIALIZATION_FAILED;
    return rv;
  }

  if (nngio_msg->msg_case != NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RAW_MESSAGE) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RAW_MESSAGE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Received message is not a RawMessage (msg_case=%d).",
                 nngio_msg->msg_case);
    nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Copy the received RawMessage to the provided pointer
  if (message == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RAW_MESSAGE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid RawMessage pointer provided for output.");
    nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }
  memcpy(message, nngio_msg->raw_message, sizeof(NngioProtobuf__RawMessage));
  message->data.data = malloc(nngio_msg->raw_message->data.len);
  if (message->data.data == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RAW_MESSAGE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for RawMessage data.");
    nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }
  memcpy(message->data.data, nngio_msg->raw_message->data.data,
         nngio_msg->raw_message->data.len);
  message->data.len = nngio_msg->raw_message->data.len;

  nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
  libnngio_log("INF", "LIBNNGIO_PROTOBUF_RECV_RAW_MESSAGE", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Successfully received raw message.");
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Send an RPC request message.
 *
 * @param ctx       Context to use for sending.
 * @param request   Pointer to the RPC request message to send.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_send_rpc_request(
    libnngio_protobuf_context *ctx,
    const NngioProtobuf__RpcRequestMessage *request) {
  libnngio_protobuf_error_code rv;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST", __FILE__,
                 __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (request == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid RPC request message provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Wrap the RpcRequestMessage in a NngioMessage
  NngioProtobuf__NngioMessage nngio_msg = NNGIO_PROTOBUF__NNGIO_MESSAGE__INIT;
  nngio_msg.uuid = libnngio_protobuf_gen_uuid();
  nngio_msg.msg_case = NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RPC_REQUEST;
  // copy rpc request message into nngio_msg without assignment to avoid ownership issues
  NngioProtobuf__RpcRequestMessage rpc_request_copy =
      NNGIO_PROTOBUF__RPC_REQUEST_MESSAGE__INIT;
  nngio_protobuf__rpc_request_message__init(&rpc_request_copy);
  rpc_request_copy.service_name = strdup(request->service_name);
  rpc_request_copy.method_name = strdup(request->method_name);
  rpc_request_copy.payload.len = request->payload.len;
  rpc_request_copy.payload.data = malloc(request->payload.len);
  if (rpc_request_copy.payload.data == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for RPC request payload.");
    free(nngio_msg.uuid);
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }
  memcpy(rpc_request_copy.payload.data, request->payload.data, request->payload.len);
  nngio_msg.rpc_request = &rpc_request_copy;

  // Serialize the NngioMessage to a buffer
  size_t packed_size = nngio_protobuf__nngio_message__get_packed_size(&nngio_msg);
  uint8_t *buffer = malloc(packed_size);
  if (buffer == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    free(nngio_msg.uuid);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }
  nngio_protobuf__nngio_message__pack(&nngio_msg, buffer);
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Serialized RPC request message (%s) of size %zu bytes.",
               nngio_msg.uuid,
               packed_size);

  // Send the serialized buffer using the underlying libnngio context
  ctx->transport_rv = libnngio_context_send(ctx->ctx, buffer, packed_size);
  free(buffer);

  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to send RPC request message: %s",
                 nng_strerror(ctx->transport_rv));
    free(rpc_request_copy.service_name);
    free(rpc_request_copy.method_name);
    free(rpc_request_copy.payload.data);
    free(nngio_msg.uuid);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }
  libnngio_log("INF", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Successfully sent RPC request message.");
  free(rpc_request_copy.service_name);
  free(rpc_request_copy.method_name);
  free(rpc_request_copy.payload.data);
  free(nngio_msg.uuid);
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Receive an RPC request message.
 *
 * @param ctx       Context to use for receiving.
 * @param request   Pointer to receive allocated RPC request message.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_recv_rpc_request(
    libnngio_protobuf_context *ctx, NngioProtobuf__RpcRequestMessage *request) {
  libnngio_protobuf_error_code rv;
  uint8_t *buffer = calloc(LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE, sizeof(uint8_t));
  size_t len = LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE;
  NngioProtobuf__NngioMessage *nngio_msg = NULL;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST", __FILE__,
                 __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  ctx->transport_rv = libnngio_context_recv(ctx->ctx, buffer, &len);
  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to receive RPC request message: %s",
                 nng_strerror(ctx->transport_rv));
    free(buffer);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }

  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Received RPC request message of size %zu bytes.", len);

  nngio_msg = nngio_protobuf__nngio_message__unpack(NULL, len, buffer);
  free(buffer);
  if (nngio_msg == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to unpack received RPC request message.");
    rv = LIBNNGIO_PROTOBUF_ERR_DESERIALIZATION_FAILED;
    return rv;
  }

  if (nngio_msg->msg_case != NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RPC_REQUEST) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Received message is not an RPC request (msg_case=%s).",
                 libnngio_protobuf_nngio_msg_case_str(nngio_msg->msg_case));
    nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Unpacked RPC request message successfully.");
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "RPC Request details: UUID='%s', Service='%s', Method='%s', Payload size=%zu.",
               nngio_msg->uuid,
               nngio_msg->rpc_request->service_name,
               nngio_msg->rpc_request->method_name,
               nngio_msg->rpc_request->payload.len);

  // Copy the received message to the user-provided structure
  memcpy(request, nngio_msg->rpc_request, sizeof(NngioProtobuf__RpcRequestMessage));
  if (nngio_msg->rpc_request->service_name) {
    request->service_name = strdup(nngio_msg->rpc_request->service_name);
  }
  if (nngio_msg->rpc_request->method_name) {
    request->method_name = strdup(nngio_msg->rpc_request->method_name);
  }
  if (nngio_msg->rpc_request->payload.len > 0 && nngio_msg->rpc_request->payload.data) {
    request->payload.len = nngio_msg->rpc_request->payload.len;
    request->payload.data = malloc(request->payload.len);
    memcpy(request->payload.data, nngio_msg->rpc_request->payload.data, request->payload.len);
  } else {
    request->payload.len = 0;
    request->payload.data = NULL;
  }

  nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
  libnngio_log("INF", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Successfully received RPC request message.");
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Send an RPC response message.
 *
 * @param ctx       Context to use for sending.
 * @param response  Pointer to the RPC response message to send.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_send_rpc_response(
    libnngio_protobuf_context *ctx,
    const NngioProtobuf__RpcResponseMessage *response) {
  libnngio_protobuf_error_code rv;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_RESPONSE", __FILE__,
                 __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (response == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_RESPONSE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid RPC response message provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Wrap the RpcResponseMessage in a NngioMessage
  NngioProtobuf__NngioMessage nngio_msg = NNGIO_PROTOBUF__NNGIO_MESSAGE__INIT;
  nngio_msg.uuid = libnngio_protobuf_gen_uuid();
  nngio_msg.msg_case = NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RPC_RESPONSE;
  // copy rpc response message into nngio_msg without assignment to avoid ownership issues
  NngioProtobuf__RpcResponseMessage rpc_response_copy =
      NNGIO_PROTOBUF__RPC_RESPONSE_MESSAGE__INIT;
  nngio_protobuf__rpc_response_message__init(&rpc_response_copy);
  rpc_response_copy.status = response->status;
  rpc_response_copy.payload.len = response->payload.len;
  rpc_response_copy.payload.data = malloc(response->payload.len);
  if (rpc_response_copy.payload.data == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_RESPONSE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for RPC response payload.");
    free(nngio_msg.uuid);
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }
  memcpy(rpc_response_copy.payload.data, response->payload.data, response->payload.len);
  nngio_msg.rpc_response = &rpc_response_copy;

  // Serialize the NngioMessage to a buffer
  size_t packed_size = nngio_protobuf__nngio_message__get_packed_size(&nngio_msg);
  uint8_t *buffer = malloc(packed_size);
  if (buffer == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_RESPONSE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    free(nngio_msg.uuid);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  nngio_protobuf__nngio_message__pack(&nngio_msg, buffer);
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_RPC_RESPONSE", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Serialized RPC response message (%s) of size %zu bytes.",
               nngio_msg.uuid,
               packed_size);

  // Send the serialized buffer using the underlying libnngio context
  ctx->transport_rv = libnngio_context_send(ctx->ctx, buffer, packed_size);
  free(buffer);

  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_RESPONSE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to send RPC response message: %s",
                 nng_strerror(ctx->transport_rv));
    free(rpc_response_copy.payload.data);
    free(nngio_msg.uuid);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }

  libnngio_log("INF", "LIBNNGIO_PROTOBUF_SEND_RPC_RESPONSE", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Successfully sent RPC response message.");
  free(rpc_response_copy.payload.data);
  free(nngio_msg.uuid);
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Receive an RPC response message.
 *
 * @param ctx       Context to use for receiving.
 * @param response  Pointer to receive allocated RPC response message.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_recv_rpc_response(
    libnngio_protobuf_context *ctx, NngioProtobuf__RpcResponseMessage *response) {
  libnngio_protobuf_error_code rv;

  uint8_t *buffer = calloc(LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE, sizeof(uint8_t));
  size_t len = LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE;
  NngioProtobuf__NngioMessage *nngio_msg = NULL;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_RESPONSE", __FILE__,
                 __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  ctx->transport_rv = libnngio_context_recv(ctx->ctx, buffer, &len);
  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_RESPONSE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to receive RPC response message: %s",
                 nng_strerror(ctx->transport_rv));
    free(buffer);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }

  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV_RPC_RESPONSE", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Received RPC response message of size %zu bytes.", len);

  nngio_msg = nngio_protobuf__nngio_message__unpack(NULL, len, buffer);
  free(buffer);
  if (nngio_msg == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_RESPONSE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to unpack received RPC response message.");
    rv = LIBNNGIO_PROTOBUF_ERR_DESERIALIZATION_FAILED;
    return rv;
  }

  if (nngio_msg->msg_case != NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RPC_RESPONSE) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_RESPONSE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Received message is not an RPC response (msg_case=%s).",
                 libnngio_protobuf_nngio_msg_case_str(nngio_msg->msg_case));
    nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV_RPC_RESPONSE", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Unpacked RPC response message successfully.");
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV_RPC_RESPONSE", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "RPC Response details: UUID='%s', Status=%d, Payload size=%zu.",
               nngio_msg->uuid,
               nngio_msg->rpc_response->status,
               nngio_msg->rpc_response->payload.len);

  // Copy the received message to the user-provided structure
  memcpy(response, nngio_msg->rpc_response, sizeof(NngioProtobuf__RpcResponseMessage));
  response->status = nngio_msg->rpc_response->status;
  if (nngio_msg->rpc_response->payload.len > 0 && nngio_msg->rpc_response->payload.data) {
    response->payload.len = nngio_msg->rpc_response->payload.len;
    response->payload.data = malloc(response->payload.len);
    memcpy(response->payload.data, nngio_msg->rpc_response->payload.data, response->payload.len);
  } else {
    response->payload.len = 0;
    response->payload.data = NULL;
  }

  nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
  libnngio_log("INF", "LIBNNGIO_PROTOBUF_RECV_RPC_RESPONSE", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Successfully received RPC response message.");
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Send a service discovery request message.
 *
 * @param ctx       Context to use for sending.
 * @param request   Pointer to the service discovery request message to send.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_send_service_discovery_request(
    libnngio_protobuf_context *ctx,
    const NngioProtobuf__ServiceDiscoveryRequest *request) {
  libnngio_protobuf_error_code rv;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_REQUEST", __FILE__,
                 __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (request == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_REQUEST", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid service discovery request message provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Wrap the ServiceDiscoveryRequest in a NngioMessage
  NngioProtobuf__NngioMessage nngio_msg = NNGIO_PROTOBUF__NNGIO_MESSAGE__INIT;
  nngio_msg.uuid = libnngio_protobuf_gen_uuid();
  nngio_msg.msg_case = NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_REQUEST;
  // copy service discovery request message into nngio_msg without assignment to avoid ownership issues
  NngioProtobuf__ServiceDiscoveryRequest sd_request_copy =
      NNGIO_PROTOBUF__SERVICE_DISCOVERY_REQUEST__INIT;
  nngio_protobuf__service_discovery_request__init(&sd_request_copy);
  nngio_msg.service_discovery_request = &sd_request_copy;

  // Serialize the NngioMessage to a buffer
  size_t packed_size = nngio_protobuf__nngio_message__get_packed_size(&nngio_msg);
  uint8_t *buffer = malloc(packed_size);
  if (buffer == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_REQUEST", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    free(nngio_msg.uuid);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  nngio_protobuf__nngio_message__pack(&nngio_msg, buffer);
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_REQUEST", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Serialized service discovery request message (%s) of size %zu bytes.",
               nngio_msg.uuid,
               packed_size);

  // Send the serialized buffer using the underlying libnngio context
  ctx->transport_rv = libnngio_context_send(ctx->ctx, buffer, packed_size);
  free(buffer);

  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_REQUEST", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to send service discovery request message: %s",
                 nng_strerror(ctx->transport_rv));
    free(nngio_msg.uuid);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }

  libnngio_log("INF", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_REQUEST", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Successfully sent service discovery request message.");
  free(nngio_msg.uuid);
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Receive a service discovery request message.
 *
 * @param ctx       Context to use for receiving.
 * @param request   Pointer to receive allocated service discovery request message.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_recv_service_discovery_request(
    libnngio_protobuf_context *ctx,
    NngioProtobuf__ServiceDiscoveryRequest *request) {
  libnngio_protobuf_error_code rv;

  uint8_t *buffer = calloc(LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE, sizeof(uint8_t));
  size_t len = LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE;
  NngioProtobuf__NngioMessage *nngio_msg = NULL;
  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_REQUEST", __FILE__,
                 __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  ctx->transport_rv = libnngio_context_recv(ctx->ctx, buffer, &len);
  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_REQUEST", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to receive service discovery request message: %s",
                 nng_strerror(ctx->transport_rv));
    free(buffer);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }

  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_REQUEST", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Received service discovery request message of size %zu bytes.", len);

  nngio_msg = nngio_protobuf__nngio_message__unpack(NULL, len, buffer);
  free(buffer);
  if (nngio_msg == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_REQUEST", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to unpack received service discovery request message.");
    rv = LIBNNGIO_PROTOBUF_ERR_DESERIALIZATION_FAILED;
    return rv;
  }

  if (nngio_msg->msg_case !=
      NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_REQUEST) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_REQUEST", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Received message is not a service discovery request (msg_case=%s).",
                 libnngio_protobuf_nngio_msg_case_str(nngio_msg->msg_case));
    nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_REQUEST", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Unpacked service discovery request message successfully.");
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_REQUEST", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Service Discovery Request details: UUID='%s'.",
               nngio_msg->uuid);

  // Copy the received message to the user-provided structure
  memcpy(request, nngio_msg->service_discovery_request, sizeof(NngioProtobuf__ServiceDiscoveryRequest));
  nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
  libnngio_log("INF", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_REQUEST", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Successfully received service discovery request message.");
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Send a service discovery response message.
 *
 * @param ctx       Context to use for sending.
 * @param response  Pointer to the service discovery response message to send.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_send_service_discovery_response(
    libnngio_protobuf_context *ctx,
    const NngioProtobuf__ServiceDiscoveryResponse *response) {
  libnngio_protobuf_error_code rv = LIBNNGIO_PROTOBUF_ERR_NONE;
  return rv;
}

/**
 * @brief Receive a service discovery response message.
 *
 * @param ctx       Context to use for receiving.
 * @param response  Pointer to receive allocated service discovery response message.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_recv_service_discovery_response(
    libnngio_protobuf_context *ctx,
    NngioProtobuf__ServiceDiscoveryResponse *response) {
  libnngio_protobuf_error_code rv = LIBNNGIO_PROTOBUF_ERR_NONE;
  return rv;
}
