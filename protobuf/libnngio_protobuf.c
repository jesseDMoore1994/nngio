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
#include "protobuf/libnngio_protobuf.h"

#include <nng/nng.h>  // for nng_strerror
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
char *libnngio_protobuf_gen_uuid(void) {
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
          uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6],
          uuid[7], uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13],
          uuid[14], uuid[15]);
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
  libnngio_log(
      "DBG", "LIBNNGIO_PROTOBUF_CONTEXT_INIT", __FILE__, __LINE__,
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
  libnngio_log(
      "DBG", "LIBNNGIO_PROTOBUF_CONTEXT_FREE", __FILE__, __LINE__,
      libnngio_context_id(proto_ctx->ctx),
      "Freeing libnngio_protobuf context wrapping libnngio context %d.",
      libnngio_context_id(proto_ctx->ctx));
  free(proto_ctx);
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Get the last transport error code from the underlying libnngio
 * context.
 * @param ctx Pointer to the libnngio_protobuf context.
 * @return The last transport error code, or 0 if no error.
 */
int libnngio_protobuf_context_get_transport_rv(libnngio_protobuf_context *ctx) {
  if (ctx == NULL || ctx->ctx == NULL) {
    return 0;
  }
  return ctx->transport_rv;
}

/**
 * @brief Create and populate a NngioProtobuf__Service structure.
 *
 * Allocates and initializes a NngioProtobuf__Service with the given name and
 * methods. Deep-copies all strings.
 *
 * @param name Name of the service.
 * @param methods Array of method names.
 * @param n_methods Number of methods in the array.
 * @return Pointer to the allocated service, or NULL on failure.
 */
NngioProtobuf__Service *nngio_create_service(const char *name,
                                             const char **methods,
                                             size_t n_methods) {
  NngioProtobuf__Service *svc = malloc(sizeof(NngioProtobuf__Service));
  if (!svc) return NULL;
  nngio_protobuf__service__init(svc);
  svc->name = strdup(name ? name : "");
  svc->n_methods = n_methods;
  svc->methods = n_methods ? malloc(sizeof(char *) * n_methods) : NULL;
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
 * @brief Create and populate a NngioProtobuf__ServiceDiscoveryResponse
 * structure.
 *
 * Allocates and initializes a response containing the provided services.
 * Takes ownership of the service pointers.
 *
 * @param services Array of pointers to NngioProtobuf__Service.
 * @param n_services Number of services.
 * @return Pointer to allocated response, or NULL on failure.
 */
NngioProtobuf__ServiceDiscoveryResponse *
nngio_create_service_discovery_response(NngioProtobuf__Service **services,
                                        size_t n_services) {
  NngioProtobuf__ServiceDiscoveryResponse *resp =
      malloc(sizeof(NngioProtobuf__ServiceDiscoveryResponse));
  if (!resp) return NULL;
  nngio_protobuf__service_discovery_response__init(resp);
  resp->n_services = n_services;
  resp->services =
      n_services ? malloc(sizeof(NngioProtobuf__Service *) * n_services) : NULL;
  for (size_t i = 0; i < n_services; ++i) {
    resp->services[i] = services[i];
  }
  return resp;
}

/**
 * @brief Free a NngioProtobuf__ServiceDiscoveryResponse and its contained
 * services.
 *
 * Frees memory for the response, services array, and each service.
 *
 * @param resp Pointer to the response to free.
 */
void nngio_free_service_discovery_response(
    NngioProtobuf__ServiceDiscoveryResponse *resp) {
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
 * Allocates and initializes a RPC request, deep-copying all strings and
 * payload.
 *
 * @param service_name Service name string.
 * @param method_name Method name string.
 * @param payload Pointer to payload data.
 * @param payload_len Length of payload data.
 * @return Pointer to allocated request, or NULL on failure.
 */
NngioProtobuf__RpcRequestMessage *nngio_create_rpc_request(
    const char *service_name, const char *method_name, const void *payload,
    size_t payload_len) {
  NngioProtobuf__RpcRequestMessage *msg =
      malloc(sizeof(NngioProtobuf__RpcRequestMessage));
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
 * Allocates and initializes a RPC response, deep-copying payload and error
 * message.
 *
 * @param status Status of the response.
 * @param payload Pointer to payload data.
 * @param payload_len Length of the payload.
 * @param error_message Error message string (may be NULL).
 * @return Pointer to allocated response, or NULL on failure.
 */
NngioProtobuf__RpcResponseMessage *nngio_create_rpc_response(
    NngioProtobuf__RpcResponseMessage__Status status, const void *payload,
    size_t payload_len, const char *error_message) {
  NngioProtobuf__RpcResponseMessage *msg =
      malloc(sizeof(NngioProtobuf__RpcResponseMessage));
  if (!msg) return NULL;
  nngio_protobuf__rpc_response_message__init(msg);
  msg->status = status;
  msg->payload.len = payload_len;
  msg->payload.data = payload_len ? malloc(payload_len) : NULL;
  if (payload && payload_len) {
    memcpy(msg->payload.data, payload, payload_len);
  }
  msg->error_message = error_message ? strdup(error_message) : NULL;
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
NngioProtobuf__RawMessage *nngio_create_raw_message(const void *data,
                                                    size_t data_len) {
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
NngioProtobuf__NngioMessage *nngio_create_nngio_message_with_rpc_request(
    const char *uuid, NngioProtobuf__RpcRequestMessage *rpc_request) {
  NngioProtobuf__NngioMessage *msg =
      malloc(sizeof(NngioProtobuf__NngioMessage));
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
NngioProtobuf__NngioMessage *nngio_create_nngio_message_with_rpc_response(
    const char *uuid, NngioProtobuf__RpcResponseMessage *rpc_response) {
  NngioProtobuf__NngioMessage *msg =
      malloc(sizeof(NngioProtobuf__NngioMessage));
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
NngioProtobuf__NngioMessage *nngio_create_nngio_message_with_raw(
    const char *uuid, NngioProtobuf__RawMessage *raw_message) {
  NngioProtobuf__NngioMessage *msg =
      malloc(sizeof(NngioProtobuf__NngioMessage));
  if (!msg) return NULL;
  nngio_protobuf__nngio_message__init(msg);
  msg->uuid = strdup(uuid ? uuid : "");
  msg->msg_case = NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RAW_MESSAGE;
  msg->raw_message = raw_message;
  return msg;
}

/**
 * @brief Create a NngioProtobuf__NngioMessage containing a
 * ServiceDiscoveryRequest.
 *
 * Allocates and initializes an NngioMessage. Takes ownership of req.
 *
 * @param uuid Unique identifier string.
 * @param req Pointer to a ServiceDiscoveryRequest.
 * @return Pointer to allocated NngioMessage, or NULL on failure.
 */
NngioProtobuf__NngioMessage *
nngio_create_nngio_message_with_service_discovery_request(
    const char *uuid, NngioProtobuf__ServiceDiscoveryRequest *req) {
  NngioProtobuf__NngioMessage *msg =
      malloc(sizeof(NngioProtobuf__NngioMessage));
  if (!msg) return NULL;
  nngio_protobuf__nngio_message__init(msg);
  msg->uuid = strdup(uuid ? uuid : "");
  msg->msg_case = NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_REQUEST;
  msg->service_discovery_request = req;
  return msg;
}

/**
 * @brief Create a NngioProtobuf__NngioMessage containing a
 * ServiceDiscoveryResponse.
 *
 * Allocates and initializes an NngioMessage. Takes ownership of resp.
 *
 * @param uuid Unique identifier string.
 * @param resp Pointer to a ServiceDiscoveryResponse.
 * @return Pointer to allocated NngioMessage, or NULL on failure.
 */
NngioProtobuf__NngioMessage *
nngio_create_nngio_message_with_service_discovery_response(
    const char *uuid, NngioProtobuf__ServiceDiscoveryResponse *resp) {
  NngioProtobuf__NngioMessage *msg =
      malloc(sizeof(NngioProtobuf__NngioMessage));
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
        nngio_protobuf__service_discovery_request__free_unpacked(
            msg->service_discovery_request, NULL);
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
 * @brief Deep copy a NngioProtobuf__Service structure.
 */
NngioProtobuf__Service *nngio_copy_service(const NngioProtobuf__Service *src) {
  if (!src) return NULL;
  return nngio_create_service(src->name, (const char **)src->methods,
                              src->n_methods);
}

/**
 * @brief Deep copy a NngioProtobuf__ServiceDiscoveryResponse structure.
 */
NngioProtobuf__ServiceDiscoveryResponse *nngio_copy_service_discovery_response(
    const NngioProtobuf__ServiceDiscoveryResponse *src) {
  if (!src) return NULL;
  NngioProtobuf__Service **services = NULL;
  if (src->n_services) {
    services = malloc(sizeof(NngioProtobuf__Service *) * src->n_services);
    if (!services) return NULL;
    for (size_t i = 0; i < src->n_services; ++i) {
      services[i] = nngio_copy_service(src->services[i]);
      if (!services[i]) {
        // cleanup previous copies
        for (size_t j = 0; j < i; ++j) nngio_free_service(services[j]);
        free(services);
        return NULL;
      }
    }
  }
  NngioProtobuf__ServiceDiscoveryResponse *resp =
      nngio_create_service_discovery_response(services, src->n_services);
  free(
      services);  // nngio_create_service_discovery_response copies the pointers
  return resp;
}

/**
 * @brief Deep copy a NngioProtobuf__RpcRequestMessage structure.
 */
NngioProtobuf__RpcRequestMessage *nngio_copy_rpc_request(
    const NngioProtobuf__RpcRequestMessage *src) {
  if (!src) return NULL;
  return nngio_create_rpc_request(src->service_name, src->method_name,
                                  src->payload.data, src->payload.len);
}

/**
 * @brief Deep copy a NngioProtobuf__RpcResponseMessage structure.
 */
NngioProtobuf__RpcResponseMessage *nngio_copy_rpc_response(
    const NngioProtobuf__RpcResponseMessage *src) {
  if (!src) return NULL;
  return nngio_create_rpc_response(src->status, src->payload.data,
                                   src->payload.len, src->error_message);
}

/**
 * @brief Deep copy a NngioProtobuf__RawMessage structure.
 */
NngioProtobuf__RawMessage *nngio_copy_raw_message(
    const NngioProtobuf__RawMessage *src) {
  if (!src) return NULL;
  libnngio_log("DBG", "NNGIO_COPY_RAW_MESSAGE", __FILE__, __LINE__, -1,
               "Copying RawMessage of size %zu bytes.", src->data.len);
  return nngio_create_raw_message(src->data.data, src->data.len);
}

/**
 * @brief Deep copy a NngioProtobuf__NngioMessage structure.
 */
NngioProtobuf__NngioMessage *nngio_copy_nngio_message(
    const NngioProtobuf__NngioMessage *src) {
  if (!src) return NULL;
  NngioProtobuf__NngioMessage *dst =
      malloc(sizeof(NngioProtobuf__NngioMessage));
  if (!dst) return NULL;
  nngio_protobuf__nngio_message__init(dst);
  dst->uuid = strdup(src->uuid ? src->uuid : "");
  dst->msg_case = src->msg_case;

  switch (src->msg_case) {
    case NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_REQUEST:
      if (src->service_discovery_request) {
        dst->service_discovery_request =
            malloc(sizeof(NngioProtobuf__ServiceDiscoveryRequest));
        if (dst->service_discovery_request)
          nngio_protobuf__service_discovery_request__init(
              dst->service_discovery_request);
      }
      break;
    case NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_RESPONSE:
      dst->service_discovery_response = nngio_copy_service_discovery_response(
          src->service_discovery_response);
      break;
    case NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RPC_REQUEST:
      dst->rpc_request = nngio_copy_rpc_request(src->rpc_request);
      break;
    case NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RPC_RESPONSE:
      dst->rpc_response = nngio_copy_rpc_response(src->rpc_response);
      break;
    case NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RAW_MESSAGE:
      dst->raw_message = nngio_copy_raw_message(src->raw_message);
      break;
    default:
      // do nothing - not set
      break;
  }
  return dst;
}

/**
 * @brief Send a raw message.
 * @param ctx           Context to use for sending.
 * @param message       Pointer to the raw message to send.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_send_raw_message(
    libnngio_protobuf_context *ctx, const NngioProtobuf__RawMessage *message) {
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
  NngioProtobuf__NngioMessage *nngio_msg =
      malloc(sizeof(NngioProtobuf__NngioMessage));
  nngio_protobuf__nngio_message__init(nngio_msg);
  nngio_msg->uuid = libnngio_protobuf_gen_uuid();
  nngio_msg->msg_case = NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RAW_MESSAGE;
  nngio_msg->raw_message = nngio_copy_raw_message(message);

  // Serialize the NngioMessage to a buffer
  size_t packed_size =
      nngio_protobuf__nngio_message__get_packed_size(nngio_msg);
  uint8_t *buffer = malloc(packed_size);
  if (buffer == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RAW_MESSAGE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  nngio_protobuf__nngio_message__pack(nngio_msg, buffer);
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_RAW_MESSAGE", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Serialized raw message (%s) of size %zu bytes.",
               nngio_msg->uuid, packed_size);

  // Send the serialized buffer using the underlying libnngio context
  ctx->transport_rv = libnngio_context_send(ctx->ctx, buffer, packed_size);
  nngio_free_nngio_message(nngio_msg);
  free(buffer);

  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RAW_MESSAGE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to send raw message: %s",
                 nng_strerror(ctx->transport_rv));
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }
  libnngio_log("INF", "LIBNNGIO_PROTOBUF_SEND_RAW_MESSAGE", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx), "Successfully sent raw message.");
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

typedef struct {
  libnngio_protobuf_send_async_cb user_cb;
  NngioProtobuf__NngioMessage *msg;
  libnngio_protobuf_context *ctx;
  void *user_data;
  void *buffer;
  size_t len;
} send_async_cb_data;

static void send_raw_message_async_cb(libnngio_context *ctx, int result,
                                      void *data, size_t len, void *arg) {
  send_async_cb_data *cb_data = (send_async_cb_data *)arg;
  libnngio_protobuf_error_code rv;
  if (result != 0) {
    libnngio_log("ERR", "SEND_RAW_MESSAGE_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx), "Asynchronous send failed: %s",
                 nng_strerror(result));
  } else {
    libnngio_log("INF", "SEND_RAW_MESSAGE_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Asynchronous send completed successfully.");
  }

  libnngio_log("DBG", "SEND_RAW_MESSAGE_ASYNC_CB", __FILE__, __LINE__,
               libnngio_context_id(ctx),
               "Invoking user callback with user data %p.", cb_data->user_data);

  libnngio_log("DBG", "SEND_RAW_MESSAGE_ASYNC_CB", __FILE__, __LINE__,
               libnngio_context_id(ctx), "msg pointer: %p.", *(cb_data->msg));

  // Make a copy of the message to pass to the user callback
  // Invoke the user callback
  if (cb_data->user_cb) {
    cb_data->user_cb(cb_data->ctx, result, cb_data->msg, cb_data->user_data);
  }
  free(cb_data->buffer);
  free(cb_data);
}

/**
 * @brief Send a raw message asynchronously.
 *
 * @param ctx       Context to use for sending.
 * @param message   Pointer to the raw message to send.
 * @param cb        Callback function to invoke upon send completion.
 * @param arg       User-defined argument to pass to the callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_send_raw_message_async(
    libnngio_protobuf_context *ctx, const NngioProtobuf__RawMessage *message,
    libnngio_protobuf_send_async_cb cb, void *user_data) {
  libnngio_protobuf_error_code rv;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RAW_MESSAGE_ASYNC", __FILE__,
                 __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (message == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RAW_MESSAGE_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid raw message provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  if (cb == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RAW_MESSAGE_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid callback function provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Wrap the RawMessage in a NngioMessage
  NngioProtobuf__NngioMessage *nngio_msg =
      malloc(sizeof(NngioProtobuf__NngioMessage));
  nngio_protobuf__nngio_message__init(nngio_msg);
  nngio_msg->uuid = libnngio_protobuf_gen_uuid();
  nngio_msg->msg_case = NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RAW_MESSAGE;
  nngio_msg->raw_message = nngio_copy_raw_message(message);

  // Prepare callback data
  // Note: cb_data->msg will be freed in the callback after user_cb is invoked
  // it will also copy the message before passing to user_cb
  send_async_cb_data *cb_data = malloc(sizeof(send_async_cb_data));
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_RAW_MESSAGE_ASYNC", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Prepared callback data structure at %p.", cb_data);

  cb_data->user_cb = cb;
  cb_data->ctx = ctx;
  cb_data->user_data = user_data;
  cb_data->msg = nngio_msg;
  cb_data->len = nngio_protobuf__nngio_message__get_packed_size(nngio_msg);
  cb_data->buffer = malloc(cb_data->len);

  if (!cb_data) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RAW_MESSAGE_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for callback data.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  // Serialize the NngioMessage into the callback buffer
  if (cb_data->buffer == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RAW_MESSAGE_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  nngio_protobuf__nngio_message__pack(cb_data->msg, cb_data->buffer);
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_RAW_MESSAGE_ASYNC", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Serialized raw message (%s) of size %zu bytes.",
               nngio_msg->uuid, cb_data->len);

  // Send the serialized buffer asynchronously using the underlying libnngio
  // context
  ctx->transport_rv =
      libnngio_context_send_async(ctx->ctx, cb_data->buffer, cb_data->len,
                                  send_raw_message_async_cb, cb_data);

  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RAW_MESSAGE_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to send raw message asynchronously: %s",
                 nng_strerror(ctx->transport_rv));
    free(cb_data);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }
  libnngio_log("INF", "LIBNNGIO_PROTOBUF_SEND_RAW_MESSAGE_ASYNC", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Successfully initiated async send of raw message.");
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Receive a raw message.
 *
 * @param ctx       Context to use for receiving.
 * @param message   Pointer to location newly allocated raw message.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_recv_raw_message(
    libnngio_protobuf_context *ctx, NngioProtobuf__RawMessage **message) {
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

  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV_RAW_MESSAGE", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Received message of size %zu bytes.", len);
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
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV_RAW_MESSAGE", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Received raw message (%s) of size %zu bytes.", nngio_msg->uuid,
               nngio_msg->raw_message->data.len);

  // Copy the raw message data into the provided message using deep copy helper
  // function. `nngio_copy_raw_message`.
  (*message) = nngio_copy_raw_message(nngio_msg->raw_message);

  nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
  libnngio_log("INF", "LIBNNGIO_PROTOBUF_RECV_RAW_MESSAGE", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Successfully received raw message.");
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

typedef struct {
  libnngio_protobuf_recv_async_cb user_cb;
  void **msg;
  libnngio_protobuf_context *ctx;
  void *user_data;
  void *buffer;
  size_t len;
} recv_async_cb_data;

static void recv_raw_message_async_cb(libnngio_context *ctx, int result,
                                      void *data, size_t len, void *arg) {
  recv_async_cb_data *cb_data = (recv_async_cb_data *)arg;
  libnngio_protobuf_error_code rv = LIBNNGIO_PROTOBUF_ERR_NONE;
  // Note: data is a pointer to the received buffer, len is its length
  // Unpack the NngioMessage from the received buffer
  NngioProtobuf__NngioMessage *nngio_msg = NULL;
  NngioProtobuf__RawMessage **raw = (NngioProtobuf__RawMessage **)cb_data->msg;
  if (result != 0) {
    libnngio_log("ERR", "RECV_RAW_MESSAGE_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx), "Asynchronous receive failed: %s",
                 nng_strerror(result));
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
  } else {
    libnngio_log("INF", "RECV_RAW_MESSAGE_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Asynchronous receive completed successfully.");
  }

  nngio_msg = nngio_protobuf__nngio_message__unpack(NULL, len, data);
  if (nngio_msg == NULL) {
    libnngio_log("ERR", "RECV_RAW_MESSAGE_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Failed to unpack NngioMessage from received buffer.");
    rv = LIBNNGIO_PROTOBUF_ERR_DESERIALIZATION_FAILED;
  } else if (nngio_msg->msg_case !=
             NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RAW_MESSAGE) {
    libnngio_log("ERR", "RECV_RAW_MESSAGE_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Received message is not a RawMessage (msg_case=%d).",
                 nngio_msg->msg_case);
    nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
  } else {
    libnngio_log("DBG", "RECV_RAW_MESSAGE_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Received message (%s) of size %zu bytes.", nngio_msg->uuid,
                 len);
  }

  libnngio_log(
      "INF", "RECV_RAW_MESSAGE_ASYNC_CB", __FILE__, __LINE__,
      libnngio_context_id(ctx),
      "Asynchronous receive callback processing completed with code %d.", rv);
  libnngio_log("DBG", "RECV_RAW_MESSAGE_ASYNC_CB", __FILE__, __LINE__,
               libnngio_context_id(ctx),
               "Received raw message (%s) of size %zu bytes.",
               nngio_msg ? nngio_msg->uuid : "NULL",
               nngio_msg ? nngio_msg->raw_message->data.len : 0);

  // update the user's message pointer if we successfully received a message
  if (rv == LIBNNGIO_PROTOBUF_ERR_NONE && nngio_msg && cb_data->msg) {
    *(raw) = nngio_copy_raw_message(nngio_msg->raw_message);
  }

  // Make a copy of the message to pass to the user callback
  NngioProtobuf__NngioMessage *msg =
      nngio_msg ? nngio_copy_nngio_message(nngio_msg) : NULL;

  // Make a copy of the message to pass to the user callback
  if (cb_data->user_cb) {
    cb_data->user_cb(cb_data->ctx, result, msg ? &msg : NULL,
                     cb_data->user_data);
  }

  nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
  free(cb_data->buffer);
  free(cb_data);
}

/**
 * @brief Receive a raw message asynchronously.
 *
 * @param ctx       Context to use for receiving.
 * @param message   Pointer to location to store newly allocated raw message.
 * @param cb        Callback function to invoke upon receive completion.
 * @param arg       User-defined argument to pass to the callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_recv_raw_message_async(
    libnngio_protobuf_context *ctx, NngioProtobuf__RawMessage **message,
    libnngio_protobuf_recv_async_cb cb, void *user_data) {
  libnngio_protobuf_error_code rv;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RAW_MESSAGE_ASYNC", __FILE__,
                 __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (cb == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RAW_MESSAGE_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid callback function provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Prepare callback data
  recv_async_cb_data *cb_data = malloc(sizeof(recv_async_cb_data));
  if (!cb_data) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RAW_MESSAGE_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for callback data.");
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  cb_data->buffer = calloc(LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE, sizeof(uint8_t));
  cb_data->len = LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE;
  cb_data->user_cb = cb;
  cb_data->ctx = ctx;
  cb_data->user_data = user_data;
  cb_data->msg = (void **)message;

  // Receive the serialized buffer asynchronously using the underlying libnngio
  // context
  ctx->transport_rv =
      libnngio_context_recv_async(ctx->ctx, cb_data->buffer, &cb_data->len,
                                  recv_raw_message_async_cb, cb_data);
  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RAW_MESSAGE_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to receive raw message asynchronously: %s",
                 nng_strerror(ctx->transport_rv));
    free(cb_data);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }

  libnngio_log("INF", "LIBNNGIO_PROTOBUF_RECV_RAW_MESSAGE_ASYNC", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Successfully initiated async receive of raw message.");

  // Note: The actual message will be processed by the callback function.
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
  NngioProtobuf__NngioMessage *nngio_msg =
      malloc(sizeof(NngioProtobuf__NngioMessage));
  nngio_protobuf__nngio_message__init(nngio_msg);
  nngio_msg->uuid = libnngio_protobuf_gen_uuid();
  nngio_msg->msg_case = NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RPC_REQUEST;
  nngio_msg->rpc_request = nngio_copy_rpc_request(request);

  // Serialize the NngioMessage to a buffer
  size_t packed_size =
      nngio_protobuf__nngio_message__get_packed_size(nngio_msg);
  uint8_t *buffer = malloc(packed_size);
  if (buffer == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }
  nngio_protobuf__nngio_message__pack(nngio_msg, buffer);
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Serialized RPC request message (%s) of size %zu bytes.",
               nngio_msg->uuid, packed_size);

  // Send the serialized buffer using the underlying libnngio context
  ctx->transport_rv = libnngio_context_send(ctx->ctx, buffer, packed_size);
  nngio_free_nngio_message(nngio_msg);
  free(buffer);

  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to send RPC request message: %s",
                 nng_strerror(ctx->transport_rv));
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }
  libnngio_log("INF", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Successfully sent RPC request message.");
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

static void send_rpc_request_async_cb(libnngio_context *ctx, int result,
                                      void *data, size_t len, void *arg) {
  send_async_cb_data *cb_data = (send_async_cb_data *)arg;
  libnngio_protobuf_error_code rv;
  if (result != 0) {
    libnngio_log("ERR", "SEND_RPC_REQUEST_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx), "Asynchronous send failed: %s",
                 nng_strerror(result));
  } else {
    libnngio_log("INF", "SEND_RPC_REQUEST_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Asynchronous send completed successfully.");
  }

  libnngio_log("DBG", "SEND_RPC_REQUEST_ASYNC_CB", __FILE__, __LINE__,
               libnngio_context_id(ctx),
               "Invoking user callback with user data %p.", cb_data->user_data);

  libnngio_log("DBG", "SEND_RPC_REQUEST_ASYNC_CB", __FILE__, __LINE__,
               libnngio_context_id(ctx), "msg pointer: %p.", *(cb_data->msg));

  // Make a copy of the message to pass to the user callback
  // Invoke the user callback
  if (cb_data->user_cb) {
    cb_data->user_cb(cb_data->ctx, result, cb_data->msg, cb_data->user_data);
  }
  free(cb_data->buffer);
  free(cb_data);
}

/**
 * @brief Send an RPC request message asynchronously.
 *
 * @param ctx       Context to use for sending.
 * @param message   Pointer to the raw message to send.
 * @param cb        Callback function to invoke upon send completion.
 * @param arg       User-defined argument to pass to the callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_send_rpc_request_async(
    libnngio_protobuf_context *ctx,
    const NngioProtobuf__RpcRequestMessage *request,
    libnngio_protobuf_send_async_cb cb, void *user_data) {
  libnngio_protobuf_error_code rv;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST_ASYNC", __FILE__,
                 __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (request == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid raw message provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  if (cb == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid callback function provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Wrap the RawMessage in a NngioMessage
  NngioProtobuf__NngioMessage *nngio_msg =
      malloc(sizeof(NngioProtobuf__NngioMessage));
  nngio_protobuf__nngio_message__init(nngio_msg);
  nngio_msg->uuid = libnngio_protobuf_gen_uuid();
  nngio_msg->msg_case = NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RPC_REQUEST;
  nngio_msg->rpc_request = nngio_copy_rpc_request(request);

  // Prepare callback data
  // Note: cb_data->msg will be freed in the callback after user_cb is invoked
  // it will also copy the message before passing to user_cb
  send_async_cb_data *cb_data = malloc(sizeof(send_async_cb_data));
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST_ASYNC", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Prepared callback data structure at %p.", cb_data);

  cb_data->user_cb = cb;
  cb_data->ctx = ctx;
  cb_data->user_data = user_data;
  cb_data->msg = nngio_msg;
  cb_data->len = nngio_protobuf__nngio_message__get_packed_size(nngio_msg);
  cb_data->buffer = malloc(cb_data->len);

  if (!cb_data) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for callback data.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  // Serialize the NngioMessage into the callback buffer
  if (cb_data->buffer == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  nngio_protobuf__nngio_message__pack(cb_data->msg, cb_data->buffer);
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST_ASYNC", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Serialized raw message (%s) of size %zu bytes.",
               nngio_msg->uuid, cb_data->len);

  // Send the serialized buffer asynchronously using the underlying libnngio
  // context
  ctx->transport_rv =
      libnngio_context_send_async(ctx->ctx, cb_data->buffer, cb_data->len,
                                  send_rpc_request_async_cb, cb_data);

  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to send raw message asynchronously: %s",
                 nng_strerror(ctx->transport_rv));
    free(cb_data);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }
  libnngio_log("INF", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST_ASYNC", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Successfully initiated async send of raw message.");
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
    libnngio_protobuf_context *ctx,
    NngioProtobuf__RpcRequestMessage **request) {
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

  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Received message of size %zu bytes.", len);

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

  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Unpacked RPC request message successfully.");
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "RPC Request details: UUID='%s', Service='%s', Method='%s', "
               "Payload size=%zu.",
               nngio_msg->uuid, nngio_msg->rpc_request->service_name,
               nngio_msg->rpc_request->method_name,
               nngio_msg->rpc_request->payload.len);

  // Copy the received message to the user-provided structure
  (*request) = nngio_copy_rpc_request(nngio_msg->rpc_request);

  nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
  libnngio_log("INF", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Successfully received RPC request message.");
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

static void recv_rpc_request_async_cb(libnngio_context *ctx, int result,
                                      void *data, size_t len, void *arg) {
  recv_async_cb_data *cb_data = (recv_async_cb_data *)arg;
  libnngio_protobuf_error_code rv = LIBNNGIO_PROTOBUF_ERR_NONE;
  // Note: data is a pointer to the received buffer, len is its length
  // Unpack the NngioMessage from the received buffer
  NngioProtobuf__NngioMessage *nngio_msg = NULL;
  NngioProtobuf__RpcRequestMessage **rpc_req =
      (NngioProtobuf__RpcRequestMessage **)cb_data->msg;
  if (result != 0) {
    libnngio_log("ERR", "RECV_RPC_REQUEST_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx), "Asynchronous receive failed: %s",
                 nng_strerror(result));
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
  } else {
    libnngio_log("INF", "RECV_RPC_REQUEST_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Asynchronous receive completed successfully.");
  }

  nngio_msg = nngio_protobuf__nngio_message__unpack(NULL, len, data);
  if (nngio_msg == NULL) {
    libnngio_log("ERR", "RECV_RPC_REQUEST_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Failed to unpack NngioMessage from received buffer.");
    rv = LIBNNGIO_PROTOBUF_ERR_DESERIALIZATION_FAILED;
  } else if (nngio_msg->msg_case !=
             NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RPC_REQUEST) {
    libnngio_log("ERR", "RECV_RPC_REQUEST_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Received message is not a RPC Request (msg_case=%d).",
                 nngio_msg->msg_case);
    nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
  } else {
    libnngio_log("DBG", "RECV_RPC_REQUEST_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Received message (%s) of size %zu bytes.", nngio_msg->uuid,
                 len);
  }

  libnngio_log(
      "INF", "RECV_RPC_REQUEST_ASYNC_CB", __FILE__, __LINE__,
      libnngio_context_id(ctx),
      "Asynchronous receive callback processing completed with code %d.", rv);
  libnngio_log("DBG", "RECV_RPC_REQUEST_ASYNC_CB", __FILE__, __LINE__,
               libnngio_context_id(ctx),
               "Received rpc request (%s) service name (%s) method name (%s) .",
               nngio_msg ? nngio_msg->uuid : "NULL",
               nngio_msg ? nngio_msg->rpc_request->service_name : "NULL",
               nngio_msg ? nngio_msg->rpc_request->method_name : "NULL");

  // update the user's message pointer if we successfully received a message
  if (rv == LIBNNGIO_PROTOBUF_ERR_NONE && nngio_msg && cb_data->msg) {
    *(cb_data->msg) = nngio_copy_rpc_request(nngio_msg->rpc_request);
  }

  // Make a copy of the message to pass to the user callback
  NngioProtobuf__NngioMessage *msg =
      nngio_msg ? nngio_copy_nngio_message(nngio_msg) : NULL;

  // Make a copy of the message to pass to the user callback
  if (cb_data->user_cb) {
    cb_data->user_cb(cb_data->ctx, result, msg ? &msg : NULL,
                     cb_data->user_data);
  }

  nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
  free(cb_data->buffer);
  free(cb_data);
}

/**
 * @brief Send an RPC request message asynchronously.
 *
 * @param ctx       Context to use for sending.
 * @param message   Pointer to the raw message to send.
 * @param cb        Callback function to invoke upon send completion.
 * @param arg       User-defined argument to pass to the callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_recv_rpc_request_async(
    libnngio_protobuf_context *ctx, NngioProtobuf__RpcRequestMessage **request,
    libnngio_protobuf_recv_async_cb cb, void *user_data) {
  libnngio_protobuf_error_code rv = LIBNNGIO_PROTOBUF_ERR_NONE;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST_ASYNC", __FILE__,
                 __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (cb == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid callback function provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Prepare callback data
  recv_async_cb_data *cb_data = malloc(sizeof(recv_async_cb_data));
  if (!cb_data) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for callback data.");
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }
  cb_data->buffer = calloc(LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE, sizeof(uint8_t));
  cb_data->len = LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE;
  cb_data->user_cb = cb;
  cb_data->ctx = ctx;
  cb_data->user_data = user_data;
  cb_data->msg =
      (void **)request;  // Note: message will be updated in the callback

  // Receive the serialized buffer asynchronously using the underlying libnngio
  // context
  ctx->transport_rv =
      libnngio_context_recv_async(ctx->ctx, cb_data->buffer, &cb_data->len,
                                  recv_rpc_request_async_cb, cb_data);
  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to receive rpc request asynchronously: %s",
                 nng_strerror(ctx->transport_rv));
    free(cb_data);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }

  libnngio_log("INF", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST_ASYNC", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Successfully initiated async receive of rpc request message.");

  // Note: The actual message will be processed by the callback function.
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
  NngioProtobuf__NngioMessage *nngio_msg =
      malloc(sizeof(NngioProtobuf__NngioMessage));
  nngio_protobuf__nngio_message__init(nngio_msg);
  nngio_msg->uuid = libnngio_protobuf_gen_uuid();
  nngio_msg->msg_case = NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RPC_RESPONSE;
  nngio_msg->rpc_response = nngio_copy_rpc_response(response);

  // Serialize the NngioMessage to a buffer
  size_t packed_size =
      nngio_protobuf__nngio_message__get_packed_size(nngio_msg);
  uint8_t *buffer = malloc(packed_size);
  if (buffer == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_RESPONSE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  nngio_protobuf__nngio_message__pack(nngio_msg, buffer);
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_RPC_RESPONSE", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Serialized RPC response message (%s) of size %zu bytes.",
               nngio_msg->uuid, packed_size);

  // Send the serialized buffer using the underlying libnngio context
  ctx->transport_rv = libnngio_context_send(ctx->ctx, buffer, packed_size);
  nngio_free_nngio_message(nngio_msg);
  free(buffer);

  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_RESPONSE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to send RPC response message: %s",
                 nng_strerror(ctx->transport_rv));
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }

  libnngio_log("INF", "LIBNNGIO_PROTOBUF_SEND_RPC_RESPONSE", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Successfully sent RPC response message.");
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

static void send_rpc_response_async_cb(libnngio_context *ctx, int result,
                                       void *data, size_t len, void *arg) {
  send_async_cb_data *cb_data = (send_async_cb_data *)arg;
  libnngio_protobuf_error_code rv;
  if (result != 0) {
    libnngio_log("ERR", "SEND_RPC_RESPONSE_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx), "Asynchronous send failed: %s",
                 nng_strerror(result));
  } else {
    libnngio_log("INF", "SEND_RPC_RESPONSE_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Asynchronous send completed successfully.");
  }

  libnngio_log("DBG", "SEND_RPC_RESPONSE_ASYNC_CB", __FILE__, __LINE__,
               libnngio_context_id(ctx),
               "Invoking user callback with user data %p.", cb_data->user_data);

  libnngio_log("DBG", "SEND_RPC_RESPONSE_ASYNC_CB", __FILE__, __LINE__,
               libnngio_context_id(ctx), "msg pointer: %p.", *(cb_data->msg));

  // Make a copy of the message to pass to the user callback
  // Invoke the user callback
  if (cb_data->user_cb) {
    cb_data->user_cb(cb_data->ctx, result, cb_data->msg, cb_data->user_data);
  }
  free(cb_data->buffer);
  free(cb_data);
}

/**
 * @brief Send an RPC response message asynchronously.
 *
 * @param ctx       Context to use for sending.
 * @param message   Pointer to the rpc response to send.
 * @param cb        Callback function to invoke upon send completion.
 * @param arg       User-defined argument to pass to the callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_send_rpc_response_async(
    libnngio_protobuf_context *ctx,
    const NngioProtobuf__RpcResponseMessage *response,
    libnngio_protobuf_send_async_cb cb, void *user_data) {
  libnngio_protobuf_error_code rv;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_RESPONSE_ASYNC", __FILE__,
                 __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (response == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_RESPONSE_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid rpc response provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  if (cb == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_RESPONSE_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid callback function provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Wrap the Response in a NngioMessage
  NngioProtobuf__NngioMessage *nngio_msg =
      malloc(sizeof(NngioProtobuf__NngioMessage));
  nngio_protobuf__nngio_message__init(nngio_msg);
  nngio_msg->uuid = libnngio_protobuf_gen_uuid();
  nngio_msg->msg_case = NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RPC_RESPONSE;
  nngio_msg->rpc_response = nngio_copy_rpc_response(response);

  // Prepare callback data
  // Note: cb_data->msg will be freed in the callback after user_cb is invoked
  // it will also copy the message before passing to user_cb
  send_async_cb_data *cb_data = malloc(sizeof(send_async_cb_data));
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_RPC_RESPONSE_ASYNC", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Prepared callback data structure at %p.", cb_data);

  cb_data->user_cb = cb;
  cb_data->ctx = ctx;
  cb_data->user_data = user_data;
  cb_data->msg = nngio_msg;
  cb_data->len = nngio_protobuf__nngio_message__get_packed_size(nngio_msg);
  cb_data->buffer = malloc(cb_data->len);

  if (!cb_data) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_RESPONSE_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for callback data.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  // Serialize the NngioMessage into the callback buffer
  if (cb_data->buffer == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_RESPONSE_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  nngio_protobuf__nngio_message__pack(cb_data->msg, cb_data->buffer);
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_RPC_RESPONSE_ASYNC", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Serialized rpc response (%s) of size %zu bytes.",
               nngio_msg->uuid, cb_data->len);

  // Send the serialized buffer asynchronously using the underlying libnngio
  // context
  ctx->transport_rv =
      libnngio_context_send_async(ctx->ctx, cb_data->buffer, cb_data->len,
                                  send_rpc_response_async_cb, cb_data);

  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_RESPONSE_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to send rpc response asynchronously: %s",
                 nng_strerror(ctx->transport_rv));
    free(cb_data);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }
  libnngio_log("INF", "LIBNNGIO_PROTOBUF_SEND_RPC_RESPONSE_ASYNC", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Successfully initiated async send of rpc response.");
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
    libnngio_protobuf_context *ctx,
    NngioProtobuf__RpcResponseMessage **response) {
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

  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV_RPC_RESPONSE", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Received message of size %zu bytes.", len);

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

  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV_RPC_RESPONSE", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Unpacked RPC response message successfully.");
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV_RPC_RESPONSE", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "RPC Response details: UUID='%s', Status=%d, Payload size=%zu.",
               nngio_msg->uuid, nngio_msg->rpc_response->status,
               nngio_msg->rpc_response->payload.len);

  // Copy the received message to the user-provided structure
  (*response) = nngio_copy_rpc_response(nngio_msg->rpc_response);

  nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
  libnngio_log("INF", "LIBNNGIO_PROTOBUF_RECV_RPC_RESPONSE", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Successfully received RPC response message.");
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

static void recv_rpc_response_async_cb(libnngio_context *ctx, int result,
                                       void *data, size_t len, void *arg) {
  recv_async_cb_data *cb_data = (recv_async_cb_data *)arg;
  libnngio_protobuf_error_code rv = LIBNNGIO_PROTOBUF_ERR_NONE;
  // Note: data is a pointer to the received buffer, len is its length
  // Unpack the NngioMessage from the received buffer
  NngioProtobuf__NngioMessage *nngio_msg = NULL;
  NngioProtobuf__RpcResponseMessage **rpc_resp =
      (NngioProtobuf__RpcResponseMessage **)cb_data->msg;
  if (result != 0) {
    libnngio_log("ERR", "RECV_RPC_RESPONSE_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx), "Asynchronous receive failed: %s",
                 nng_strerror(result));
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
  } else {
    libnngio_log("INF", "RECV_RPC_RESPONSE_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Asynchronous receive completed successfully.");
  }

  nngio_msg = nngio_protobuf__nngio_message__unpack(NULL, len, data);
  if (nngio_msg == NULL) {
    libnngio_log("ERR", "RECV_RPC_RESPONSE_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Failed to unpack NngioMessage from received buffer.");
    rv = LIBNNGIO_PROTOBUF_ERR_DESERIALIZATION_FAILED;
  } else if (nngio_msg->msg_case !=
             NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RPC_RESPONSE) {
    libnngio_log("ERR", "RECV_RPC_RESPONSE_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Received message is not a RPC Response (msg_case=%d).",
                 nngio_msg->msg_case);
    nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
  } else {
    libnngio_log("DBG", "RECV_RPC_RESPONSE_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Received message (%s) of size %zu bytes.", nngio_msg->uuid,
                 len);
  }

  libnngio_log(
      "INF", "RECV_RPC_RESPONSE_ASYNC_CB", __FILE__, __LINE__,
      libnngio_context_id(ctx),
      "Asynchronous receive callback processing completed with code %d.", rv);
  libnngio_log("DBG", "RECV_RPC_RESPONSE_ASYNC_CB", __FILE__, __LINE__,
               libnngio_context_id(ctx), "Received rpc response (%s).",
               nngio_msg ? nngio_msg->uuid : "NULL");

  // update the user's message pointer if we successfully received a message
  if (rv == LIBNNGIO_PROTOBUF_ERR_NONE && nngio_msg && cb_data->msg) {
    *(cb_data->msg) = nngio_copy_rpc_response(nngio_msg->rpc_response);
  }

  // Make a copy of the message to pass to the user callback
  NngioProtobuf__NngioMessage *msg =
      nngio_msg ? nngio_copy_nngio_message(nngio_msg) : NULL;

  // Make a copy of the message to pass to the user callback
  if (cb_data->user_cb) {
    cb_data->user_cb(cb_data->ctx, result, msg ? &msg : NULL,
                     cb_data->user_data);
  }

  nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
  free(cb_data->buffer);
  free(cb_data);
}

/**
 * @brief Send an RPC response message asynchronously.
 *
 * @param ctx       Context to use for sending.
 * @param message   Pointer to receive the rpc response.
 * @param cb        Callback function to invoke upon send completion.
 * @param arg       User-defined argument to pass to the callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_recv_rpc_response_async(
    libnngio_protobuf_context *ctx,
    NngioProtobuf__RpcResponseMessage **response,
    libnngio_protobuf_recv_async_cb cb, void *user_data) {
  libnngio_protobuf_error_code rv = LIBNNGIO_PROTOBUF_ERR_NONE;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST_ASYNC", __FILE__,
                 __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (cb == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid callback function provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Prepare callback data
  recv_async_cb_data *cb_data = malloc(sizeof(recv_async_cb_data));
  if (!cb_data) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for callback data.");
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }
  cb_data->buffer = calloc(LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE, sizeof(uint8_t));
  cb_data->len = LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE;
  cb_data->user_cb = cb;
  cb_data->ctx = ctx;
  cb_data->user_data = user_data;
  cb_data->msg =
      (void **)response;  // Note: message will be updated in the callback

  // Receive the serialized buffer asynchronously using the underlying libnngio
  // context
  ctx->transport_rv =
      libnngio_context_recv_async(ctx->ctx, cb_data->buffer, &cb_data->len,
                                  recv_rpc_response_async_cb, cb_data);
  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to receive rpc request asynchronously: %s",
                 nng_strerror(ctx->transport_rv));
    free(cb_data);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }

  libnngio_log("INF", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST_ASYNC", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Successfully initiated async receive of rpc request message.");

  // Note: The actual message will be processed by the callback function.
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
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_REQUEST",
                 __FILE__, __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (request == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_REQUEST",
                 __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid service discovery request message provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Wrap the ServiceDiscoveryRequest in a NngioMessage
  NngioProtobuf__NngioMessage nngio_msg = NNGIO_PROTOBUF__NNGIO_MESSAGE__INIT;
  nngio_msg.uuid = libnngio_protobuf_gen_uuid();
  nngio_msg.msg_case =
      NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_REQUEST;
  // copy service discovery request message into nngio_msg without assignment to
  // avoid ownership issues
  NngioProtobuf__ServiceDiscoveryRequest *sd_request_copy =
      malloc(sizeof(NngioProtobuf__ServiceDiscoveryRequest));
  nngio_protobuf__service_discovery_request__init(sd_request_copy);
  nngio_msg.service_discovery_request = sd_request_copy;

  // Serialize the NngioMessage to a buffer
  size_t packed_size =
      nngio_protobuf__nngio_message__get_packed_size(&nngio_msg);
  uint8_t *buffer = malloc(packed_size);
  if (buffer == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_REQUEST",
                 __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    free(nngio_msg.uuid);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  nngio_protobuf__nngio_message__pack(&nngio_msg, buffer);
  libnngio_log(
      "DBG", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_REQUEST", __FILE__,
      __LINE__, libnngio_context_id(ctx->ctx),
      "Serialized service discovery request message (%s) of size %zu bytes.",
      nngio_msg.uuid, packed_size);

  // Send the serialized buffer using the underlying libnngio context
  ctx->transport_rv = libnngio_context_send(ctx->ctx, buffer, packed_size);
  free(buffer);

  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_REQUEST",
                 __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to send service discovery request message: %s",
                 nng_strerror(ctx->transport_rv));
    free(nngio_msg.uuid);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }

  libnngio_log("INF", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_REQUEST",
               __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
               "Successfully sent service discovery request message.");
  free(nngio_msg.uuid);
  free(sd_request_copy);
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

static void send_service_discovery_request_async_cb(libnngio_context *ctx,
                                                    int result, void *data,
                                                    size_t len, void *arg) {
  send_async_cb_data *cb_data = (send_async_cb_data *)arg;
  libnngio_protobuf_error_code rv;
  if (result != 0) {
    libnngio_log("ERR", "SEND_SERVICE_DISCOVERY_REQUEST_ASYNC_CB", __FILE__,
                 __LINE__, libnngio_context_id(ctx),
                 "Asynchronous send failed: %s", nng_strerror(result));
  } else {
    libnngio_log("INF", "SEND_SERVICE_DISCOVERY_REQUEST_ASYNC_CB", __FILE__,
                 __LINE__, libnngio_context_id(ctx),
                 "Asynchronous send completed successfully.");
  }

  libnngio_log("DBG", "SEND_SERVICE_DISCOVERY_REQUEST_ASYNC_CB", __FILE__,
               __LINE__, libnngio_context_id(ctx),
               "Invoking user callback with user data %p.", cb_data->user_data);

  libnngio_log("DBG", "SEND_SERVICE_DISCOVERY_REQUEST_ASYNC_CB", __FILE__,
               __LINE__, libnngio_context_id(ctx), "msg pointer: %p.",
               *(cb_data->msg));

  // Make a copy of the message to pass to the user callback
  // Invoke the user callback
  if (cb_data->user_cb) {
    cb_data->user_cb(cb_data->ctx, result, cb_data->msg, cb_data->user_data);
  }
  free(cb_data->buffer);
  free(cb_data);
}

/**
 * @brief Send an RPC request message asynchronously.
 *
 * @param ctx       Context to use for sending.
 * @param message   Pointer to the raw message to send.
 * @param cb        Callback function to invoke upon send completion.
 * @param arg       User-defined argument to pass to the callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code
libnngio_protobuf_send_service_discovery_request_async(
    libnngio_protobuf_context *ctx,
    const NngioProtobuf__ServiceDiscoveryRequest *request,
    libnngio_protobuf_send_async_cb cb, void *user_data) {
  libnngio_protobuf_error_code rv;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR",
                 "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_REQUEST_ASYNC",
                 __FILE__, __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (request == NULL) {
    libnngio_log("ERR",
                 "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_REQUEST_ASYNC",
                 __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid service discovery request provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  if (cb == NULL) {
    libnngio_log("ERR",
                 "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_REQUEST_ASYNC",
                 __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid callback function provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Wrap the RawMessage in a NngioMessage
  NngioProtobuf__NngioMessage *nngio_msg =
      malloc(sizeof(NngioProtobuf__NngioMessage));
  nngio_protobuf__nngio_message__init(nngio_msg);
  nngio_msg->uuid = libnngio_protobuf_gen_uuid();
  nngio_msg->msg_case =
      NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_REQUEST;
  NngioProtobuf__ServiceDiscoveryRequest *sd_request_copy =
      malloc(sizeof(NngioProtobuf__ServiceDiscoveryRequest));
  nngio_protobuf__service_discovery_request__init(sd_request_copy);
  nngio_msg->service_discovery_request = sd_request_copy;

  // Prepare callback data
  // Note: cb_data->msg will be freed in the callback after user_cb is invoked
  // it will also copy the message before passing to user_cb
  send_async_cb_data *cb_data = malloc(sizeof(send_async_cb_data));
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_REQUEST_ASYNC",
               __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
               "Prepared callback data structure at %p.", cb_data);

  cb_data->user_cb = cb;
  cb_data->ctx = ctx;
  cb_data->user_data = user_data;
  cb_data->msg = nngio_msg;
  cb_data->len = nngio_protobuf__nngio_message__get_packed_size(nngio_msg);
  cb_data->buffer = malloc(cb_data->len);

  if (!cb_data) {
    libnngio_log("ERR",
                 "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_REQUEST_ASYNC",
                 __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for callback data.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  // Serialize the NngioMessage into the callback buffer
  if (cb_data->buffer == NULL) {
    libnngio_log("ERR",
                 "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_REQUEST_ASYNC",
                 __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  nngio_protobuf__nngio_message__pack(cb_data->msg, cb_data->buffer);
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_REQUEST_ASYNC",
               __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
               "Serialized service discovery request (%s) of size %zu bytes.",
               nngio_msg->uuid, cb_data->len);

  // Send the serialized buffer asynchronously using the underlying libnngio
  // context
  ctx->transport_rv = libnngio_context_send_async(
      ctx->ctx, cb_data->buffer, cb_data->len,
      send_service_discovery_request_async_cb, cb_data);

  if (ctx->transport_rv != 0) {
    libnngio_log("ERR",
                 "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_REQUEST_ASYNC",
                 __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to send service discovery request asynchronously: %s",
                 nng_strerror(ctx->transport_rv));
    free(cb_data);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }
  libnngio_log(
      "INF", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_REQUEST_ASYNC", __FILE__,
      __LINE__, libnngio_context_id(ctx->ctx),
      "Successfully initiated async send of service discovery request.");
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Receive a service discovery request message.
 *
 * @param ctx       Context to use for receiving.
 * @param request   Pointer to receive allocated service discovery request
 * message.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_recv_service_discovery_request(
    libnngio_protobuf_context *ctx,
    NngioProtobuf__ServiceDiscoveryRequest **request) {
  libnngio_protobuf_error_code rv;

  uint8_t *buffer = calloc(LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE, sizeof(uint8_t));
  size_t len = LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE;
  NngioProtobuf__NngioMessage *nngio_msg = NULL;
  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_REQUEST",
                 __FILE__, __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  ctx->transport_rv = libnngio_context_recv(ctx->ctx, buffer, &len);
  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_REQUEST",
                 __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to receive service discovery request message: %s",
                 nng_strerror(ctx->transport_rv));
    free(buffer);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }

  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_REQUEST",
               __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
               "Received service discovery request message of size %zu bytes.",
               len);

  nngio_msg = nngio_protobuf__nngio_message__unpack(NULL, len, buffer);
  free(buffer);
  if (nngio_msg == NULL) {
    libnngio_log(
        "ERR", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_REQUEST", __FILE__,
        __LINE__, libnngio_context_id(ctx->ctx),
        "Failed to unpack received service discovery request message.");
    rv = LIBNNGIO_PROTOBUF_ERR_DESERIALIZATION_FAILED;
    return rv;
  }

  if (nngio_msg->msg_case !=
      NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_REQUEST) {
    libnngio_log(
        "ERR", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_REQUEST", __FILE__,
        __LINE__, libnngio_context_id(ctx->ctx),
        "Received message is not a service discovery request (msg_case=%s).",
        libnngio_protobuf_nngio_msg_case_str(nngio_msg->msg_case));
    nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_REQUEST",
               __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
               "Unpacked service discovery request message successfully.");
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_REQUEST",
               __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
               "Service Discovery Request details: UUID='%s'.",
               nngio_msg->uuid);

  // Copy the received message to the user-provided structure
  *request = malloc(sizeof(NngioProtobuf__ServiceDiscoveryRequest));
  nngio_protobuf__service_discovery_request__init(*request);

  nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
  libnngio_log("INF", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_REQUEST",
               __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
               "Successfully received service discovery request message.");
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

static void recv_service_discovery_request_async_cb(libnngio_context *ctx,
                                                    int result, void *data,
                                                    size_t len, void *arg) {
  recv_async_cb_data *cb_data = (recv_async_cb_data *)arg;
  libnngio_protobuf_error_code rv = LIBNNGIO_PROTOBUF_ERR_NONE;
  // Note: data is a pointer to the received buffer, len is its length
  // Unpack the NngioMessage from the received buffer
  NngioProtobuf__NngioMessage *nngio_msg = NULL;
  NngioProtobuf__ServiceDiscoveryRequest **rpc_req =
      (NngioProtobuf__ServiceDiscoveryRequest **)cb_data->msg;
  if (result != 0) {
    libnngio_log("ERR", "RECV_SERVICE_DISCOVERY_REQUEST_ASYNC_CB", __FILE__,
                 __LINE__, libnngio_context_id(ctx),
                 "Asynchronous receive failed: %s", nng_strerror(result));
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
  } else {
    libnngio_log("INF", "RECV_SERVICE_DISCOVERY_REQUEST_ASYNC_CB", __FILE__,
                 __LINE__, libnngio_context_id(ctx),
                 "Asynchronous receive completed successfully.");
  }

  nngio_msg = nngio_protobuf__nngio_message__unpack(NULL, len, data);
  if (nngio_msg == NULL) {
    libnngio_log("ERR", "RECV_SERVICE_DISCOVERY_REQUEST_ASYNC_CB", __FILE__,
                 __LINE__, libnngio_context_id(ctx),
                 "Failed to unpack NngioMessage from received buffer.");
    rv = LIBNNGIO_PROTOBUF_ERR_DESERIALIZATION_FAILED;
  } else if (nngio_msg->msg_case !=
             NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_REQUEST) {
    libnngio_log("ERR", "RECV_SERVICE_DISCOVERY_REQUEST_ASYNC_CB", __FILE__,
                 __LINE__, libnngio_context_id(ctx),
                 "Received message is not a RPC Request (msg_case=%d).",
                 nngio_msg->msg_case);
    nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
  } else {
    libnngio_log("DBG", "RECV_SERVICE_DISCOVERY_REQUEST_ASYNC_CB", __FILE__,
                 __LINE__, libnngio_context_id(ctx),
                 "Received message (%s) of size %zu bytes.", nngio_msg->uuid,
                 len);
  }

  libnngio_log(
      "INF", "RECV_SERVICE_DISCOVERY_REQUEST_ASYNC_CB", __FILE__, __LINE__,
      libnngio_context_id(ctx),
      "Asynchronous receive callback processing completed with code %d.", rv);
  libnngio_log("DBG", "RECV_SERVICE_DISCOVERY_REQUEST_ASYNC_CB", __FILE__,
               __LINE__, libnngio_context_id(ctx),
               "Received service discovery request (%s).",
               nngio_msg ? nngio_msg->uuid : "NULL");

  // update the user's message pointer if we successfully received a message
  if (rv == LIBNNGIO_PROTOBUF_ERR_NONE && nngio_msg && cb_data->msg) {
    libnngio_log("DBG", "RECV_SERVICE_DISCOVERY_REQUEST_ASYNC_CB",
                 __FILE__, __LINE__, libnngio_context_id(ctx),
                 "Updating user message pointer %p.", cb_data->msg);
    NngioProtobuf__ServiceDiscoveryRequest *req_copy =
        malloc(sizeof(NngioProtobuf__ServiceDiscoveryRequest));
    nngio_protobuf__service_discovery_request__init(req_copy);
    *(cb_data->msg) = req_copy;
  }

  // Make a copy of the message to pass to the user callback
  NngioProtobuf__NngioMessage *msg =
      nngio_msg ? nngio_copy_nngio_message(nngio_msg) : NULL;

  // Make a copy of the message to pass to the user callback
  if (cb_data->user_cb) {
    cb_data->user_cb(cb_data->ctx, result, msg ? &msg : NULL,
                     cb_data->user_data);
  }

  nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
  free(cb_data->buffer);
  free(cb_data);
}

/**
 * @brief Send an RPC request message asynchronously.
 *
 * @param ctx       Context to use for sending.
 * @param message   Pointer to the raw message to send.
 * @param cb        Callback function to invoke upon send completion.
 * @param arg       User-defined argument to pass to the callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code
libnngio_protobuf_recv_service_discovery_request_async(
    libnngio_protobuf_context *ctx,
    NngioProtobuf__ServiceDiscoveryRequest **request,
    libnngio_protobuf_recv_async_cb cb, void *user_data) {
  libnngio_protobuf_error_code rv = LIBNNGIO_PROTOBUF_ERR_NONE;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST_ASYNC", __FILE__,
                 __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (cb == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid callback function provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Prepare callback data
  recv_async_cb_data *cb_data = malloc(sizeof(recv_async_cb_data));
  if (!cb_data) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for callback data.");
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }
  cb_data->buffer = calloc(LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE, sizeof(uint8_t));
  cb_data->len = LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE;
  cb_data->user_cb = cb;
  cb_data->ctx = ctx;
  cb_data->user_data = user_data;
  cb_data->msg =
      (void **)request;  // Note: message will be updated in the callback

  // Receive the serialized buffer asynchronously using the underlying libnngio
  // context
  ctx->transport_rv = libnngio_context_recv_async(
      ctx->ctx, cb_data->buffer, &cb_data->len,
      recv_service_discovery_request_async_cb, cb_data);
  if (ctx->transport_rv != 0) {
    libnngio_log(
        "ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST_ASYNC", __FILE__, __LINE__,
        libnngio_context_id(ctx->ctx),
        "Failed to receive service discovery request asynchronously: %s",
        nng_strerror(ctx->transport_rv));
    free(cb_data);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }

  libnngio_log("INF", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST_ASYNC", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Successfully initiated async receive of service discovery "
               "request message.");

  // Note: The actual message will be processed by the callback function.
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
  libnngio_protobuf_error_code rv;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_RESPONSE",
                 __FILE__, __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (response == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_RESPONSE",
                 __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid service discovery response message provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Wrap the ServiceDiscoveryResponse in a NngioMessage
  NngioProtobuf__NngioMessage *nngio_msg =
      malloc(sizeof(NngioProtobuf__NngioMessage));
  nngio_protobuf__nngio_message__init(nngio_msg);
  nngio_msg->uuid = libnngio_protobuf_gen_uuid();
  nngio_msg->msg_case =
      NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_RESPONSE;
  nngio_msg->service_discovery_response =
      nngio_copy_service_discovery_response(response);

  // Serialize the NngioMessage to a buffer
  size_t packed_size =
      nngio_protobuf__nngio_message__get_packed_size(nngio_msg);
  uint8_t *buffer = malloc(packed_size);
  if (buffer == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_RESPONSE",
                 __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  nngio_protobuf__nngio_message__pack(nngio_msg, buffer);
  libnngio_log(
      "DBG", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_RESPONSE", __FILE__,
      __LINE__, libnngio_context_id(ctx->ctx),
      "Serialized service discovery response message (%s) of size %zu bytes.",
      nngio_msg->uuid, packed_size);

  // Send the serialized buffer using the underlying libnngio context
  ctx->transport_rv = libnngio_context_send(ctx->ctx, buffer, packed_size);
  nngio_free_nngio_message(nngio_msg);
  free(buffer);

  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_RESPONSE",
                 __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to send service discovery response message: %s",
                 nng_strerror(ctx->transport_rv));
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }
  libnngio_log("INF", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_RESPONSE",
               __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
               "Successfully sent service discovery response message.");
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

static void send_service_discovery_response_async_cb(libnngio_context *ctx,
                                                     int result, void *data,
                                                     size_t len, void *arg) {
  send_async_cb_data *cb_data = (send_async_cb_data *)arg;
  libnngio_protobuf_error_code rv;
  if (result != 0) {
    libnngio_log("ERR", "SEND_SERVICE_DISCOVERY_RESPONSE_ASYNC_CB", __FILE__,
                 __LINE__, libnngio_context_id(ctx),
                 "Asynchronous send failed: %s", nng_strerror(result));
  } else {
    libnngio_log("INF", "SEND_SERVICE_DISCOVERY_RESPONSE_ASYNC_CB", __FILE__,
                 __LINE__, libnngio_context_id(ctx),
                 "Asynchronous send completed successfully.");
  }

  libnngio_log("DBG", "SEND_SERVICE_DISCOVERY_RESPONSE_ASYNC_CB", __FILE__,
               __LINE__, libnngio_context_id(ctx),
               "Invoking user callback with user data %p.", cb_data->user_data);

  libnngio_log("DBG", "SEND_SERVICE_DISCOVERY_RESPONSE_ASYNC_CB", __FILE__,
               __LINE__, libnngio_context_id(ctx), "msg pointer: %p.",
               *(cb_data->msg));

  // Make a copy of the message to pass to the user callback
  // Invoke the user callback
  if (cb_data->user_cb) {
    cb_data->user_cb(cb_data->ctx, result, cb_data->msg, cb_data->user_data);
  }
  free(cb_data->buffer);
  free(cb_data);
}

/**
 * @brief Send an RPC response message asynchronously.
 *
 * @param ctx       Context to use for sending.
 * @param message   Pointer to the raw message to send.
 * @param cb        Callback function to invoke upon send completion.
 * @param arg       User-defined argument to pass to the callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code
libnngio_protobuf_send_service_discovery_response_async(
    libnngio_protobuf_context *ctx,
    const NngioProtobuf__ServiceDiscoveryResponse *response,
    libnngio_protobuf_send_async_cb cb, void *user_data) {
  libnngio_protobuf_error_code rv;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR",
                 "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_RESPONSE_ASYNC",
                 __FILE__, __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (response == NULL) {
    libnngio_log("ERR",
                 "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_RESPONSE_ASYNC",
                 __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid service discovery response provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  if (cb == NULL) {
    libnngio_log("ERR",
                 "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_RESPONSE_ASYNC",
                 __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid callback function provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Wrap the RawMessage in a NngioMessage
  NngioProtobuf__NngioMessage *nngio_msg =
      malloc(sizeof(NngioProtobuf__NngioMessage));
  nngio_protobuf__nngio_message__init(nngio_msg);
  nngio_msg->uuid = libnngio_protobuf_gen_uuid();
  nngio_msg->msg_case =
      NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_RESPONSE;
  nngio_msg->service_discovery_response =
      nngio_copy_service_discovery_response(response);

  // Prepare callback data
  // Note: cb_data->msg will be freed in the callback after user_cb is invoked
  // it will also copy the message before passing to user_cb
  send_async_cb_data *cb_data = malloc(sizeof(send_async_cb_data));
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_RESPONSE_ASYNC",
               __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
               "Prepared callback data structure at %p.", cb_data);

  cb_data->user_cb = cb;
  cb_data->ctx = ctx;
  cb_data->user_data = user_data;
  cb_data->msg = nngio_msg;
  cb_data->len = nngio_protobuf__nngio_message__get_packed_size(nngio_msg);
  cb_data->buffer = malloc(cb_data->len);

  if (!cb_data) {
    libnngio_log("ERR",
                 "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_RESPONSE_ASYNC",
                 __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for callback data.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  // Serialize the NngioMessage into the callback buffer
  if (cb_data->buffer == NULL) {
    libnngio_log("ERR",
                 "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_RESPONSE_ASYNC",
                 __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  nngio_protobuf__nngio_message__pack(cb_data->msg, cb_data->buffer);
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_RESPONSE_ASYNC",
               __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
               "Serialized service discovery response (%s) of size %zu bytes.",
               nngio_msg->uuid, cb_data->len);

  // Send the serialized buffer asynchronously using the underlying libnngio
  // context
  ctx->transport_rv = libnngio_context_send_async(
      ctx->ctx, cb_data->buffer, cb_data->len,
      send_service_discovery_response_async_cb, cb_data);

  if (ctx->transport_rv != 0) {
    libnngio_log("ERR",
                 "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_RESPONSE_ASYNC",
                 __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to send service discovery response asynchronously: %s",
                 nng_strerror(ctx->transport_rv));
    free(cb_data);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }
  libnngio_log(
      "INF", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_RESPONSE_ASYNC",
      __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
      "Successfully initiated async send of service discovery response.");
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Receive a service discovery response message.
 *
 * @param ctx       Context to use for receiving.
 * @param response  Pointer to receive allocated service discovery response
 * message.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_recv_service_discovery_response(
    libnngio_protobuf_context *ctx,
    NngioProtobuf__ServiceDiscoveryResponse **response) {
  libnngio_protobuf_error_code rv;
  uint8_t *buffer = calloc(LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE, sizeof(uint8_t));
  size_t len = LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE;
  NngioProtobuf__NngioMessage *nngio_msg = NULL;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_RESPONSE",
                 __FILE__, __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  ctx->transport_rv = libnngio_context_recv(ctx->ctx, buffer, &len);
  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_RESPONSE",
                 __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to receive service discovery response message: %s",
                 nng_strerror(ctx->transport_rv));
    free(buffer);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }

  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_RESPONSE",
               __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
               "Received service discovery response message of size %zu bytes.",
               len);
  nngio_msg = nngio_protobuf__nngio_message__unpack(NULL, len, buffer);
  free(buffer);

  if (nngio_msg == NULL) {
    libnngio_log(
        "ERR", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_RESPONSE", __FILE__,
        __LINE__, libnngio_context_id(ctx->ctx),
        "Failed to unpack received service discovery response message.");
    rv = LIBNNGIO_PROTOBUF_ERR_DESERIALIZATION_FAILED;
    return rv;
  }

  if (nngio_msg->msg_case !=
      NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_RESPONSE) {
    libnngio_log(
        "ERR", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_RESPONSE", __FILE__,
        __LINE__, libnngio_context_id(ctx->ctx),
        "Received message is not a service discovery response (msg_case=%s).",
        libnngio_protobuf_nngio_msg_case_str(nngio_msg->msg_case));
    nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_RESPONSE",
               __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
               "Unpacked service discovery response message successfully.");
  libnngio_log(
      "DBG", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_RESPONSE", __FILE__,
      __LINE__, libnngio_context_id(ctx->ctx),
      "Service Discovery Response details: UUID='%s', Services count=%zu.",
      nngio_msg->uuid, nngio_msg->service_discovery_response->n_services);

  // Copy the received message to the user-provided structure
  (*response) = nngio_copy_service_discovery_response(
      nngio_msg->service_discovery_response);

  nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
  libnngio_log("INF", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_RESPONSE",
               __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
               "Successfully received service discovery response message.");
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

static void recv_service_discovery_response_async_cb(libnngio_context *ctx,
                                                     int result, void *data,
                                                     size_t len, void *arg) {
  recv_async_cb_data *cb_data = (recv_async_cb_data *)arg;
  libnngio_protobuf_error_code rv = LIBNNGIO_PROTOBUF_ERR_NONE;
  // Note: data is a pointer to the received buffer, len is its length
  // Unpack the NngioMessage from the received buffer
  NngioProtobuf__NngioMessage *nngio_msg = NULL;
  NngioProtobuf__ServiceDiscoveryResponse **rpc_req =
      (NngioProtobuf__ServiceDiscoveryResponse **)cb_data->msg;
  if (result != 0) {
    libnngio_log("ERR", "RECV_SERVICE_DISCOVERY_RESPONSE_ASYNC_CB", __FILE__,
                 __LINE__, libnngio_context_id(ctx),
                 "Asynchronous receive failed: %s", nng_strerror(result));
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
  } else {
    libnngio_log("INF", "RECV_SERVICE_DISCOVERY_RESPONSE_ASYNC_CB", __FILE__,
                 __LINE__, libnngio_context_id(ctx),
                 "Asynchronous receive completed successfully.");
  }

  nngio_msg = nngio_protobuf__nngio_message__unpack(NULL, len, data);
  if (nngio_msg == NULL) {
    libnngio_log("ERR", "RECV_SERVICE_DISCOVERY_RESPONSE_ASYNC_CB", __FILE__,
                 __LINE__, libnngio_context_id(ctx),
                 "Failed to unpack NngioMessage from received buffer.");
    rv = LIBNNGIO_PROTOBUF_ERR_DESERIALIZATION_FAILED;
  } else if (nngio_msg->msg_case !=
             NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_RESPONSE) {
    libnngio_log("ERR", "RECV_SERVICE_DISCOVERY_RESPONSE_ASYNC_CB", __FILE__,
                 __LINE__, libnngio_context_id(ctx),
                 "Received message is not a RPC Response (msg_case=%d).",
                 nngio_msg->msg_case);
    nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
  } else {
    libnngio_log("DBG", "RECV_SERVICE_DISCOVERY_RESPONSE_ASYNC_CB", __FILE__,
                 __LINE__, libnngio_context_id(ctx),
                 "Received message (%s) of size %zu bytes.", nngio_msg->uuid,
                 len);
  }

  libnngio_log(
      "INF", "RECV_SERVICE_DISCOVERY_RESPONSE_ASYNC_CB", __FILE__, __LINE__,
      libnngio_context_id(ctx),
      "Asynchronous receive callback processing completed with code %d.", rv);
  libnngio_log("DBG", "RECV_SERVICE_DISCOVERY_RESPONSE_ASYNC_CB", __FILE__,
               __LINE__, libnngio_context_id(ctx),
               "Received service discovery response (%s).",
               nngio_msg ? nngio_msg->uuid : "NULL");

  // update the user's message pointer if we successfully received a message
  if (rv == LIBNNGIO_PROTOBUF_ERR_NONE && nngio_msg && cb_data->msg) {
    *(cb_data->msg) = nngio_copy_service_discovery_response(
        nngio_msg->service_discovery_response);
  }

  // Make a copy of the message to pass to the user callback
  NngioProtobuf__NngioMessage *msg =
      nngio_msg ? nngio_copy_nngio_message(nngio_msg) : NULL;

  // Make a copy of the message to pass to the user callback
  if (cb_data->user_cb) {
    cb_data->user_cb(cb_data->ctx, result, msg ? &msg : NULL,
                     cb_data->user_data);
  }

  nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
  free(cb_data->buffer);
  free(cb_data);
}

/**
 * @brief Send an RPC request message asynchronously.
 *
 * @param ctx       Context to use for sending.
 * @param message   Pointer to the raw message to send.
 * @param cb        Callback function to invoke upon send completion.
 * @param arg       User-defined argument to pass to the callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code
libnngio_protobuf_recv_service_discovery_response_async(
    libnngio_protobuf_context *ctx,
    NngioProtobuf__ServiceDiscoveryResponse **response,
    libnngio_protobuf_recv_async_cb cb, void *user_data) {
  libnngio_protobuf_error_code rv = LIBNNGIO_PROTOBUF_ERR_NONE;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_RESPONSE_ASYNC", __FILE__,
                 __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (cb == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_RESPONSE_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid callback function provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Prepare callback data
  recv_async_cb_data *cb_data = malloc(sizeof(recv_async_cb_data));
  if (!cb_data) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_RESPONSE_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for callback data.");
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }
  cb_data->buffer = calloc(LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE, sizeof(uint8_t));
  cb_data->len = LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE;
  cb_data->user_cb = cb;
  cb_data->ctx = ctx;
  cb_data->user_data = user_data;
  cb_data->msg =
      (void **)response;  // Note: message will be updated in the callback

  // Receive the serialized buffer asynchronously using the underlying libnngio
  // context
  ctx->transport_rv = libnngio_context_recv_async(
      ctx->ctx, cb_data->buffer, &cb_data->len,
      recv_service_discovery_response_async_cb, cb_data);
  if (ctx->transport_rv != 0) {
    libnngio_log(
        "ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_RESPONSE_ASYNC", __FILE__, __LINE__,
        libnngio_context_id(ctx->ctx),
        "Failed to receive service discovery response asynchronously: %s",
        nng_strerror(ctx->transport_rv));
    free(cb_data);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }

  libnngio_log("INF", "LIBNNGIO_PROTOBUF_RECV_RPC_RESPONSE_ASYNC", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Successfully initiated async receive of service discovery "
               "response message.");

  // Note: The actual message will be processed by the callback function.
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Send a generic NngioMessage.
 *
 * @param ctx       Context to use for sending.
 * @param message   Pointer to the NngioMessage to send.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_send(
    libnngio_protobuf_context *ctx, const NngioProtobuf__NngioMessage *message) {
  libnngio_protobuf_error_code rv;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND", __FILE__, __LINE__, -1,
                 "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (message == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND", __FILE__, __LINE__,
                 libnngio_context_id(ctx->ctx),
                 "Invalid NngioMessage provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Serialize the NngioMessage to a buffer
  size_t packed_size =
      nngio_protobuf__nngio_message__get_packed_size(message);
  uint8_t *buffer = malloc(packed_size);
  if (buffer == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND", __FILE__, __LINE__,
                 libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  nngio_protobuf__nngio_message__pack(message, buffer);
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Serialized NngioMessage (%s) of size %zu bytes.", message->uuid,
               packed_size);

  // Send the serialized buffer using the underlying libnngio context
  ctx->transport_rv = libnngio_context_send(ctx->ctx, buffer, packed_size);
  free(buffer);

  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND", __FILE__, __LINE__,
                 libnngio_context_id(ctx->ctx),
                 "Failed to send NngioMessage: %s",
                 nng_strerror(ctx->transport_rv));
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }
  libnngio_log("INF", "LIBNNGIO_PROTOBUF_SEND", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Successfully sent NngioMessage.");
  return LIBNNGIO_PROTOBUF_ERR_NONE;
} 

static void send_async_cb(libnngio_context *ctx, int result, void *data,
                          size_t len, void *arg) {
  send_async_cb_data *cb_data = (send_async_cb_data *)arg;
  if (result != 0) {
    libnngio_log("ERR", "SEND_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Asynchronous send failed: %s", nng_strerror(result));
  } else {
    libnngio_log("INF", "SEND_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Asynchronous send completed successfully.");
  }

  libnngio_log("DBG", "SEND_ASYNC_CB", __FILE__, __LINE__,
               libnngio_context_id(ctx),
               "Invoking user callback with user data %p.", cb_data->user_data);

  libnngio_log("DBG", "SEND_ASYNC_CB", __FILE__, __LINE__,
               libnngio_context_id(ctx), "msg pointer: %p.",
               *(cb_data->msg));

  // Make a copy of the message to pass to the user callback
  // Invoke the user callback
  if (cb_data->user_cb) {
    cb_data->user_cb(cb_data->ctx, result, cb_data->msg, cb_data->user_data);
  }
  free(cb_data->buffer);
  free(cb_data);
}

/**
 * @brief Send a generic NngioMessage asynchronously.
 *
 * @param ctx       Context to use for sending.
 * @param message   Pointer to the NngioMessage to send.
 * @param cb        Callback function to invoke upon send completion.
 * @param arg       User-defined argument to pass to the callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_send_async(
    libnngio_protobuf_context *ctx, const NngioProtobuf__NngioMessage *message,
    libnngio_protobuf_send_async_cb cb, void *user_data) {
  libnngio_protobuf_error_code rv;
  
  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_ASYNC", __FILE__, __LINE__,
                 -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (message == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_ASYNC", __FILE__, __LINE__,
                 libnngio_context_id(ctx->ctx),
                 "Invalid NngioMessage provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  if (cb == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_ASYNC", __FILE__, __LINE__,
                 libnngio_context_id(ctx->ctx),
                 "Invalid callback function provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Prepare callback data
  // Note: cb_data->msg will be freed in the callback after user_cb is invoked
  // it will also copy the message before passing to user_cb
  send_async_cb_data *cb_data = malloc(sizeof(send_async_cb_data));
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_ASYNC", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Prepared callback data structure at %p.", cb_data);

  cb_data->user_cb = cb;
  cb_data->ctx = ctx;
  cb_data->user_data = user_data;
  cb_data->msg = (NngioProtobuf__NngioMessage *)message;
  cb_data->len = nngio_protobuf__nngio_message__get_packed_size(message);
  cb_data->buffer = malloc(cb_data->len);

  if (!cb_data) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_ASYNC", __FILE__, __LINE__,
                 libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for callback data.");
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  // Serialize the NngioMessage into the callback buffer
  if (cb_data->buffer == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_ASYNC", __FILE__, __LINE__,
                 libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  nngio_protobuf__nngio_message__pack(cb_data->msg, cb_data->buffer);
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_ASYNC", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Serialized NngioMessage (%s) of size %zu bytes.",
               message->uuid, cb_data->len);

  // Send the serialized buffer asynchronously using the underlying libnngio
  // context
  ctx->transport_rv = libnngio_context_send_async(
      ctx->ctx, cb_data->buffer, cb_data->len, send_async_cb, cb_data);

  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_ASYNC", __FILE__, __LINE__,
                 libnngio_context_id(ctx->ctx),
                 "Failed to send NngioMessage asynchronously: %s",
                 nng_strerror(ctx->transport_rv));
    free(cb_data);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }
  libnngio_log("INF", "LIBNNGIO_PROTOBUF_SEND_ASYNC", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Successfully initiated async send of NngioMessage.");
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Receive a generic NngioMessage.
 *
 * @param ctx       Context to use for receiving.
 * @param message   Pointer to receive allocated NngioMessage.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_recv(
    libnngio_protobuf_context *ctx, NngioProtobuf__NngioMessage **message) {
  libnngio_protobuf_error_code rv;
  uint8_t *buffer = calloc(LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE, sizeof(uint8_t));
  size_t len = LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE;
  NngioProtobuf__NngioMessage *nngio_msg = NULL;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV", __FILE__, __LINE__, -1,
                 "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  ctx->transport_rv = libnngio_context_recv(ctx->ctx, buffer, &len);
  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV", __FILE__, __LINE__,
                 libnngio_context_id(ctx->ctx),
                 "Failed to receive NngioMessage: %s",
                 nng_strerror(ctx->transport_rv));
    free(buffer);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }

  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Received NngioMessage of size %zu bytes.", len);
  nngio_msg = nngio_protobuf__nngio_message__unpack(NULL, len, buffer);
  free(buffer);

  if (nngio_msg == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV", __FILE__, __LINE__,
                 libnngio_context_id(ctx->ctx),
                 "Failed to unpack received NngioMessage.");
    rv = LIBNNGIO_PROTOBUF_ERR_DESERIALIZATION_FAILED;
    return rv;
  }

  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Unpacked NngioMessage successfully.");
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "NngioMessage details: UUID='%s', msg_case=%s.", nngio_msg->uuid,
               libnngio_protobuf_nngio_msg_case_str(nngio_msg->msg_case));

  // Copy the received message to the user-provided structure
  (*message) = nngio_copy_nngio_message(nngio_msg);

  nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
  libnngio_log("INF", "LIBNNGIO_PROTOBUF_RECV", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Successfully received NngioMessage.");

  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

static void recv_async_cb(libnngio_context *ctx, int result, void *data,
                          size_t len, void *arg) {
  recv_async_cb_data *cb_data = (recv_async_cb_data *)arg;
  libnngio_protobuf_error_code rv = LIBNNGIO_PROTOBUF_ERR_NONE;
  // Note: data is a pointer to the received buffer, len is its length
  // Unpack the NngioMessage from the received buffer
  NngioProtobuf__NngioMessage *nngio_msg = NULL;
  NngioProtobuf__NngioMessage **msg = (NngioProtobuf__NngioMessage **)&nngio_msg;

  if (result != 0) {
    libnngio_log("ERR", "RECV_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Asynchronous receive failed: %s", nng_strerror(result));
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
  } else {
    libnngio_log("INF", "RECV_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Asynchronous receive completed successfully.");
  }

  nngio_msg = nngio_protobuf__nngio_message__unpack(NULL, len, data);
  if (nngio_msg == NULL) {
    libnngio_log("ERR", "RECV_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Failed to unpack NngioMessage from received buffer.");
    rv = LIBNNGIO_PROTOBUF_ERR_DESERIALIZATION_FAILED;
  } else {
    libnngio_log("DBG", "RECV_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Received message (%s) of size %zu bytes.", nngio_msg->uuid,
                 len);
  }

  libnngio_log("INF", "RECV_ASYNC_CB", __FILE__, __LINE__,
               libnngio_context_id(ctx),
               "Asynchronous receive callback processing completed with code %d.",
               rv);
  libnngio_log("DBG", "RECV_ASYNC_CB", __FILE__, __LINE__,
               libnngio_context_id(ctx),
               "Received NngioMessage (%s).", nngio_msg ? nngio_msg->uuid : "NULL");

  // update the user's message pointer if we successfully received a message
  if (rv == LIBNNGIO_PROTOBUF_ERR_NONE && nngio_msg && cb_data->msg) {
    libnngio_log("DBG", "RECV_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Setting user message pointer %p to received message %p\n", cb_data->msg, msg);

    (*cb_data->msg) = nngio_copy_nngio_message(*msg);
  }
  else {
    libnngio_log("DBG", "RECV_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Not setting user message pointer %p due to error or null message\n", cb_data->msg);
  }

  // Make a copy of the message to pass to the user callback
  NngioProtobuf__NngioMessage *msg_copy =
      nngio_msg ? nngio_copy_nngio_message(nngio_msg) : NULL;

  // Make a copy of the message to pass to the user callback
  if (cb_data->user_cb) {
    cb_data->user_cb(cb_data->ctx, result, msg_copy ? &msg_copy : NULL,
                     cb_data->user_data);
  }

  nngio_protobuf__nngio_message__free_unpacked(nngio_msg, NULL);
  free(cb_data->buffer);
  free(cb_data);
}

libnngio_protobuf_error_code libnngio_protobuf_recv_async(
    libnngio_protobuf_context *ctx, NngioProtobuf__NngioMessage **message,
    libnngio_protobuf_recv_async_cb cb, void *user_data) {
  libnngio_protobuf_error_code rv = LIBNNGIO_PROTOBUF_ERR_NONE;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_ASYNC", __FILE__, __LINE__,
                 -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (cb == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_ASYNC", __FILE__, __LINE__,
                 libnngio_context_id(ctx->ctx),
                 "Invalid callback function provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  if (message == NULL) {
    libnngio_log("NTC", "LIBNNGIO_PROTOBUF_RECV_ASYNC", __FILE__, __LINE__,
                 libnngio_context_id(ctx->ctx),
                 "message pointer is NULL, creating a place for the received message.");

    // Allocate memory for the message pointer if it's NULL
    message = malloc(sizeof(NngioProtobuf__NngioMessage *));
    if (message == NULL) {
      libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_ASYNC", __FILE__, __LINE__,
                   libnngio_context_id(ctx->ctx),
                   "Failed to allocate memory for message pointer.");
      rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
      return rv;
    }

    libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV_ASYNC", __FILE__, __LINE__,
                 libnngio_context_id(ctx->ctx),
                 "Allocated memory for message pointer at %p.", message);

  }

  // Prepare callback data
  recv_async_cb_data *cb_data = malloc(sizeof(recv_async_cb_data));
  if (!cb_data) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_ASYNC", __FILE__, __LINE__,
                 libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for callback data.");
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }
  cb_data->buffer = calloc(LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE, sizeof(uint8_t));
  cb_data->len = LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE;
  cb_data->user_cb = cb;
  cb_data->ctx = ctx;
  cb_data->user_data = user_data;
  cb_data->msg =
      (void **)message;  // Note: message will be updated in the callback

  // Receive the serialized buffer asynchronously using the underlying libnngio
  // context
  ctx->transport_rv = libnngio_context_recv_async(
      ctx->ctx, cb_data->buffer, &cb_data->len, recv_async_cb, cb_data);
  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_ASYNC", __FILE__, __LINE__,
                 libnngio_context_id(ctx->ctx),
                 "Failed to receive NngioMessage asynchronously: %s",
                 nng_strerror(ctx->transport_rv));
    free(cb_data);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }

  libnngio_log("INF", "LIBNNGIO_PROTOBUF_RECV_ASYNC", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Successfully initiated async receive of NngioMessage.");

  // Note: The actual message will be processed by the callback function.
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

// Service implementation functions

/**
 * @brief Initialize a libnngio_server with the given protobuf context.
 */
libnngio_protobuf_error_code libnngio_server_init(
    libnngio_server **server, libnngio_protobuf_context *proto_ctx) {
  if (server == NULL || proto_ctx == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  *server = calloc(1, sizeof(libnngio_server));
  if (*server == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_UNKNOWN;
  }

  (*server)->proto_ctx = proto_ctx;
  (*server)->services = NULL;
  (*server)->n_services = 0;
  (*server)->running = 0;

  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Free a libnngio_server and its resources.
 */
libnngio_protobuf_error_code libnngio_server_free(libnngio_server *server) {
  if (server == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  // Free registered services
  for (size_t i = 0; i < server->n_services; i++) {
    if (server->services[i].service_name) {
      free(server->services[i].service_name);
    }
    // Free methods for this service
    for (size_t j = 0; j < server->services[i].n_methods; j++) {
      if (server->services[i].methods[j].method_name) {
        free(server->services[i].methods[j].method_name);
      }
    }
    if (server->services[i].methods) {
      free(server->services[i].methods);
    }
  }
  if (server->services) {
    free(server->services);
  }

  free(server);
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Register a service with the server.
 */
libnngio_protobuf_error_code libnngio_server_register_service(
    libnngio_server *server, const char *service_name,
    const libnngio_service_method *methods, size_t n_methods) {
  if (server == NULL || service_name == NULL || methods == NULL || n_methods == 0) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  // Reallocate services array
  server->services = realloc(server->services, 
                           (server->n_services + 1) * sizeof(libnngio_service_registration));
  if (server->services == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_UNKNOWN;
  }

  libnngio_service_registration *new_service = &server->services[server->n_services];
  
  // Copy service name
  new_service->service_name = strdup(service_name);
  if (new_service->service_name == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_UNKNOWN;
  }

  // Copy methods
  new_service->methods = calloc(n_methods, sizeof(libnngio_service_method));
  if (new_service->methods == NULL) {
    free(new_service->service_name);
    return LIBNNGIO_PROTOBUF_ERR_UNKNOWN;
  }

  for (size_t i = 0; i < n_methods; i++) {
    new_service->methods[i].method_name = strdup(methods[i].method_name);
    if (new_service->methods[i].method_name == NULL) {
      // Clean up on failure
      for (size_t j = 0; j < i; j++) {
        free(new_service->methods[j].method_name);
      }
      free(new_service->methods);
      free(new_service->service_name);
      return LIBNNGIO_PROTOBUF_ERR_UNKNOWN;
    }
    new_service->methods[i].handler = methods[i].handler;
    new_service->methods[i].user_data = methods[i].user_data;
  }
  new_service->n_methods = n_methods;

  server->n_services++;
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Handle a service discovery request.
 */
static libnngio_protobuf_error_code handle_service_discovery_request(
    libnngio_server *server) {
  libnngio_protobuf_error_code rv;

  // Create service discovery response
  NngioProtobuf__Service **services = calloc(server->n_services, sizeof(NngioProtobuf__Service*));
  if (services == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_UNKNOWN;
  }

  for (size_t i = 0; i < server->n_services; i++) {
    // Create method names array
    const char **method_names = calloc(server->services[i].n_methods, sizeof(char*));
    if (method_names == NULL) {
      // Clean up previously allocated services
      for (size_t j = 0; j < i; j++) {
        nngio_free_service(services[j]);
      }
      free(services);
      return LIBNNGIO_PROTOBUF_ERR_UNKNOWN;
    }

    for (size_t j = 0; j < server->services[i].n_methods; j++) {
      method_names[j] = server->services[i].methods[j].method_name;
    }

    services[i] = nngio_create_service(server->services[i].service_name,
                                      method_names, server->services[i].n_methods);
    free(method_names);
    
    if (services[i] == NULL) {
      // Clean up on failure
      for (size_t j = 0; j < i; j++) {
        nngio_free_service(services[j]);
      }
      free(services);
      return LIBNNGIO_PROTOBUF_ERR_UNKNOWN;
    }
  }

  NngioProtobuf__ServiceDiscoveryResponse *response = 
      nngio_create_service_discovery_response(services, server->n_services);
  if (response == NULL) {
    for (size_t i = 0; i < server->n_services; i++) {
      nngio_free_service(services[i]);
    }
    free(services);
    return LIBNNGIO_PROTOBUF_ERR_UNKNOWN;
  }

  // Send response
  rv = libnngio_protobuf_send_service_discovery_response(server->proto_ctx, response);
  
  nngio_free_service_discovery_response(response);
  return rv;
}

/**
 * @brief Handle an RPC request.
 */
static libnngio_protobuf_error_code handle_rpc_request(
    libnngio_server *server, NngioProtobuf__RpcRequestMessage *request) {
  libnngio_protobuf_error_code rv;

  // Find the service and method
  libnngio_service_registration *service = NULL;
  libnngio_service_method *method = NULL;

  for (size_t i = 0; i < server->n_services; i++) {
    if (strcmp(server->services[i].service_name, request->service_name) == 0) {
      service = &server->services[i];
      break;
    }
  }

  if (service == NULL) {
    // Service not found
    NngioProtobuf__RpcResponseMessage *response = 
        nngio_create_rpc_response(NNGIO_PROTOBUF__RPC_RESPONSE_MESSAGE__STATUS__ServiceNotFound,
                                 NULL, 0, "Service not found");
    if (response == NULL) {
      return LIBNNGIO_PROTOBUF_ERR_UNKNOWN;
    }
    rv = libnngio_protobuf_send_rpc_response(server->proto_ctx, response);
    nngio_free_rpc_response(response);
    return rv;
  }

  for (size_t i = 0; i < service->n_methods; i++) {
    if (strcmp(service->methods[i].method_name, request->method_name) == 0) {
      method = &service->methods[i];
      break;
    }
  }

  if (method == NULL) {
    // Method not found
    NngioProtobuf__RpcResponseMessage *response = 
        nngio_create_rpc_response(NNGIO_PROTOBUF__RPC_RESPONSE_MESSAGE__STATUS__MethodNotFound,
                                 NULL, 0, "Method not found");
    if (response == NULL) {
      return LIBNNGIO_PROTOBUF_ERR_UNKNOWN;
    }
    rv = libnngio_protobuf_send_rpc_response(server->proto_ctx, response);
    nngio_free_rpc_response(response);
    return rv;
  }

  // Call the handler
  void *response_payload = NULL;
  size_t response_payload_len = 0;
  NngioProtobuf__RpcResponseMessage__Status status = 
      method->handler(request->service_name, request->method_name,
                     request->payload.data, request->payload.len,
                     &response_payload, &response_payload_len, method->user_data);

  // Create and send response
  NngioProtobuf__RpcResponseMessage *response = 
      nngio_create_rpc_response(status, response_payload, response_payload_len, NULL);
  if (response == NULL) {
    if (response_payload) {
      free(response_payload);
    }
    return LIBNNGIO_PROTOBUF_ERR_UNKNOWN;
  }

  rv = libnngio_protobuf_send_rpc_response(server->proto_ctx, response);
  nngio_free_rpc_response(response);
  
  if (response_payload) {
    free(response_payload);
  }

  return rv;
}

/**
 * @brief Start the server to handle incoming requests.
 */
libnngio_protobuf_error_code libnngio_server_run(libnngio_server *server) {
  if (server == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  server->running = 1;
  libnngio_protobuf_error_code rv;

  while (server->running) {
    NngioProtobuf__NngioMessage *msg = NULL;
    rv = libnngio_protobuf_recv(server->proto_ctx, &msg);
    
    if (rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
      // Handle error or timeout
      continue;
    }

    if (msg == NULL) {
      continue;
    }

    switch (msg->msg_case) {
      case NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_REQUEST:
        rv = handle_service_discovery_request(server);
        break;
      
      case NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RPC_REQUEST:
        rv = handle_rpc_request(server, msg->rpc_request);
        break;
      
      default:
        // Ignore other message types
        break;
    }

    nngio_free_nngio_message(msg);
  }

  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Stop a running server.
 */
libnngio_protobuf_error_code libnngio_server_stop(libnngio_server *server) {
  if (server == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  server->running = 0;
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Initialize a libnngio_client with the given protobuf context.
 */
libnngio_protobuf_error_code libnngio_client_init(
    libnngio_client **client, libnngio_protobuf_context *proto_ctx) {
  if (client == NULL || proto_ctx == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  *client = calloc(1, sizeof(libnngio_client));
  if (*client == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_UNKNOWN;
  }

  (*client)->proto_ctx = proto_ctx;
  (*client)->discovered_services = NULL;
  (*client)->n_discovered_services = 0;

  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Free a libnngio_client and its resources.
 */
libnngio_protobuf_error_code libnngio_client_free(libnngio_client *client) {
  if (client == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  // Free discovered services
  for (size_t i = 0; i < client->n_discovered_services; i++) {
    nngio_free_service(client->discovered_services[i]);
  }
  if (client->discovered_services) {
    free(client->discovered_services);
  }

  free(client);
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Discover services from the server.
 */
libnngio_protobuf_error_code libnngio_client_discover_services(
    libnngio_client *client) {
  if (client == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  // Create service discovery request
  NngioProtobuf__ServiceDiscoveryRequest request = NNGIO_PROTOBUF__SERVICE_DISCOVERY_REQUEST__INIT;
  
  libnngio_protobuf_error_code rv = 
      libnngio_protobuf_send_service_discovery_request(client->proto_ctx, &request);
  if (rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    return rv;
  }

  // Receive response
  NngioProtobuf__ServiceDiscoveryResponse *response = NULL;
  rv = libnngio_protobuf_recv_service_discovery_response(client->proto_ctx, &response);
  if (rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    return rv;
  }

  // Free previous discovered services
  for (size_t i = 0; i < client->n_discovered_services; i++) {
    nngio_free_service(client->discovered_services[i]);
  }
  if (client->discovered_services) {
    free(client->discovered_services);
  }

  // Store discovered services
  client->n_discovered_services = response->n_services;
  client->discovered_services = calloc(response->n_services, sizeof(NngioProtobuf__Service*));
  if (client->discovered_services == NULL && response->n_services > 0) {
    nngio_free_service_discovery_response(response);
    return LIBNNGIO_PROTOBUF_ERR_UNKNOWN;
  }

  for (size_t i = 0; i < response->n_services; i++) {
    client->discovered_services[i] = nngio_copy_service(response->services[i]);
    if (client->discovered_services[i] == NULL) {
      // Clean up on failure
      for (size_t j = 0; j < i; j++) {
        nngio_free_service(client->discovered_services[j]);
      }
      free(client->discovered_services);
      client->discovered_services = NULL;
      client->n_discovered_services = 0;
      nngio_free_service_discovery_response(response);
      return LIBNNGIO_PROTOBUF_ERR_UNKNOWN;
    }
  }

  nngio_free_service_discovery_response(response);
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Call an RPC method on the server.
 */
libnngio_protobuf_error_code libnngio_client_call_rpc(
    libnngio_client *client, const char *service_name, const char *method_name,
    const void *request_payload, size_t request_payload_len,
    void **response_payload, size_t *response_payload_len) {
  if (client == NULL || service_name == NULL || method_name == NULL ||
      response_payload == NULL || response_payload_len == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  *response_payload = NULL;
  *response_payload_len = 0;

  // Create RPC request
  NngioProtobuf__RpcRequestMessage *request = 
      nngio_create_rpc_request(service_name, method_name, request_payload, request_payload_len);
  if (request == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_UNKNOWN;
  }

  // Send request
  libnngio_protobuf_error_code rv = 
      libnngio_protobuf_send_rpc_request(client->proto_ctx, request);
  if (rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    nngio_free_rpc_request(request);
    return rv;
  }

  nngio_free_rpc_request(request);

  // Receive response
  NngioProtobuf__RpcResponseMessage *response = NULL;
  rv = libnngio_protobuf_recv_rpc_response(client->proto_ctx, &response);
  if (rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    return rv;
  }

  // Check response status
  if (response->status != NNGIO_PROTOBUF__RPC_RESPONSE_MESSAGE__STATUS__Success) {
    nngio_free_rpc_response(response);
    return LIBNNGIO_PROTOBUF_ERR_SERVICE_NOT_FOUND; // Or map other error codes
  }

  // Copy response payload
  if (response->payload.len > 0) {
    *response_payload = malloc(response->payload.len);
    if (*response_payload == NULL) {
      nngio_free_rpc_response(response);
      return LIBNNGIO_PROTOBUF_ERR_UNKNOWN;
    }
    memcpy(*response_payload, response->payload.data, response->payload.len);
    *response_payload_len = response->payload.len;
  }

  nngio_free_rpc_response(response);
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}
