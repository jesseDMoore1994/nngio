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
 *   mgmt_ctx -> ctx: is the underlying libnngio_context used for transport.
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
 * @brief Convert LibnngioProtobuf__LibnngioMessage__MsgCase to human-readable
 * string.
 *
 * @param msg_case The message case to convert.
 * @return A pointer to a static string describing the message case.
 */
char *libnngio_protobuf_nngio_msg_case_str(
    LibnngioProtobuf__LibnngioMessage__MsgCase msg_case) {
  switch (msg_case) {
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG__NOT_SET:
      return "Not set";
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_REQUEST:
      return "ServiceDiscoveryRequest";
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_RESPONSE:
      return "ServiceDiscoveryResponse";
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RPC_REQUEST:
      return "RpcRequestMessage";
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RPC_RESPONSE:
      return "RpcResponseMessage";
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RAW:
      return "RawMessage";
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_ADD_TRANSPORT_REQUEST:
      return "AddTransportRequest";
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_ADD_TRANSPORT_RESPONSE:
      return "AddTransportResponse";
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_GET_TRANSPORTS_REQUEST:
      return "GetTransportsRequest";
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_GET_TRANSPORTS_RESPONSE:
      return "GetTransportsResponse";
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_REMOVE_TRANSPORT_REQUEST:
      return "RemoveTransportRequest";
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_REMOVE_TRANSPORT_RESPONSE:
      return "RemoveTransportResponse";
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
    case LIBNNGIO_PROTOBUF_ERR_INTERNAL_ERROR:
      return "Internal server error";
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
 * @param mgmt_ctx Pointer to the context to initialize.
 * @param ctx Pointer to the underlying libnngio context to use.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_context_init(
    libnngio_protobuf_context **mgmt_ctx, libnngio_context *ctx) {
  if (mgmt_ctx == NULL || ctx == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  struct libnngio_protobuf_context *new_ctx =
      malloc(sizeof(struct libnngio_protobuf_context));

  if (new_ctx == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  new_ctx->ctx = ctx;
  *mgmt_ctx = new_ctx;
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
    libnngio_protobuf_context *mgmt_ctx) {
  if (mgmt_ctx == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_NONE;
  }
  libnngio_log(
      "DBG", "LIBNNGIO_PROTOBUF_CONTEXT_FREE", __FILE__, __LINE__,
      libnngio_context_id(mgmt_ctx->ctx),
      "Freeing libnngio_protobuf context wrapping libnngio context %d.",
      libnngio_context_id(mgmt_ctx->ctx));
  free(mgmt_ctx);
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
 * @brief Create and populate a LibnngioProtobuf__Service structure.
 *
 * Allocates and initializes a LibnngioProtobuf__Service with the given name and
 * methods. Deep-copies all strings.
 *
 * @param name Name of the service.
 * @param methods Array of method names.
 * @param n_methods Number of methods in the array.
 * @return Pointer to the allocated service, or NULL on failure.
 */
LibnngioProtobuf__Service *nngio_create_service(const char *name,
                                                const char **methods,
                                                size_t n_methods) {
  LibnngioProtobuf__Service *svc = malloc(sizeof(LibnngioProtobuf__Service));
  if (!svc) return NULL;
  libnngio_protobuf__service__init(svc);
  svc->name = strdup(name ? name : "");
  svc->n_methods = n_methods;
  svc->methods = n_methods ? malloc(sizeof(char *) * n_methods) : NULL;
  for (size_t i = 0; i < n_methods; ++i) {
    svc->methods[i] = strdup(methods[i]);
  }
  return svc;
}

/**
 * @brief Free a LibnngioProtobuf__Service structure and its contents.
 *
 * Frees memory for the name, methods array, and method strings.
 *
 * @param svc Pointer to the service to free.
 */
void nngio_free_service(LibnngioProtobuf__Service *svc) {
  if (!svc) return;
  if (svc->name) free(svc->name);
  for (size_t i = 0; i < svc->n_methods; ++i) {
    if (svc->methods[i]) free(svc->methods[i]);
  }
  free(svc->methods);
  free(svc);
}

/**
 * @brief Create and populate a LibnngioProtobuf__ServiceDiscoveryResponse
 * structure.
 *
 * Allocates and initializes a response containing the provided services.
 * Takes ownership of the service pointers.
 *
 * @param services Array of pointers to LibnngioProtobuf__Service.
 * @param n_services Number of services.
 * @return Pointer to allocated response, or NULL on failure.
 */
LibnngioProtobuf__ServiceDiscoveryResponse *
nngio_create_service_discovery_response(LibnngioProtobuf__Service **services,
                                        size_t n_services) {
  LibnngioProtobuf__ServiceDiscoveryResponse *resp =
      malloc(sizeof(LibnngioProtobuf__ServiceDiscoveryResponse));
  if (!resp) return NULL;
  libnngio_protobuf__service_discovery_response__init(resp);
  resp->n_services = n_services;
  resp->services =
      n_services ? malloc(sizeof(LibnngioProtobuf__Service *) * n_services)
                 : NULL;
  for (size_t i = 0; i < n_services; ++i) {
    resp->services[i] = services[i];
  }
  return resp;
}

/**
 * @brief Free a LibnngioProtobuf__ServiceDiscoveryResponse and its contained
 * services.
 *
 * Frees memory for the response, services array, and each service.
 *
 * @param resp Pointer to the response to free.
 */
void nngio_free_service_discovery_response(
    LibnngioProtobuf__ServiceDiscoveryResponse *resp) {
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
 * @brief Create and populate a LibnngioProtobuf__RpcRequest.
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
LibnngioProtobuf__RpcRequest *nngio_create_rpc_request(const char *service_name,
                                                       const char *method_name,
                                                       const void *payload,
                                                       size_t payload_len) {
  LibnngioProtobuf__RpcRequest *msg =
      malloc(sizeof(LibnngioProtobuf__RpcRequest));
  if (!msg) return NULL;
  libnngio_protobuf__rpc_request__init(msg);
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
 * @brief Free a LibnngioProtobuf__RpcRequest and its contents.
 *
 * Frees memory for the service name, method name, and payload.
 *
 * @param msg Pointer to the request to free.
 */
void nngio_free_rpc_request(LibnngioProtobuf__RpcRequest *msg) {
  if (!msg) return;
  if (msg->service_name) free(msg->service_name);
  if (msg->method_name) free(msg->method_name);
  if (msg->payload.data) free(msg->payload.data);
  free(msg);
}

/**
 * @brief Create and populate a LibnngioProtobuf__RpcResponse.
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
LibnngioProtobuf__RpcResponse *nngio_create_rpc_response(
    LibnngioProtobuf__RpcResponse__Status status, const void *payload,
    size_t payload_len, const char *error_message) {
  LibnngioProtobuf__RpcResponse *msg =
      malloc(sizeof(LibnngioProtobuf__RpcResponse));
  if (!msg) return NULL;
  libnngio_protobuf__rpc_response__init(msg);
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
 * @brief Free a LibnngioProtobuf__RpcResponse and its contents.
 *
 * Frees memory for the payload and error message.
 *
 * @param msg Pointer to the response to free.
 */
void nngio_free_rpc_response(LibnngioProtobuf__RpcResponse *msg) {
  if (!msg) return;
  if (msg->payload.data) free(msg->payload.data);
  if (msg->error_message) free(msg->error_message);
  free(msg);
}

/**
 * @brief Create and populate a LibnngioProtobuf__Raw.
 *
 * Allocates and initializes a raw message with the given binary data.
 * Deep-copies the data.
 *
 * @param data Pointer to binary data.
 * @param data_len Length of binary data.
 * @return Pointer to allocated raw message, or NULL on failure.
 */
LibnngioProtobuf__Raw *nngio_create_raw_message(const void *data,
                                                size_t data_len) {
  LibnngioProtobuf__Raw *msg = malloc(sizeof(LibnngioProtobuf__Raw));
  if (!msg) return NULL;
  libnngio_protobuf__raw__init(msg);
  msg->data.len = data_len;
  msg->data.data = data_len ? malloc(data_len) : NULL;
  if (data && data_len) {
    memcpy(msg->data.data, data, data_len);
  }
  return msg;
}

/**
 * @brief Free a LibnngioProtobuf__Raw and its contents.
 *
 * Frees memory for the binary data.
 *
 * @param msg Pointer to the raw message to free.
 */
void nngio_free_raw_message(LibnngioProtobuf__Raw *msg) {
  if (!msg) return;
  if (msg->data.data) free(msg->data.data);
  free(msg);
}

/**
 * @brief Create and populate a LibnngioProtobuf__Transport.
 *
 * Allocates and initializes a transport message with the given config.
 * Deep-copies strings.
 * @param config Pointer to libnngio_config containing transport settings.
 * @return Pointer to allocated transport message, or NULL on failure.
 */
LibnngioProtobuf__Transport *nngio_create_transport(libnngio_config *config) {
  if (!config) return NULL;
  LibnngioProtobuf__Transport *msg =
      malloc(sizeof(LibnngioProtobuf__Transport));
  if (!msg) return NULL;
  libnngio_protobuf__transport__init(msg);

  msg->name = config->name ? strdup(config->name) : NULL;

  switch (config->mode) {
    case LIBNNGIO_MODE_DIAL:
      msg->mode = LIBNNGIO_PROTOBUF__TRANSPORT_MODE__Dial;
      break;
    case LIBNNGIO_MODE_LISTEN:
      msg->mode = LIBNNGIO_PROTOBUF__TRANSPORT_MODE__Listen;
      break;
    default:
      assert(0 && "Invalid transport mode");
      return NULL;
  }

  switch (config->proto) {
    case LIBNNGIO_PROTO_PAIR:
      msg->proto = LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Pair;
      break;
    case LIBNNGIO_PROTO_REQ:
      msg->proto = LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Req;
      break;
    case LIBNNGIO_PROTO_REP:
      msg->proto = LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Rep;
      break;
    case LIBNNGIO_PROTO_PUB:
      msg->proto = LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Pub;
      break;
    case LIBNNGIO_PROTO_SUB:
      msg->proto = LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Sub;
      break;
    case LIBNNGIO_PROTO_PUSH:
      msg->proto = LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Push;
      break;
    case LIBNNGIO_PROTO_PULL:
      msg->proto = LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Pull;
      break;
    case LIBNNGIO_PROTO_SURVEYOR:
      msg->proto = LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Surveyor;
      break;
    case LIBNNGIO_PROTO_RESPONDENT:
      msg->proto = LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Respondent;
      break;
    case LIBNNGIO_PROTO_BUS:
      msg->proto = LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Bus;
      break;
    default:
      assert(0 && "Invalid transport protocol");
      return NULL;
  }

  msg->url = config->url ? strdup(config->url) : NULL;
  msg->tls_cert = config->tls_cert ? strdup(config->tls_cert) : NULL;
  msg->tls_key = config->tls_key ? strdup(config->tls_key) : NULL;
  msg->tls_ca_cert = config->tls_ca_cert ? strdup(config->tls_ca_cert) : NULL;
  return msg;
}

/**
 * @brief Free a LibnngioProtobuf__Transport and its contents.
 *
 * Frees memory for the strings.
 *
 * @param msg Pointer to the transport message to free.
 */
void nngio_free_transport(LibnngioProtobuf__Transport *transport) {
  if (!transport) return;
  if (transport->name) free(transport->name);
  if (transport->url) free(transport->url);
  if (transport->tls_cert) free(transport->tls_cert);
  if (transport->tls_key) free(transport->tls_key);
  if (transport->tls_ca_cert) free(transport->tls_ca_cert);
  free(transport);
}

/**
 * @brief Create and populate a LibnngioProtobuf__AddTransportRequest.
 *
 * Allocates and initializes a response containing the provided transport.
 * Takes ownership of the transport pointer.
 *
 * @param config Pointer to libnngio_config containing transport settings.
 * @return Pointer to allocated response, or NULL on failure.
 */
LibnngioProtobuf__AddTransportRequest * nngio_create_add_transport_request(
    libnngio_config *config) {
  LibnngioProtobuf__AddTransportRequest *req =
      malloc(sizeof(LibnngioProtobuf__AddTransportRequest));
  if (!req) return NULL;
  libnngio_protobuf__add_transport_request__init(req);
  req->transport = nngio_create_transport(config);
  return req;
}

/**
 * @brief Free a LibnngioProtobuf__AddTransportResponse and its contained
 * transport.
 *
 * Frees memory for the response and the transport.
 *
 * @param resp Pointer to the response to free.
 */
void nngio_free_add_transport_request(
    LibnngioProtobuf__AddTransportRequest *req) {
  if (!req) return;
  if (req->transport) {
    nngio_free_transport(req->transport);
  }
  free(req);
}

/**
 * @brief Create and populate a LibnngioProtobuf__GetTransportsResponse.
 *
 * Allocates and initializes a response containing the provided transports.
 * Takes ownership of the transport pointers.
 *
 * @param config Array of pointers to libnngio_config.
 * @param n_configs Number of transport configs.
 * @return Pointer to allocated response, or NULL on failure.
 */
LibnngioProtobuf__GetTransportsResponse *
nngio_create_get_transports_response(
    libnngio_config **configs, size_t n_configs) {
  LibnngioProtobuf__GetTransportsResponse *resp =
      malloc(sizeof(LibnngioProtobuf__GetTransportsResponse));
  if (!resp) return NULL;
  libnngio_protobuf__get_transports_response__init(resp);
  resp->n_transports = n_configs;
  resp->transports =
      n_configs ? malloc(sizeof(LibnngioProtobuf__Transport *) * n_configs)
                : NULL;
  for (size_t i = 0; i < n_configs; ++i) {
    resp->transports[i] = nngio_create_transport(configs[i]);
  }
  return resp;
}

/**
 * @brief Free a LibnngioProtobuf__GetTransportsResponse and its contained
 * transports.
 *
 * Frees memory for the response, transports array, and each transport.
 *
 * @param resp Pointer to the response to free.
 */
void nngio_free_get_transports_response(
    LibnngioProtobuf__GetTransportsResponse *resp) {
  if (!resp) return;
  if (resp->transports) {
    for (size_t i = 0; i < resp->n_transports; ++i) {
      nngio_free_transport(resp->transports[i]);
    }
    free(resp->transports);
  }
  free(resp);
}

/**
 * @brief Create and populate a LibnngioProtobuf__RemoveTransportRequest.
 * 
 * Allocates and initializes a request to remove a transport.
 *
 * @param mode Transport mode (Dial or Listen).
 * @param proto Transport protocol (Pair, Req, Rep, etc).
 * @param url Transport URL.
 * @return Pointer to allocated request, or NULL on failure.
 */
LibnngioProtobuf__RemoveTransportRequest * nngio_create_remove_transport_request(
    const char* name, libnngio_mode mode, libnngio_proto proto, const char *url) {
  LibnngioProtobuf__RemoveTransportRequest *req =
      malloc(sizeof(LibnngioProtobuf__RemoveTransportRequest));
  if (!req) return NULL;
  libnngio_protobuf__remove_transport_request__init(req);
  req->name = strdup(name ? name : "");
  return req;
}

/**
 * @brief Free a LibnngioProtobuf__RemoveTransportRequest and its contents.
 *
 * Frees memory for the URL string.
 *
 * @param req Pointer to the request to free.
 */
void nngio_free_remove_transport_request(
    LibnngioProtobuf__RemoveTransportRequest *req) {
  if (!req) return;
  if (req->name) free(req->name);
  free(req);
}

/**
 * @brief Create a LibnngioProtobuf__LibnngioMessage containing a
 * RpcRequestMessage.
 *
 * Allocates and initializes an LibnngioMessage. Takes ownership of rpc_request.
 *
 * @param uuid Unique identifier string.
 * @param rpc_request Pointer to a RpcRequestMessage.
 * @return Pointer to allocated LibnngioMessage, or NULL on failure.
 */
LibnngioProtobuf__LibnngioMessage *nngio_create_nngio_message_with_rpc_request(
    const char *uuid, LibnngioProtobuf__RpcRequest *rpc_request) {
  LibnngioProtobuf__LibnngioMessage *msg =
      malloc(sizeof(LibnngioProtobuf__LibnngioMessage));
  if (!msg) return NULL;
  libnngio_protobuf__libnngio_message__init(msg);
  msg->uuid = strdup(uuid ? uuid : "");
  msg->msg_case = LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RPC_REQUEST;
  msg->rpc_request = rpc_request;
  return msg;
}

/**
 * @brief Create a LibnngioProtobuf__LibnngioMessage containing a
 * RpcResponseMessage.
 *
 * Allocates and initializes an LibnngioMessage. Takes ownership of
 * rpc_response.
 *
 * @param uuid Unique identifier string.
 * @param rpc_response Pointer to a RpcResponseMessage.
 * @return Pointer to allocated LibnngioMessage, or NULL on failure.
 */
LibnngioProtobuf__LibnngioMessage *nngio_create_nngio_message_with_rpc_response(
    const char *uuid, LibnngioProtobuf__RpcResponse *rpc_response) {
  LibnngioProtobuf__LibnngioMessage *msg =
      malloc(sizeof(LibnngioProtobuf__LibnngioMessage));
  if (!msg) return NULL;
  libnngio_protobuf__libnngio_message__init(msg);
  msg->uuid = strdup(uuid ? uuid : "");
  msg->msg_case = LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RPC_RESPONSE;
  msg->rpc_response = rpc_response;
  return msg;
}

/**
 * @brief Create a LibnngioProtobuf__LibnngioMessage containing a
 * ServiceDiscoveryRequest.
 *
 * Allocates and initializes an LibnngioMessage. Takes ownership of req.
 *
 * @param uuid Unique identifier string.
 * @param req Pointer to a ServiceDiscoveryRequest.
 * @return Pointer to allocated LibnngioMessage, or NULL on failure.
 */
LibnngioProtobuf__LibnngioMessage *
nngio_create_nngio_message_with_service_discovery_request(
    const char *uuid, LibnngioProtobuf__ServiceDiscoveryRequest *req) {
  LibnngioProtobuf__LibnngioMessage *msg =
      malloc(sizeof(LibnngioProtobuf__LibnngioMessage));
  if (!msg) return NULL;
  libnngio_protobuf__libnngio_message__init(msg);
  msg->uuid = strdup(uuid ? uuid : "");
  msg->msg_case =
      LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_REQUEST;
  msg->service_discovery_request = req;
  return msg;
}

/**
 * @brief Create a LibnngioProtobuf__LibnngioMessage containing a
 * ServiceDiscoveryResponse.
 *
 * Allocates and initializes an LibnngioMessage. Takes ownership of resp.
 *
 * @param uuid Unique identifier string.
 * @param resp Pointer to a ServiceDiscoveryResponse.
 * @return Pointer to allocated LibnngioMessage, or NULL on failure.
 */
LibnngioProtobuf__LibnngioMessage *
nngio_create_nngio_message_with_service_discovery_response(
    const char *uuid, LibnngioProtobuf__ServiceDiscoveryResponse *resp) {
  LibnngioProtobuf__LibnngioMessage *msg =
      malloc(sizeof(LibnngioProtobuf__LibnngioMessage));
  if (!msg) return NULL;
  libnngio_protobuf__libnngio_message__init(msg);
  msg->uuid = strdup(uuid ? uuid : "");
  msg->msg_case =
      LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_RESPONSE;
  msg->service_discovery_response = resp;
  return msg;
}

/**
 * @brief Create a LibnngioProtobuf__LibnngioMessage containing a RawMessage.
 *
 * Allocates and initializes an LibnngioMessage. Takes ownership of raw_message.
 *
 * @param uuid Unique identifier string.
 * @param raw_message Pointer to a RawMessage.
 * @return Pointer to allocated LibnngioMessage, or NULL on failure.
 */
LibnngioProtobuf__LibnngioMessage *nngio_create_nngio_message_with_raw(
    const char *uuid, LibnngioProtobuf__Raw *raw_message) {
  LibnngioProtobuf__LibnngioMessage *msg =
      malloc(sizeof(LibnngioProtobuf__LibnngioMessage));
  if (!msg) return NULL;
  libnngio_protobuf__libnngio_message__init(msg);
  msg->uuid = strdup(uuid ? uuid : "");
  msg->msg_case = LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RAW;
  msg->raw = raw_message;
  return msg;
}

/**
 * @brief Create a LibnngioProtobuf__LibnngioMessage containing an
 * AddTransportRequest.
 * Allocates and initializes an LibnngioMessage. Takes ownership of req.
 * @param uuid Unique identifier string.
 * @param req Pointer to a AddTransportRequest.
 * @return Pointer to allocated LibnngioMessage, or NULL on failure.
 */
LibnngioProtobuf__LibnngioMessage *
nngio_create_nngio_message_with_add_transport_request(
    const char *uuid,
    LibnngioProtobuf__AddTransportRequest *req) {
  LibnngioProtobuf__LibnngioMessage *msg =
      malloc(sizeof(LibnngioProtobuf__LibnngioMessage));
  if (!msg) return NULL;
  libnngio_protobuf__libnngio_message__init(msg);
  msg->uuid = strdup(uuid ? uuid : "");
  msg->msg_case =
      LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_ADD_TRANSPORT_REQUEST;
  msg->add_transport_request = req;
  return msg;
}

/**
 * @brief Create a LibnngioProtobuf__LibnngioMessage containing a
 * GetTransportsResponse.
 * Allocates and initializes an LibnngioMessage. Takes ownership of resp.
 * @param uuid Unique identifier string.
 * @param resp Pointer to a TransportDiscoveryResponse.
 * @return Pointer to allocated LibnngioMessage, or NULL on failure.
 */
LibnngioProtobuf__LibnngioMessage *
nngio_create_nngio_message_with_get_transports_response(
    const char *uuid,
    LibnngioProtobuf__GetTransportsResponse *resp) {
  LibnngioProtobuf__LibnngioMessage *msg =
      malloc(sizeof(LibnngioProtobuf__LibnngioMessage));
  if (!msg) return NULL;
  libnngio_protobuf__libnngio_message__init(msg);
  msg->uuid = strdup(uuid ? uuid : "");
  msg->msg_case =
      LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_GET_TRANSPORTS_RESPONSE;
  msg->get_transports_response = resp;
  return msg;
}

/**
 * @brief Create a LibnngioProtobuf__LibnngioMessage containing a
 * RemoveTransportRequest.
 * Allocates and initializes an LibnngioMessage. Takes ownership of req.
 * @param uuid Unique identifier string.
 * @param req Pointer to a RemoveTransportRequest.
 * @return Pointer to allocated LibnngioMessage, or NULL on failure.
 */
LibnngioProtobuf__LibnngioMessage *
nngio_create_nngio_message_with_remove_transport_request(
    const char *uuid,
    LibnngioProtobuf__RemoveTransportRequest *req) {
  LibnngioProtobuf__LibnngioMessage *msg =
      malloc(sizeof(LibnngioProtobuf__LibnngioMessage));
  if (!msg) return NULL;
  libnngio_protobuf__libnngio_message__init(msg);
  msg->uuid = strdup(uuid ? uuid : "");
  msg->msg_case =
      LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_REMOVE_TRANSPORT_REQUEST;
  msg->remove_transport_request = req;
  return msg;
}

/**
 * @brief Free a LibnngioProtobuf__LibnngioMessage and all nested messages.
 *
 * Frees memory for the uuid and the contained message (depending on msg_case).
 *
 * @param msg Pointer to the LibnngioMessage to free.
 */
void nngio_free_nngio_message(LibnngioProtobuf__LibnngioMessage *msg) {
  if (!msg) return;
  if (msg->uuid) free(msg->uuid);

  switch (msg->msg_case) {
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_REQUEST:
      if (msg->service_discovery_request) {
        libnngio_protobuf__service_discovery_request__free_unpacked(
            msg->service_discovery_request, NULL);
      }
      break;
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_RESPONSE:
      if (msg->service_discovery_response) {
        nngio_free_service_discovery_response(msg->service_discovery_response);
      }
      break;
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RPC_REQUEST:
      if (msg->rpc_request) {
        nngio_free_rpc_request(msg->rpc_request);
      }
      break;
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RPC_RESPONSE:
      if (msg->rpc_response) {
        nngio_free_rpc_response(msg->rpc_response);
      }
      break;
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RAW:
      if (msg->raw) {
        nngio_free_raw_message(msg->raw);
      }
      break;
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_ADD_TRANSPORT_REQUEST:
      if (msg->add_transport_request) {
        nngio_free_add_transport_request(msg->add_transport_request);
      }
      break;
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_GET_TRANSPORTS_RESPONSE:
      if (msg->get_transports_response) {
        nngio_free_get_transports_response(
            msg->get_transports_response);
      }
      break;
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_REMOVE_TRANSPORT_REQUEST:
      if (msg->remove_transport_request) {
        nngio_free_remove_transport_request(msg->remove_transport_request);
      }
      break;
    default:
      break;
  }
  free(msg);
}

/**
 * @brief Deep copy a LibnngioProtobuf__Service structure.
 */
LibnngioProtobuf__Service *nngio_copy_service(
    const LibnngioProtobuf__Service *src) {
  if (!src) return NULL;
  return nngio_create_service(src->name, (const char **)src->methods,
                              src->n_methods);
}

/**
 * @brief Deep copy a LibnngioProtobuf__ServiceDiscoveryResponse structure.
 */
LibnngioProtobuf__ServiceDiscoveryResponse *
nngio_copy_service_discovery_response(
    const LibnngioProtobuf__ServiceDiscoveryResponse *src) {
  if (!src) return NULL;
  LibnngioProtobuf__Service **services = NULL;
  if (src->n_services) {
    services = malloc(sizeof(LibnngioProtobuf__Service *) * src->n_services);
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
  LibnngioProtobuf__ServiceDiscoveryResponse *resp =
      nngio_create_service_discovery_response(services, src->n_services);
  free(
      services);  // nngio_create_service_discovery_response copies the pointers
  return resp;
}

/**
 * @brief Deep copy a LibnngioProtobuf__RpcRequest structure.
 */
LibnngioProtobuf__RpcRequest *nngio_copy_rpc_request(
    const LibnngioProtobuf__RpcRequest *src) {
  if (!src) return NULL;
  return nngio_create_rpc_request(src->service_name, src->method_name,
                                  src->payload.data, src->payload.len);
}

/**
 * @brief Deep copy a LibnngioProtobuf__RpcResponse structure.
 */
LibnngioProtobuf__RpcResponse *nngio_copy_rpc_response(
    const LibnngioProtobuf__RpcResponse *src) {
  if (!src) return NULL;
  return nngio_create_rpc_response(src->status, src->payload.data,
                                   src->payload.len, src->error_message);
}

/**
 * @brief Deep copy a LibnngioProtobuf__Raw structure.
 */
LibnngioProtobuf__Raw *nngio_copy_raw_message(
    const LibnngioProtobuf__Raw *src) {
  if (!src) return NULL;
  libnngio_log("DBG", "NNGIO_COPY_RAW_MESSAGE", __FILE__, __LINE__, -1,
               "Copying RawMessage of size %zu bytes.", src->data.len);
  return nngio_create_raw_message(src->data.data, src->data.len);
}

static libnngio_config *libnngio_config_from_transport(
    const LibnngioProtobuf__Transport *transport) {
  libnngio_config *config = calloc(1, sizeof(libnngio_config));

  if(strcmp(transport->name, "") != 0) {
    config->name = strdup(transport->name);
  } else {
    config->name = NULL;
  }

  switch (transport->mode) {
    case LIBNNGIO_PROTOBUF__TRANSPORT_MODE__Dial:
      config->mode = LIBNNGIO_MODE_DIAL;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_MODE__Listen:
      config->mode = LIBNNGIO_MODE_LISTEN;
      break;
    default:
      assert(0 && "Invalid transport mode");
  }

  switch (transport->proto) {
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Pair:
      config->proto = LIBNNGIO_PROTO_PAIR;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Req:
      config->proto = LIBNNGIO_PROTO_REQ;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Rep:
      config->proto = LIBNNGIO_PROTO_REP;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Pub:
      config->proto = LIBNNGIO_PROTO_PUB;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Sub:
      config->proto = LIBNNGIO_PROTO_SUB;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Push:
      config->proto = LIBNNGIO_PROTO_PUSH;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Pull:
      config->proto = LIBNNGIO_PROTO_PULL;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Surveyor:
      config->proto = LIBNNGIO_PROTO_SURVEYOR;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Respondent:
      config->proto = LIBNNGIO_PROTO_RESPONDENT;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Bus:
      config->proto = LIBNNGIO_PROTO_BUS;
      break;
    default:
      assert(0 && "Invalid transport protocol");
  }

  if(strcmp(transport->url, "") != 0) {
    config->url = strdup(transport->url);
  } else {
    config->url = NULL;
  }

  if(strcmp(transport->tls_cert, "") != 0) {
    config->tls_cert = strdup(transport->tls_cert);
  } else {
    config->tls_cert = NULL;
  }

  if(strcmp(transport->tls_cert, "") != 0) {
    config->tls_key = strdup(transport->tls_key);
  } else {
    config->tls_key = NULL;
  }

  if(strcmp(transport->tls_ca_cert, "") != 0) {
    config->tls_ca_cert = strdup(transport->tls_ca_cert);
  } else {
    config->tls_ca_cert = NULL;
  }

  config->recv_timeout_ms = transport->recv_timeout_ms;
  config->send_timeout_ms = transport->send_timeout_ms;
  config->max_msg_size = transport->max_msg_size;

  return config;
}

/**
 * @brief Deep copy a LibnngioProtobuf__Transport structure.
 */
LibnngioProtobuf__Transport *nngio_copy_transport(
    const LibnngioProtobuf__Transport *src) {
  if (!src) return NULL;
  libnngio_config config;
  config.name = src->name ? strdup(src->name) : NULL;
  switch (src->mode) {
    case LIBNNGIO_PROTOBUF__TRANSPORT_MODE__Dial:
      config.mode = LIBNNGIO_MODE_DIAL;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_MODE__Listen:
      config.mode = LIBNNGIO_MODE_LISTEN;
      break;
    default:
      assert(0 && "Invalid transport mode");
      return NULL;
  }

  switch (src->proto) {
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Pair:
      config.proto = LIBNNGIO_PROTO_PAIR;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Req:
      config.proto = LIBNNGIO_PROTO_REQ;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Rep:
      config.proto = LIBNNGIO_PROTO_REP;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Pub:
      config.proto = LIBNNGIO_PROTO_PUB;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Sub:
      config.proto = LIBNNGIO_PROTO_SUB;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Push:
      config.proto = LIBNNGIO_PROTO_PUSH;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Pull:
      config.proto = LIBNNGIO_PROTO_PULL;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Surveyor:
      config.proto = LIBNNGIO_PROTO_SURVEYOR;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Respondent:
      config.proto = LIBNNGIO_PROTO_RESPONDENT;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Bus:
      config.proto = LIBNNGIO_PROTO_BUS;
      break;
    default:
      assert(0 && "Invalid transport protocol");
      return NULL;
  }

  config.url = strdup(src->url ? src->url : "");
  config.tls_cert = strdup(src->tls_cert ? src->tls_cert : "");
  config.tls_key = strdup(src->tls_key ? src->tls_key : "");
  config.tls_ca_cert = strdup(src->tls_ca_cert ? src->tls_ca_cert : "");
  return nngio_create_transport(&config);
}

/**
 * @brief Deep copy a LibnngioProtobuf__AddTransportRequest structure.
 */
LibnngioProtobuf__AddTransportRequest *nngio_copy_add_transport_request(
    const LibnngioProtobuf__AddTransportRequest *src) {
  if (!src) return NULL;
  libnngio_config config;
  src->transport->name
      ? strdup(src->transport->name)
      : NULL;
  switch (src->transport->mode) {
    case LIBNNGIO_PROTOBUF__TRANSPORT_MODE__Dial:
      config.mode = LIBNNGIO_MODE_DIAL;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_MODE__Listen:
      config.mode = LIBNNGIO_MODE_LISTEN;
      break;
    default:
      assert(0 && "Invalid transport mode");
      return NULL;
  }
  switch (src->transport->proto) {
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Pair:
      config.proto = LIBNNGIO_PROTO_PAIR;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Req:
      config.proto = LIBNNGIO_PROTO_REQ;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Rep:
      config.proto = LIBNNGIO_PROTO_REP;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Pub:
      config.proto = LIBNNGIO_PROTO_PUB;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Sub:
      config.proto = LIBNNGIO_PROTO_SUB;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Push:
      config.proto = LIBNNGIO_PROTO_PUSH;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Pull:
      config.proto = LIBNNGIO_PROTO_PULL;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Surveyor:
      config.proto = LIBNNGIO_PROTO_SURVEYOR;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Respondent:
      config.proto = LIBNNGIO_PROTO_RESPONDENT;
      break;
    case LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Bus:
      config.proto = LIBNNGIO_PROTO_BUS;
      break;
    default:
      assert(0 && "Invalid transport protocol");
      return NULL;
  }
  config.url = strdup(src->transport->url ? src->transport->url : "");
  config.tls_cert = strdup(src->transport->tls_cert ? src->transport->tls_cert : "");
  config.tls_key = strdup(src->transport->tls_key ? src->transport->tls_key : "");
  config.tls_ca_cert = strdup(src->transport->tls_ca_cert ? src->transport->tls_ca_cert : "");
  return nngio_create_add_transport_request(&config);
}

/**
 * @brief Deep copy a LibnngioProtobuf__GetTransportsResponse structure.
 */
LibnngioProtobuf__GetTransportsResponse *
nngio_copy_get_transports_response(
    const LibnngioProtobuf__GetTransportsResponse *src) {
  if (!src) return NULL;
  LibnngioProtobuf__Transport **transports = NULL;
  if (src->n_transports) {
    transports =
        malloc(sizeof(LibnngioProtobuf__Transport *) * src->n_transports);
    if (!transports) return NULL;
    for (size_t i = 0; i < src->n_transports; ++i) {
      transports[i] = nngio_copy_transport(src->transports[i]);
      if (!transports[i]) {
        // cleanup previous copies
        for (size_t j = 0; j < i; ++j) nngio_free_transport(transports[j]);
        free(transports);
        return NULL;
      }
    }
  }

  LibnngioProtobuf__GetTransportsResponse *resp = NULL;
  resp = malloc(sizeof(LibnngioProtobuf__GetTransportsResponse));
  if (!resp) {
    for (size_t i = 0; i < src->n_transports; ++i) {
      nngio_free_transport(transports[i]);
    }
    return NULL;
  }

  libnngio_protobuf__get_transports_response__init(resp);
  resp->n_transports = src->n_transports;
  resp->transports = transports;
  return resp;
}

/**
 * @brief Deep copy a LibnngioProtobuf__RemoveTransportRequest structure.
 */
LibnngioProtobuf__RemoveTransportRequest *nngio_copy_remove_transport_request(
    const LibnngioProtobuf__RemoveTransportRequest *src) {
  if (!src) return NULL;
  LibnngioProtobuf__RemoveTransportRequest *req =
      malloc(sizeof(LibnngioProtobuf__RemoveTransportRequest));
  if (!req) return NULL;
  libnngio_protobuf__remove_transport_request__init(req);
  req->name = src->name ? strdup(src->name) : NULL;
  return req;
}

/**
 * @brief Deep copy a LibnngioProtobuf__LibnngioMessage structure.
 */
LibnngioProtobuf__LibnngioMessage *nngio_copy_nngio_message(
    const LibnngioProtobuf__LibnngioMessage *src) {
  if (!src) return NULL;
  LibnngioProtobuf__LibnngioMessage *dst =
      malloc(sizeof(LibnngioProtobuf__LibnngioMessage));
  if (!dst) return NULL;
  libnngio_protobuf__libnngio_message__init(dst);
  dst->uuid = strdup(src->uuid ? src->uuid : "");
  dst->msg_case = src->msg_case;

  switch (src->msg_case) {
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_REQUEST:
      if (src->service_discovery_request) {
        dst->service_discovery_request =
            malloc(sizeof(LibnngioProtobuf__ServiceDiscoveryRequest));
        if (dst->service_discovery_request)
          libnngio_protobuf__service_discovery_request__init(
              dst->service_discovery_request);
      }
      break;
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_RESPONSE:
      dst->service_discovery_response = nngio_copy_service_discovery_response(
          src->service_discovery_response);
      break;
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RPC_REQUEST:
      dst->rpc_request = nngio_copy_rpc_request(src->rpc_request);
      break;
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RPC_RESPONSE:
      dst->rpc_response = nngio_copy_rpc_response(src->rpc_response);
      break;
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RAW:
      dst->raw = nngio_copy_raw_message(src->raw);
      break;
    case LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_GET_TRANSPORTS_RESPONSE:
      dst->get_transports_response = nngio_copy_get_transports_response(
          src->get_transports_response);
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
    libnngio_protobuf_context *ctx, const LibnngioProtobuf__Raw *message) {
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

  // Wrap the RawMessage in a LibnngioMessage
  LibnngioProtobuf__LibnngioMessage *nngio_msg =
      malloc(sizeof(LibnngioProtobuf__LibnngioMessage));
  libnngio_protobuf__libnngio_message__init(nngio_msg);
  nngio_msg->uuid = libnngio_protobuf_gen_uuid();
  nngio_msg->msg_case = LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RAW;
  nngio_msg->raw = nngio_copy_raw_message(message);

  // Serialize the LibnngioMessage to a buffer
  size_t packed_size =
      libnngio_protobuf__libnngio_message__get_packed_size(nngio_msg);
  uint8_t *buffer = malloc(packed_size);
  if (buffer == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RAW_MESSAGE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  libnngio_protobuf__libnngio_message__pack(nngio_msg, buffer);
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
  libnngio_protobuf_context *ctx;
  libnngio_server *server;
  libnngio_client *client;
  libnngio_protobuf_send_async_cb user_cb;
  libnngio_protobuf_server_send_async_cb server_cb;
  libnngio_protobuf_client_send_async_cb client_cb;
  void *user_data;
  void *buffer;
  size_t len;
  LibnngioProtobuf__LibnngioMessage *msg;
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

  // We invoke a series of callbacks in order:
  // 1. Server callback (if provided and server is set)
  // 2. Client callback (if provided and client is set)
  // 3. User callback (if provided)

  // Invoke the server callback
  if (cb_data->server_cb && cb_data->server) {
    cb_data->server_cb(cb_data->server, result, cb_data->msg,
                       cb_data->user_data);
  }
  // Invoke the client callback
  if (cb_data->client_cb && cb_data->client) {
    cb_data->client_cb(cb_data->client, result, cb_data->msg,
                       cb_data->user_data);
  }
  // Invoke the user callback
  if (cb_data->user_cb) {
    cb_data->user_cb(cb_data->ctx, result, cb_data->msg, cb_data->user_data);
  }
  nngio_free_nngio_message(cb_data->msg);
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
    libnngio_protobuf_context *ctx, const LibnngioProtobuf__Raw *message,
    libnngio_protobuf_send_cb_info cb_info) {
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

  if (cb_info.user_cb == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RAW_MESSAGE_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid callback function provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Wrap the RawMessage in a LibnngioMessage
  LibnngioProtobuf__LibnngioMessage *nngio_msg =
      malloc(sizeof(LibnngioProtobuf__LibnngioMessage));
  libnngio_protobuf__libnngio_message__init(nngio_msg);
  nngio_msg->uuid = libnngio_protobuf_gen_uuid();
  nngio_msg->msg_case = LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RAW;
  nngio_msg->raw = nngio_copy_raw_message(message);

  // Prepare callback data
  // Note: cb_data->msg will be freed in the callback after user_cb is invoked
  // it will also copy the message before passing to user_cb
  send_async_cb_data *cb_data = malloc(sizeof(send_async_cb_data));
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_RAW_MESSAGE_ASYNC", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Prepared callback data structure at %p.", cb_data);

  cb_data->user_cb = cb_info.user_cb;
  cb_data->server_cb = cb_info.server_cb;
  cb_data->client_cb = cb_info.client_cb;
  cb_data->server = cb_info.server;
  cb_data->client = cb_info.client;
  cb_data->ctx = ctx;
  cb_data->user_data = cb_info.user_data;
  cb_data->msg = nngio_msg;
  cb_data->len =
      libnngio_protobuf__libnngio_message__get_packed_size(nngio_msg);
  cb_data->buffer = malloc(cb_data->len);

  if (!cb_data) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RAW_MESSAGE_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for callback data.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  // Serialize the LibnngioMessage into the callback buffer
  if (cb_data->buffer == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RAW_MESSAGE_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  libnngio_protobuf__libnngio_message__pack(cb_data->msg, cb_data->buffer);
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
    libnngio_protobuf_context *ctx, LibnngioProtobuf__Raw **message) {
  libnngio_protobuf_error_code rv;
  uint8_t *buffer = calloc(LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE, sizeof(uint8_t));
  size_t len = LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE;
  LibnngioProtobuf__LibnngioMessage *nngio_msg = NULL;

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
  nngio_msg = libnngio_protobuf__libnngio_message__unpack(NULL, len, buffer);
  free(buffer);

  if (nngio_msg == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RAW_MESSAGE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to unpack LibnngioMessage from received buffer.");
    rv = LIBNNGIO_PROTOBUF_ERR_DESERIALIZATION_FAILED;
    return rv;
  }

  if (nngio_msg->msg_case != LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RAW) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RAW_MESSAGE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Received message is not a RawMessage (msg_case=%d).",
                 nngio_msg->msg_case);
    libnngio_protobuf__libnngio_message__free_unpacked(nngio_msg, NULL);
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Copy the received RawMessage to the provided pointer
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV_RAW_MESSAGE", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Received raw message (%s) of size %zu bytes.", nngio_msg->uuid,
               nngio_msg->raw->data.len);

  // Copy the raw message data into the provided message using deep copy helper
  // function. `nngio_copy_raw_message`.
  (*message) = nngio_copy_raw_message(nngio_msg->raw);

  libnngio_protobuf__libnngio_message__free_unpacked(nngio_msg, NULL);
  libnngio_log("INF", "LIBNNGIO_PROTOBUF_RECV_RAW_MESSAGE", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Successfully received raw message.");
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

typedef struct {
  libnngio_protobuf_context *ctx;
  libnngio_server *server;
  libnngio_client *client;
  libnngio_protobuf_recv_async_cb user_cb;
  libnngio_protobuf_server_recv_async_cb server_cb;
  libnngio_protobuf_client_recv_async_cb client_cb;
  void **msg;
  void *user_data;
  void *buffer;
  size_t len;
} recv_async_cb_data;

static void recv_raw_message_async_cb(libnngio_context *ctx, int result,
                                      void *data, size_t len, void *arg) {
  recv_async_cb_data *cb_data = (recv_async_cb_data *)arg;
  libnngio_protobuf_error_code rv = LIBNNGIO_PROTOBUF_ERR_NONE;
  // Note: data is a pointer to the received buffer, len is its length
  // Unpack the LibnngioMessage from the received buffer
  LibnngioProtobuf__LibnngioMessage *nngio_msg = NULL;
  LibnngioProtobuf__Raw **raw = (LibnngioProtobuf__Raw **)cb_data->msg;
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

  nngio_msg = libnngio_protobuf__libnngio_message__unpack(NULL, len, data);
  if (nngio_msg == NULL) {
    libnngio_log("ERR", "RECV_RAW_MESSAGE_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Failed to unpack LibnngioMessage from received buffer.");
    rv = LIBNNGIO_PROTOBUF_ERR_DESERIALIZATION_FAILED;
  } else if (nngio_msg->msg_case !=
             LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RAW) {
    libnngio_log("ERR", "RECV_RAW_MESSAGE_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Received message is not a RawMessage (msg_case=%d).",
                 nngio_msg->msg_case);
    libnngio_protobuf__libnngio_message__free_unpacked(nngio_msg, NULL);
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
               nngio_msg ? nngio_msg->raw->data.len : 0);

  // update the user's message pointer if we successfully received a message
  if (rv == LIBNNGIO_PROTOBUF_ERR_NONE && nngio_msg && cb_data->msg) {
    *(raw) = nngio_copy_raw_message(nngio_msg->raw);
  }

  // Make a copy of the message to pass to the user callback
  LibnngioProtobuf__LibnngioMessage *msg =
      nngio_msg ? nngio_copy_nngio_message(nngio_msg) : NULL;

  // We invoke a series of callbacks in order:
  // 1. Server callback (if provided and server is set)
  // 2. Client callback (if provided and client is set)
  // 3. User callback (if provided)
  //
  // Different from send, here we pass a copy of the received message
  // to each callback, the original is freed at the end of this function.
  //
  // The client and server callbacks get passed the message first, and then
  // the user callback gets invoked. If the user provides a callback, then
  // they are responsible for freeing the message passed to them.

  if (cb_data->server_cb && cb_data->server) {
    cb_data->server_cb(cb_data->server, result, msg ? &msg : NULL,
                       cb_data->user_data);
  }

  if (cb_data->client_cb && cb_data->client) {
    cb_data->client_cb(cb_data->client, result, msg ? &msg : NULL,
                       cb_data->user_data);
  }

  if (cb_data->user_cb) {
    cb_data->user_cb(cb_data->ctx, result, msg ? &msg : NULL,
                     cb_data->user_data);
  } else {
    // If no user callback, free the copied message here
    nngio_free_nngio_message(msg);
  }

  libnngio_protobuf__libnngio_message__free_unpacked(nngio_msg, NULL);
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
    libnngio_protobuf_context *ctx, LibnngioProtobuf__Raw **message,
    libnngio_protobuf_recv_cb_info cb_info) {
  libnngio_protobuf_error_code rv;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RAW_MESSAGE_ASYNC", __FILE__,
                 __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (cb_info.user_cb == NULL) {
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
  cb_data->user_cb = cb_info.user_cb;
  cb_data->server_cb = cb_info.server_cb;
  cb_data->client_cb = cb_info.client_cb;
  cb_data->ctx = ctx;
  cb_data->server = cb_info.server;
  cb_data->client = cb_info.client;
  cb_data->user_data = cb_info.user_data;
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
    const LibnngioProtobuf__RpcRequest *request) {
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

  // Wrap the RpcRequestMessage in a LibnngioMessage
  LibnngioProtobuf__LibnngioMessage *nngio_msg =
      malloc(sizeof(LibnngioProtobuf__LibnngioMessage));
  libnngio_protobuf__libnngio_message__init(nngio_msg);
  nngio_msg->uuid = libnngio_protobuf_gen_uuid();
  nngio_msg->msg_case = LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RPC_REQUEST;
  nngio_msg->rpc_request = nngio_copy_rpc_request(request);

  // Serialize the LibnngioMessage to a buffer
  size_t packed_size =
      libnngio_protobuf__libnngio_message__get_packed_size(nngio_msg);
  uint8_t *buffer = malloc(packed_size);
  if (buffer == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }
  libnngio_protobuf__libnngio_message__pack(nngio_msg, buffer);
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

  // We invoke a series of callbacks in order:
  // 1. Server callback (if provided and server is set)
  // 2. Client callback (if provided and client is set)
  // 3. User callback (if provided)

  // Invoke the server callback
  if (cb_data->server_cb && cb_data->server) {
    cb_data->server_cb(cb_data->server, result, cb_data->msg,
                       cb_data->user_data);
  }
  // Invoke the client callback
  if (cb_data->client_cb && cb_data->client) {
    cb_data->client_cb(cb_data->client, result, cb_data->msg,
                       cb_data->user_data);
  }
  // Invoke the user callback
  if (cb_data->user_cb) {
    cb_data->user_cb(cb_data->ctx, result, cb_data->msg, cb_data->user_data);
  }
  nngio_free_nngio_message(cb_data->msg);
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
    libnngio_protobuf_context *ctx, const LibnngioProtobuf__RpcRequest *request,
    libnngio_protobuf_send_cb_info cb_info) {
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

  if (cb_info.user_cb == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid callback function provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Wrap the RawMessage in a LibnngioMessage
  LibnngioProtobuf__LibnngioMessage *nngio_msg =
      malloc(sizeof(LibnngioProtobuf__LibnngioMessage));
  libnngio_protobuf__libnngio_message__init(nngio_msg);
  nngio_msg->uuid = libnngio_protobuf_gen_uuid();
  nngio_msg->msg_case = LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RPC_REQUEST;
  nngio_msg->rpc_request = nngio_copy_rpc_request(request);

  // Prepare callback data
  // Note: cb_data->msg will be freed in the callback after user_cb is invoked
  // it will also copy the message before passing to user_cb
  send_async_cb_data *cb_data = malloc(sizeof(send_async_cb_data));
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST_ASYNC", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Prepared callback data structure at %p.", cb_data);

  cb_data->user_cb = cb_info.user_cb;
  cb_data->server_cb = cb_info.server_cb;
  cb_data->client_cb = cb_info.client_cb;
  cb_data->ctx = ctx;
  cb_data->server = cb_info.server;
  cb_data->client = cb_info.client;
  cb_data->user_data = cb_info.user_data;
  cb_data->msg = nngio_msg;
  cb_data->len =
      libnngio_protobuf__libnngio_message__get_packed_size(nngio_msg);
  cb_data->buffer = malloc(cb_data->len);

  if (!cb_data) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for callback data.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  // Serialize the LibnngioMessage into the callback buffer
  if (cb_data->buffer == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  libnngio_protobuf__libnngio_message__pack(cb_data->msg, cb_data->buffer);
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_RPC_REQUEST_ASYNC", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Serialized rpc request message (%s) of size %zu bytes.",
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
    libnngio_protobuf_context *ctx, LibnngioProtobuf__RpcRequest **request) {
  libnngio_protobuf_error_code rv;
  uint8_t *buffer = calloc(LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE, sizeof(uint8_t));
  size_t len = LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE;
  LibnngioProtobuf__LibnngioMessage *nngio_msg = NULL;

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

  nngio_msg = libnngio_protobuf__libnngio_message__unpack(NULL, len, buffer);
  free(buffer);
  if (nngio_msg == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to unpack received RPC request message.");
    rv = LIBNNGIO_PROTOBUF_ERR_DESERIALIZATION_FAILED;
    return rv;
  }

  if (nngio_msg->msg_case !=
      LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RPC_REQUEST) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Received message is not an RPC request (msg_case=%s).",
                 libnngio_protobuf_nngio_msg_case_str(nngio_msg->msg_case));
    libnngio_protobuf__libnngio_message__free_unpacked(nngio_msg, NULL);
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

  libnngio_protobuf__libnngio_message__free_unpacked(nngio_msg, NULL);
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
  // Unpack the LibnngioMessage from the received buffer
  LibnngioProtobuf__LibnngioMessage *nngio_msg = NULL;
  LibnngioProtobuf__RpcRequest **rpc_req =
      (LibnngioProtobuf__RpcRequest **)cb_data->msg;
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

  nngio_msg = libnngio_protobuf__libnngio_message__unpack(NULL, len, data);
  if (nngio_msg == NULL) {
    libnngio_log("ERR", "RECV_RPC_REQUEST_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Failed to unpack LibnngioMessage from received buffer.");
    rv = LIBNNGIO_PROTOBUF_ERR_DESERIALIZATION_FAILED;
  } else if (nngio_msg->msg_case !=
             LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RPC_REQUEST) {
    libnngio_log("ERR", "RECV_RPC_REQUEST_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Received message is not a RPC Request (msg_case=%d).",
                 nngio_msg->msg_case);
    libnngio_protobuf__libnngio_message__free_unpacked(nngio_msg, NULL);
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
  LibnngioProtobuf__LibnngioMessage *msg =
      nngio_msg ? nngio_copy_nngio_message(nngio_msg) : NULL;

  // We invoke a series of callbacks in order:
  // 1. Server callback (if provided and server is set)
  // 2. Client callback (if provided and client is set)
  // 3. User callback (if provided)
  //
  // Different from send, here we pass a copy of the received message
  // to each callback, the original is freed at the end of this function.
  //
  // The client and server callbacks get passed the message first, and then
  // the user callback gets invoked. If the user provides a callback, then
  // they are responsible for freeing the message passed to them.

  if (cb_data->server_cb && cb_data->server) {
    cb_data->server_cb(cb_data->server, result, msg ? &msg : NULL,
                       cb_data->user_data);
  }

  if (cb_data->client_cb && cb_data->client) {
    cb_data->client_cb(cb_data->client, result, msg ? &msg : NULL,
                       cb_data->user_data);
  }

  if (cb_data->user_cb) {
    cb_data->user_cb(cb_data->ctx, result, msg ? &msg : NULL,
                     cb_data->user_data);
  } else {
    // If no user callback, free the copied message here
    nngio_free_nngio_message(msg);
  }

  libnngio_protobuf__libnngio_message__free_unpacked(nngio_msg, NULL);
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
    libnngio_protobuf_context *ctx, LibnngioProtobuf__RpcRequest **request,
    libnngio_protobuf_recv_cb_info cb_info) {
  libnngio_protobuf_error_code rv = LIBNNGIO_PROTOBUF_ERR_NONE;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST_ASYNC", __FILE__,
                 __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (cb_info.user_cb == NULL) {
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
  cb_data->user_cb = cb_info.user_cb;
  cb_data->server_cb = cb_info.server_cb;
  cb_data->client_cb = cb_info.client_cb;
  cb_data->ctx = ctx;
  cb_data->server = cb_info.server;
  cb_data->client = cb_info.client;
  cb_data->user_data = cb_info.user_data;
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
    const LibnngioProtobuf__RpcResponse *response) {
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

  // Wrap the RpcResponseMessage in a LibnngioMessage
  LibnngioProtobuf__LibnngioMessage *nngio_msg =
      malloc(sizeof(LibnngioProtobuf__LibnngioMessage));
  libnngio_protobuf__libnngio_message__init(nngio_msg);
  nngio_msg->uuid = libnngio_protobuf_gen_uuid();
  nngio_msg->msg_case = LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RPC_RESPONSE;
  nngio_msg->rpc_response = nngio_copy_rpc_response(response);

  // Serialize the LibnngioMessage to a buffer
  size_t packed_size =
      libnngio_protobuf__libnngio_message__get_packed_size(nngio_msg);
  uint8_t *buffer = malloc(packed_size);
  if (buffer == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_RESPONSE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  libnngio_protobuf__libnngio_message__pack(nngio_msg, buffer);
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

  // We invoke a series of callbacks in order:
  // 1. Server callback (if provided and server is set)
  // 2. Client callback (if provided and client is set)
  // 3. User callback (if provided)

  // Invoke the server callback
  if (cb_data->server_cb && cb_data->server) {
    cb_data->server_cb(cb_data->server, result, cb_data->msg,
                       cb_data->user_data);
  }
  // Invoke the client callback
  if (cb_data->client_cb && cb_data->client) {
    cb_data->client_cb(cb_data->client, result, cb_data->msg,
                       cb_data->user_data);
  }
  // Invoke the user callback
  if (cb_data->user_cb) {
    cb_data->user_cb(cb_data->ctx, result, cb_data->msg, cb_data->user_data);
  }
  nngio_free_nngio_message(cb_data->msg);
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
    const LibnngioProtobuf__RpcResponse *response,
    libnngio_protobuf_send_cb_info cb_info) {
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

  if (cb_info.user_cb == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_RESPONSE_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid callback function provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Wrap the Response in a LibnngioMessage
  LibnngioProtobuf__LibnngioMessage *nngio_msg =
      malloc(sizeof(LibnngioProtobuf__LibnngioMessage));
  libnngio_protobuf__libnngio_message__init(nngio_msg);
  nngio_msg->uuid = libnngio_protobuf_gen_uuid();
  nngio_msg->msg_case = LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RPC_RESPONSE;
  nngio_msg->rpc_response = nngio_copy_rpc_response(response);

  // Prepare callback data
  // Note: cb_data->msg will be freed in the callback after user_cb is invoked
  // it will also copy the message before passing to user_cb
  send_async_cb_data *cb_data = malloc(sizeof(send_async_cb_data));
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_RPC_RESPONSE_ASYNC", __FILE__,
               __LINE__, libnngio_context_id(ctx->ctx),
               "Prepared callback data structure at %p.", cb_data);

  cb_data->user_cb = cb_info.user_cb;
  cb_data->server_cb = cb_info.server_cb;
  cb_data->client_cb = cb_info.client_cb;
  cb_data->ctx = ctx;
  cb_data->server = cb_info.server;
  cb_data->client = cb_info.client;
  cb_data->user_data = cb_info.user_data;
  cb_data->msg = nngio_msg;
  cb_data->len =
      libnngio_protobuf__libnngio_message__get_packed_size(nngio_msg);
  cb_data->buffer = malloc(cb_data->len);

  if (!cb_data) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_RESPONSE_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for callback data.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  // Serialize the LibnngioMessage into the callback buffer
  if (cb_data->buffer == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_RPC_RESPONSE_ASYNC", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  libnngio_protobuf__libnngio_message__pack(cb_data->msg, cb_data->buffer);
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
    libnngio_protobuf_context *ctx, LibnngioProtobuf__RpcResponse **response) {
  libnngio_protobuf_error_code rv;

  uint8_t *buffer = calloc(LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE, sizeof(uint8_t));
  size_t len = LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE;
  LibnngioProtobuf__LibnngioMessage *nngio_msg = NULL;

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

  nngio_msg = libnngio_protobuf__libnngio_message__unpack(NULL, len, buffer);
  free(buffer);

  if (nngio_msg == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_RESPONSE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to unpack received RPC response message.");
    rv = LIBNNGIO_PROTOBUF_ERR_DESERIALIZATION_FAILED;
    return rv;
  }

  if (nngio_msg->msg_case !=
      LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RPC_RESPONSE) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_RESPONSE", __FILE__,
                 __LINE__, libnngio_context_id(ctx->ctx),
                 "Received message is not an RPC response (msg_case=%s).",
                 libnngio_protobuf_nngio_msg_case_str(nngio_msg->msg_case));
    libnngio_protobuf__libnngio_message__free_unpacked(nngio_msg, NULL);
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

  libnngio_protobuf__libnngio_message__free_unpacked(nngio_msg, NULL);
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
  // Unpack the LibnngioMessage from the received buffer
  LibnngioProtobuf__LibnngioMessage *nngio_msg = NULL;
  LibnngioProtobuf__RpcResponse **rpc_resp =
      (LibnngioProtobuf__RpcResponse **)cb_data->msg;
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

  nngio_msg = libnngio_protobuf__libnngio_message__unpack(NULL, len, data);
  if (nngio_msg == NULL) {
    libnngio_log("ERR", "RECV_RPC_RESPONSE_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Failed to unpack LibnngioMessage from received buffer.");
    rv = LIBNNGIO_PROTOBUF_ERR_DESERIALIZATION_FAILED;
  } else if (nngio_msg->msg_case !=
             LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RPC_RESPONSE) {
    libnngio_log("ERR", "RECV_RPC_RESPONSE_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Received message is not a RPC Response (msg_case=%d).",
                 nngio_msg->msg_case);
    libnngio_protobuf__libnngio_message__free_unpacked(nngio_msg, NULL);
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
  LibnngioProtobuf__LibnngioMessage *msg =
      nngio_msg ? nngio_copy_nngio_message(nngio_msg) : NULL;

  // We invoke a series of callbacks in order:
  // 1. Server callback (if provided and server is set)
  // 2. Client callback (if provided and client is set)
  // 3. User callback (if provided)
  //
  // Different from send, here we pass a copy of the received message
  // to each callback, the original is freed at the end of this function.
  //
  // The client and server callbacks get passed the message first, and then
  // the user callback gets invoked. If the user provides a callback, then
  // they are responsible for freeing the message passed to them.

  if (cb_data->server_cb && cb_data->server) {
    cb_data->server_cb(cb_data->server, result, msg ? &msg : NULL,
                       cb_data->user_data);
  }

  if (cb_data->client_cb && cb_data->client) {
    cb_data->client_cb(cb_data->client, result, msg ? &msg : NULL,
                       cb_data->user_data);
  }

  if (cb_data->user_cb) {
    cb_data->user_cb(cb_data->ctx, result, msg ? &msg : NULL,
                     cb_data->user_data);
  } else {
    // If no user callback, free the copied message here
    nngio_free_nngio_message(msg);
  }

  libnngio_protobuf__libnngio_message__free_unpacked(nngio_msg, NULL);
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
    libnngio_protobuf_context *ctx, LibnngioProtobuf__RpcResponse **response,
    libnngio_protobuf_recv_cb_info cb_info) {
  libnngio_protobuf_error_code rv = LIBNNGIO_PROTOBUF_ERR_NONE;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST_ASYNC", __FILE__,
                 __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (cb_info.user_cb == NULL) {
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
  cb_data->user_cb = cb_info.user_cb;
  cb_data->server_cb = cb_info.server_cb;
  cb_data->client_cb = cb_info.client_cb;
  cb_data->ctx = ctx;
  cb_data->server = cb_info.server;
  cb_data->client = cb_info.client;
  cb_data->user_data = cb_info.user_data;
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
    const LibnngioProtobuf__ServiceDiscoveryRequest *request) {
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

  // Wrap the ServiceDiscoveryRequest in a LibnngioMessage
  LibnngioProtobuf__LibnngioMessage nngio_msg =
      LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__INIT;
  nngio_msg.uuid = libnngio_protobuf_gen_uuid();
  nngio_msg.msg_case =
      LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_REQUEST;
  // copy service discovery request message into nngio_msg without assignment to
  // avoid ownership issues
  LibnngioProtobuf__ServiceDiscoveryRequest *sd_request_copy =
      malloc(sizeof(LibnngioProtobuf__ServiceDiscoveryRequest));
  libnngio_protobuf__service_discovery_request__init(sd_request_copy);
  nngio_msg.service_discovery_request = sd_request_copy;

  // Serialize the LibnngioMessage to a buffer
  size_t packed_size =
      libnngio_protobuf__libnngio_message__get_packed_size(&nngio_msg);
  uint8_t *buffer = malloc(packed_size);
  if (buffer == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_REQUEST",
                 __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    free(nngio_msg.uuid);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  libnngio_protobuf__libnngio_message__pack(&nngio_msg, buffer);
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

  // We invoke a series of callbacks in order:
  // 1. Server callback (if provided and server is set)
  // 2. Client callback (if provided and client is set)
  // 3. User callback (if provided)

  // Invoke the server callback
  if (cb_data->server_cb && cb_data->server) {
    cb_data->server_cb(cb_data->server, result, cb_data->msg,
                       cb_data->user_data);
  }
  // Invoke the client callback
  if (cb_data->client_cb && cb_data->client) {
    cb_data->client_cb(cb_data->client, result, cb_data->msg,
                       cb_data->user_data);
  }
  // Invoke the user callback
  if (cb_data->user_cb) {
    cb_data->user_cb(cb_data->ctx, result, cb_data->msg, cb_data->user_data);
  }

  nngio_free_nngio_message(cb_data->msg);
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
    const LibnngioProtobuf__ServiceDiscoveryRequest *request,
    libnngio_protobuf_send_cb_info cb_info) {
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

  if (cb_info.user_cb == NULL) {
    libnngio_log("ERR",
                 "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_REQUEST_ASYNC",
                 __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid callback function provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Wrap the RawMessage in a LibnngioMessage
  LibnngioProtobuf__LibnngioMessage *nngio_msg =
      malloc(sizeof(LibnngioProtobuf__LibnngioMessage));
  libnngio_protobuf__libnngio_message__init(nngio_msg);
  nngio_msg->uuid = libnngio_protobuf_gen_uuid();
  nngio_msg->msg_case =
      LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_REQUEST;
  LibnngioProtobuf__ServiceDiscoveryRequest *sd_request_copy =
      malloc(sizeof(LibnngioProtobuf__ServiceDiscoveryRequest));
  libnngio_protobuf__service_discovery_request__init(sd_request_copy);
  nngio_msg->service_discovery_request = sd_request_copy;

  // Prepare callback data
  // Note: cb_data->msg will be freed in the callback after user_cb is invoked
  // it will also copy the message before passing to user_cb
  send_async_cb_data *cb_data = malloc(sizeof(send_async_cb_data));
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_REQUEST_ASYNC",
               __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
               "Prepared callback data structure at %p.", cb_data);

  cb_data->user_cb = cb_info.user_cb;
  cb_data->server_cb = cb_info.server_cb;
  cb_data->client_cb = cb_info.client_cb;
  cb_data->ctx = ctx;
  cb_data->server = cb_info.server;
  cb_data->client = cb_info.client;
  cb_data->user_data = cb_info.user_data;
  cb_data->msg = nngio_msg;
  cb_data->len =
      libnngio_protobuf__libnngio_message__get_packed_size(nngio_msg);
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

  // Serialize the LibnngioMessage into the callback buffer
  if (cb_data->buffer == NULL) {
    libnngio_log("ERR",
                 "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_REQUEST_ASYNC",
                 __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  libnngio_protobuf__libnngio_message__pack(cb_data->msg, cb_data->buffer);
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
    LibnngioProtobuf__ServiceDiscoveryRequest **request) {
  libnngio_protobuf_error_code rv;

  uint8_t *buffer = calloc(LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE, sizeof(uint8_t));
  size_t len = LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE;
  LibnngioProtobuf__LibnngioMessage *nngio_msg = NULL;
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

  nngio_msg = libnngio_protobuf__libnngio_message__unpack(NULL, len, buffer);
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
      LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_REQUEST) {
    libnngio_log(
        "ERR", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_REQUEST", __FILE__,
        __LINE__, libnngio_context_id(ctx->ctx),
        "Received message is not a service discovery request (msg_case=%s).",
        libnngio_protobuf_nngio_msg_case_str(nngio_msg->msg_case));
    libnngio_protobuf__libnngio_message__free_unpacked(nngio_msg, NULL);
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
  *request = malloc(sizeof(LibnngioProtobuf__ServiceDiscoveryRequest));
  libnngio_protobuf__service_discovery_request__init(*request);

  libnngio_protobuf__libnngio_message__free_unpacked(nngio_msg, NULL);
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
  // Unpack the LibnngioMessage from the received buffer
  LibnngioProtobuf__LibnngioMessage *nngio_msg = NULL;
  LibnngioProtobuf__ServiceDiscoveryRequest **rpc_req =
      (LibnngioProtobuf__ServiceDiscoveryRequest **)cb_data->msg;
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

  nngio_msg = libnngio_protobuf__libnngio_message__unpack(NULL, len, data);
  if (nngio_msg == NULL) {
    libnngio_log("ERR", "RECV_SERVICE_DISCOVERY_REQUEST_ASYNC_CB", __FILE__,
                 __LINE__, libnngio_context_id(ctx),
                 "Failed to unpack LibnngioMessage from received buffer.");
    rv = LIBNNGIO_PROTOBUF_ERR_DESERIALIZATION_FAILED;
  } else if (
      nngio_msg->msg_case !=
      LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_REQUEST) {
    libnngio_log("ERR", "RECV_SERVICE_DISCOVERY_REQUEST_ASYNC_CB", __FILE__,
                 __LINE__, libnngio_context_id(ctx),
                 "Received message is not a RPC Request (msg_case=%d).",
                 nngio_msg->msg_case);
    libnngio_protobuf__libnngio_message__free_unpacked(nngio_msg, NULL);
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
    libnngio_log("DBG", "RECV_SERVICE_DISCOVERY_REQUEST_ASYNC_CB", __FILE__,
                 __LINE__, libnngio_context_id(ctx),
                 "Updating user message pointer %p.", cb_data->msg);
    LibnngioProtobuf__ServiceDiscoveryRequest *req_copy =
        malloc(sizeof(LibnngioProtobuf__ServiceDiscoveryRequest));
    libnngio_protobuf__service_discovery_request__init(req_copy);
    *(cb_data->msg) = req_copy;
  }

  // Make a copy of the message to pass to the user callback
  LibnngioProtobuf__LibnngioMessage *msg =
      nngio_msg ? nngio_copy_nngio_message(nngio_msg) : NULL;

  // We invoke a series of callbacks in order:
  // 1. Server callback (if provided and server is set)
  // 2. Client callback (if provided and client is set)
  // 3. User callback (if provided)
  //
  // Different from send, here we pass a copy of the received message
  // to each callback, the original is freed at the end of this function.
  //
  // The client and server callbacks get passed the message first, and then
  // the user callback gets invoked. If the user provides a callback, then
  // they are responsible for freeing the message passed to them.

  if (cb_data->server_cb && cb_data->server) {
    cb_data->server_cb(cb_data->server, result, msg ? &msg : NULL,
                       cb_data->user_data);
  }

  if (cb_data->client_cb && cb_data->client) {
    cb_data->client_cb(cb_data->client, result, msg ? &msg : NULL,
                       cb_data->user_data);
  }

  if (cb_data->user_cb) {
    cb_data->user_cb(cb_data->ctx, result, msg ? &msg : NULL,
                     cb_data->user_data);
  } else {
    // If no user callback, free the copied message here
    nngio_free_nngio_message(msg);
  }

  libnngio_protobuf__libnngio_message__free_unpacked(nngio_msg, NULL);
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
    LibnngioProtobuf__ServiceDiscoveryRequest **request,
    libnngio_protobuf_recv_cb_info cb_info) {
  libnngio_protobuf_error_code rv = LIBNNGIO_PROTOBUF_ERR_NONE;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_REQUEST_ASYNC", __FILE__,
                 __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (cb_info.user_cb == NULL) {
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
  cb_data->user_cb = cb_info.user_cb;
  cb_data->server_cb = cb_info.server_cb;
  cb_data->client_cb = cb_info.client_cb;
  cb_data->ctx = ctx;
  cb_data->server = cb_info.server;
  cb_data->client = cb_info.client;
  cb_data->user_data = cb_info.user_data;
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
    const LibnngioProtobuf__ServiceDiscoveryResponse *response) {
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

  // Wrap the ServiceDiscoveryResponse in a LibnngioMessage
  LibnngioProtobuf__LibnngioMessage *nngio_msg =
      malloc(sizeof(LibnngioProtobuf__LibnngioMessage));
  libnngio_protobuf__libnngio_message__init(nngio_msg);
  nngio_msg->uuid = libnngio_protobuf_gen_uuid();
  nngio_msg->msg_case =
      LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_RESPONSE;
  nngio_msg->service_discovery_response =
      nngio_copy_service_discovery_response(response);

  // Serialize the LibnngioMessage to a buffer
  size_t packed_size =
      libnngio_protobuf__libnngio_message__get_packed_size(nngio_msg);
  uint8_t *buffer = malloc(packed_size);
  if (buffer == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_RESPONSE",
                 __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  libnngio_protobuf__libnngio_message__pack(nngio_msg, buffer);
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
  nngio_free_nngio_message(cb_data->msg);
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
    const LibnngioProtobuf__ServiceDiscoveryResponse *response,
    libnngio_protobuf_send_cb_info cb_info) {
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

  if (cb_info.user_cb == NULL) {
    libnngio_log("ERR",
                 "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_RESPONSE_ASYNC",
                 __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
                 "Invalid callback function provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Wrap the RawMessage in a LibnngioMessage
  LibnngioProtobuf__LibnngioMessage *nngio_msg =
      malloc(sizeof(LibnngioProtobuf__LibnngioMessage));
  libnngio_protobuf__libnngio_message__init(nngio_msg);
  nngio_msg->uuid = libnngio_protobuf_gen_uuid();
  nngio_msg->msg_case =
      LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_RESPONSE;
  nngio_msg->service_discovery_response =
      nngio_copy_service_discovery_response(response);

  // Prepare callback data
  // Note: cb_data->msg will be freed in the callback after user_cb is invoked
  // it will also copy the message before passing to user_cb
  send_async_cb_data *cb_data = malloc(sizeof(send_async_cb_data));
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_RESPONSE_ASYNC",
               __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
               "Prepared callback data structure at %p.", cb_data);

  cb_data->user_cb = cb_info.user_cb;
  cb_data->server_cb = cb_info.server_cb;
  cb_data->client_cb = cb_info.client_cb;
  cb_data->ctx = ctx;
  cb_data->server = cb_info.server;
  cb_data->client = cb_info.client;
  cb_data->user_data = cb_info.user_data;
  cb_data->msg = nngio_msg;
  cb_data->len =
      libnngio_protobuf__libnngio_message__get_packed_size(nngio_msg);
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

  // Serialize the LibnngioMessage into the callback buffer
  if (cb_data->buffer == NULL) {
    libnngio_log("ERR",
                 "LIBNNGIO_PROTOBUF_SEND_SERVICE_DISCOVERY_RESPONSE_ASYNC",
                 __FILE__, __LINE__, libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    nngio_free_nngio_message(nngio_msg);
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  libnngio_protobuf__libnngio_message__pack(cb_data->msg, cb_data->buffer);
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
    LibnngioProtobuf__ServiceDiscoveryResponse **response) {
  libnngio_protobuf_error_code rv;
  uint8_t *buffer = calloc(LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE, sizeof(uint8_t));
  size_t len = LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE;
  LibnngioProtobuf__LibnngioMessage *nngio_msg = NULL;

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
  nngio_msg = libnngio_protobuf__libnngio_message__unpack(NULL, len, buffer);
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
      LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_RESPONSE) {
    libnngio_log(
        "ERR", "LIBNNGIO_PROTOBUF_RECV_SERVICE_DISCOVERY_RESPONSE", __FILE__,
        __LINE__, libnngio_context_id(ctx->ctx),
        "Received message is not a service discovery response (msg_case=%s).",
        libnngio_protobuf_nngio_msg_case_str(nngio_msg->msg_case));
    libnngio_protobuf__libnngio_message__free_unpacked(nngio_msg, NULL);
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

  libnngio_protobuf__libnngio_message__free_unpacked(nngio_msg, NULL);
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
  // Unpack the LibnngioMessage from the received buffer
  LibnngioProtobuf__LibnngioMessage *nngio_msg = NULL;
  LibnngioProtobuf__ServiceDiscoveryResponse **rpc_req =
      (LibnngioProtobuf__ServiceDiscoveryResponse **)cb_data->msg;
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

  nngio_msg = libnngio_protobuf__libnngio_message__unpack(NULL, len, data);
  if (nngio_msg == NULL) {
    libnngio_log("ERR", "RECV_SERVICE_DISCOVERY_RESPONSE_ASYNC_CB", __FILE__,
                 __LINE__, libnngio_context_id(ctx),
                 "Failed to unpack LibnngioMessage from received buffer.");
    rv = LIBNNGIO_PROTOBUF_ERR_DESERIALIZATION_FAILED;
  } else if (
      nngio_msg->msg_case !=
      LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_RESPONSE) {
    libnngio_log("ERR", "RECV_SERVICE_DISCOVERY_RESPONSE_ASYNC_CB", __FILE__,
                 __LINE__, libnngio_context_id(ctx),
                 "Received message is not a RPC Response (msg_case=%d).",
                 nngio_msg->msg_case);
    libnngio_protobuf__libnngio_message__free_unpacked(nngio_msg, NULL);
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
  LibnngioProtobuf__LibnngioMessage *msg =
      nngio_msg ? nngio_copy_nngio_message(nngio_msg) : NULL;

  // We invoke a series of callbacks in order:
  // 1. Server callback (if provided and server is set)
  // 2. Client callback (if provided and client is set)
  // 3. User callback (if provided)
  //
  // Different from send, here we pass a copy of the received message
  // to each callback, the original is freed at the end of this function.
  //
  // The client and server callbacks get passed the message first, and then
  // the user callback gets invoked. If the user provides a callback, then
  // they are responsible for freeing the message passed to them.

  if (cb_data->server_cb && cb_data->server) {
    cb_data->server_cb(cb_data->server, result, msg ? &msg : NULL,
                       cb_data->user_data);
  }

  if (cb_data->client_cb && cb_data->client) {
    cb_data->client_cb(cb_data->client, result, msg ? &msg : NULL,
                       cb_data->user_data);
  }

  if (cb_data->user_cb) {
    cb_data->user_cb(cb_data->ctx, result, msg ? &msg : NULL,
                     cb_data->user_data);
  } else {
    // If no user callback, free the copied message here
    nngio_free_nngio_message(msg);
  }

  libnngio_protobuf__libnngio_message__free_unpacked(nngio_msg, NULL);
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
    LibnngioProtobuf__ServiceDiscoveryResponse **response,
    libnngio_protobuf_recv_cb_info cb_info) {
  libnngio_protobuf_error_code rv = LIBNNGIO_PROTOBUF_ERR_NONE;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_RPC_RESPONSE_ASYNC", __FILE__,
                 __LINE__, -1, "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (cb_info.user_cb == NULL) {
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
  cb_data->user_cb = cb_info.user_cb;
  cb_data->server_cb = cb_info.server_cb;
  cb_data->client_cb = cb_info.client_cb;
  cb_data->ctx = ctx;
  cb_data->server = cb_info.server;
  cb_data->client = cb_info.client;
  cb_data->user_data = cb_info.user_data;
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
 * @brief Send a generic LibnngioMessage.
 *
 * @param ctx       Context to use for sending.
 * @param message   Pointer to the LibnngioMessage to send.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_send(
    libnngio_protobuf_context *ctx,
    const LibnngioProtobuf__LibnngioMessage *message) {
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
                 "Invalid LibnngioMessage provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  // Serialize the LibnngioMessage to a buffer
  size_t packed_size =
      libnngio_protobuf__libnngio_message__get_packed_size(message);
  uint8_t *buffer = malloc(packed_size);
  if (buffer == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND", __FILE__, __LINE__,
                 libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  libnngio_protobuf__libnngio_message__pack(message, buffer);
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Serialized LibnngioMessage (%s) of size %zu bytes.",
               message->uuid, packed_size);

  // Send the serialized buffer using the underlying libnngio context
  ctx->transport_rv = libnngio_context_send(ctx->ctx, buffer, packed_size);
  free(buffer);

  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND", __FILE__, __LINE__,
                 libnngio_context_id(ctx->ctx),
                 "Failed to send LibnngioMessage: %s",
                 nng_strerror(ctx->transport_rv));
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }
  libnngio_log("INF", "LIBNNGIO_PROTOBUF_SEND", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Successfully sent LibnngioMessage.");
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

static void send_async_cb(libnngio_context *ctx, int result, void *data,
                          size_t len, void *arg) {
  send_async_cb_data *cb_data = (send_async_cb_data *)arg;
  if (result != 0) {
    libnngio_log("ERR", "SEND_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx), "Asynchronous send failed: %s",
                 nng_strerror(result));
  } else {
    libnngio_log("INF", "SEND_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Asynchronous send completed successfully.");
  }

  libnngio_log("DBG", "SEND_ASYNC_CB", __FILE__, __LINE__,
               libnngio_context_id(ctx),
               "Invoking user callback with user data %p.", cb_data->user_data);

  libnngio_log("DBG", "SEND_ASYNC_CB", __FILE__, __LINE__,
               libnngio_context_id(ctx), "msg pointer: %p.", *(cb_data->msg));

  // We invoke a series of callbacks in order:
  // 1. Server callback (if provided and server is set)
  // 2. Client callback (if provided and client is set)
  // 3. User callback (if provided)

  // Invoke the server callback
  if (cb_data->server_cb && cb_data->server) {
    cb_data->server_cb(cb_data->server, result, cb_data->msg,
                       cb_data->user_data);
  }
  // Invoke the client callback
  if (cb_data->client_cb && cb_data->client) {
    cb_data->client_cb(cb_data->client, result, cb_data->msg,
                       cb_data->user_data);
  }
  // Invoke the user callback
  if (cb_data->user_cb) {
    cb_data->user_cb(cb_data->ctx, result, cb_data->msg, cb_data->user_data);
  }

  free(cb_data->buffer);
  free(cb_data);
}

/**
 * @brief Send a generic LibnngioMessage asynchronously.
 *
 * @param ctx       Context to use for sending.
 * @param message   Pointer to the LibnngioMessage to send.
 * @param cb        Callback function to invoke upon send completion.
 * @param arg       User-defined argument to pass to the callback.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_send_async(
    libnngio_protobuf_context *ctx,
    const LibnngioProtobuf__LibnngioMessage *message,
    libnngio_protobuf_send_cb_info cb_info) {
  libnngio_protobuf_error_code rv;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_ASYNC", __FILE__, __LINE__, -1,
                 "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (message == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_ASYNC", __FILE__, __LINE__,
                 libnngio_context_id(ctx->ctx),
                 "Invalid LibnngioMessage provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  if (cb_info.user_cb == NULL) {
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

  cb_data->user_cb = cb_info.user_cb;
  cb_data->server_cb = cb_info.server_cb;
  cb_data->client_cb = cb_info.client_cb;
  cb_data->ctx = ctx;
  cb_data->server = cb_info.server;
  cb_data->client = cb_info.client;
  cb_data->user_data = cb_info.user_data;
  cb_data->msg = (LibnngioProtobuf__LibnngioMessage *)message;
  cb_data->len = libnngio_protobuf__libnngio_message__get_packed_size(message);
  cb_data->buffer = malloc(cb_data->len);

  if (!cb_data) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_ASYNC", __FILE__, __LINE__,
                 libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for callback data.");
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  // Serialize the LibnngioMessage into the callback buffer
  if (cb_data->buffer == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_ASYNC", __FILE__, __LINE__,
                 libnngio_context_id(ctx->ctx),
                 "Failed to allocate memory for serialization buffer.");
    rv = LIBNNGIO_PROTOBUF_ERR_SERIALIZATION_FAILED;
    return rv;
  }

  libnngio_protobuf__libnngio_message__pack(cb_data->msg, cb_data->buffer);
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_SEND_ASYNC", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Serialized LibnngioMessage (%s) of size %zu bytes.",
               message->uuid, cb_data->len);

  // Send the serialized buffer asynchronously using the underlying libnngio
  // context
  ctx->transport_rv = libnngio_context_send_async(
      ctx->ctx, cb_data->buffer, cb_data->len, send_async_cb, cb_data);

  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_SEND_ASYNC", __FILE__, __LINE__,
                 libnngio_context_id(ctx->ctx),
                 "Failed to send LibnngioMessage asynchronously: %s",
                 nng_strerror(ctx->transport_rv));
    free(cb_data);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }
  libnngio_log("INF", "LIBNNGIO_PROTOBUF_SEND_ASYNC", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Successfully initiated async send of LibnngioMessage.");
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Receive a generic LibnngioMessage.
 *
 * @param ctx       Context to use for receiving.
 * @param message   Pointer to receive allocated LibnngioMessage.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_protobuf_recv(
    libnngio_protobuf_context *ctx,
    LibnngioProtobuf__LibnngioMessage **message) {
  libnngio_protobuf_error_code rv;
  uint8_t *buffer = calloc(LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE, sizeof(uint8_t));
  size_t len = LIBNNGIO_PROTOBUF_MAX_MESSAGE_SIZE;
  LibnngioProtobuf__LibnngioMessage *nngio_msg = NULL;

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
                 "Failed to receive LibnngioMessage: %s",
                 nng_strerror(ctx->transport_rv));
    free(buffer);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }

  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Received LibnngioMessage of size %zu bytes.", len);
  nngio_msg = libnngio_protobuf__libnngio_message__unpack(NULL, len, buffer);
  free(buffer);

  if (nngio_msg == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV", __FILE__, __LINE__,
                 libnngio_context_id(ctx->ctx),
                 "Failed to unpack received LibnngioMessage.");
    rv = LIBNNGIO_PROTOBUF_ERR_DESERIALIZATION_FAILED;
    return rv;
  }

  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Unpacked LibnngioMessage successfully.");
  libnngio_log("DBG", "LIBNNGIO_PROTOBUF_RECV", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "LibnngioMessage details: UUID='%s', msg_case=%s.",
               nngio_msg->uuid,
               libnngio_protobuf_nngio_msg_case_str(nngio_msg->msg_case));

  // Copy the received message to the user-provided structure
  (*message) = nngio_copy_nngio_message(nngio_msg);

  libnngio_protobuf__libnngio_message__free_unpacked(nngio_msg, NULL);
  libnngio_log("INF", "LIBNNGIO_PROTOBUF_RECV", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Successfully received LibnngioMessage.");

  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

static void recv_async_cb(libnngio_context *ctx, int result, void *data,
                          size_t len, void *arg) {
  recv_async_cb_data *cb_data = (recv_async_cb_data *)arg;
  libnngio_protobuf_error_code rv = LIBNNGIO_PROTOBUF_ERR_NONE;
  // Note: data is a pointer to the received buffer, len is its length
  // Unpack the LibnngioMessage from the received buffer
  LibnngioProtobuf__LibnngioMessage *nngio_msg = NULL;
  LibnngioProtobuf__LibnngioMessage **msg =
      (LibnngioProtobuf__LibnngioMessage **)&nngio_msg;

  if (result != 0) {
    libnngio_log("ERR", "RECV_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx), "Asynchronous receive failed: %s",
                 nng_strerror(result));
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
  } else {
    libnngio_log("INF", "RECV_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Asynchronous receive completed successfully.");
  }

  nngio_msg = libnngio_protobuf__libnngio_message__unpack(NULL, len, data);
  if (nngio_msg == NULL) {
    libnngio_log("ERR", "RECV_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Failed to unpack LibnngioMessage from received buffer.");
    rv = LIBNNGIO_PROTOBUF_ERR_DESERIALIZATION_FAILED;
  } else {
    libnngio_log(
        "DBG", "RECV_ASYNC_CB", __FILE__, __LINE__, libnngio_context_id(ctx),
        "Received message (%s) of size %zu bytes.", nngio_msg->uuid, len);
  }

  libnngio_log(
      "INF", "RECV_ASYNC_CB", __FILE__, __LINE__, libnngio_context_id(ctx),
      "Asynchronous receive callback processing completed with code %d.", rv);
  libnngio_log("DBG", "RECV_ASYNC_CB", __FILE__, __LINE__,
               libnngio_context_id(ctx), "Received LibnngioMessage (%s).",
               nngio_msg ? nngio_msg->uuid : "NULL");

  // update the user's message pointer if we successfully received a message
  if (rv == LIBNNGIO_PROTOBUF_ERR_NONE && nngio_msg && cb_data->msg) {
    libnngio_log("DBG", "RECV_ASYNC_CB", __FILE__, __LINE__,
                 libnngio_context_id(ctx),
                 "Setting user message pointer %p to received message %p\n",
                 cb_data->msg, msg);

    (*cb_data->msg) = nngio_copy_nngio_message(*msg);
  } else {
    libnngio_log(
        "DBG", "RECV_ASYNC_CB", __FILE__, __LINE__, libnngio_context_id(ctx),
        "Not setting user message pointer %p due to error or null message\n",
        cb_data->msg);
  }

  // Make a copy of the message to pass to the user callback
  LibnngioProtobuf__LibnngioMessage *msg_copy =
      nngio_msg ? nngio_copy_nngio_message(nngio_msg) : NULL;

  // We invoke a series of callbacks in order:
  // 1. Server callback (if provided and server is set)
  // 2. Client callback (if provided and client is set)
  // 3. User callback (if provided)
  //
  // Different from send, here we pass a copy of the received message
  // to each callback, the original is freed at the end of this function.
  //
  // The client and server callbacks get passed the message first, and then
  // the user callback gets invoked. If the user provides a callback, then
  // they are responsible for freeing the message passed to them.

  if (cb_data->server_cb && cb_data->server) {
    cb_data->server_cb(cb_data->server, result, msg_copy ? &msg_copy : NULL,
                       cb_data->user_data);
  }

  if (cb_data->client_cb && cb_data->client) {
    cb_data->client_cb(cb_data->client, result, msg_copy ? &msg_copy : NULL,
                       cb_data->user_data);
  }

  if (cb_data->user_cb) {
    cb_data->user_cb(cb_data->ctx, result, msg_copy ? &msg_copy : NULL,
                     cb_data->user_data);
  } else {
    // If no user callback, free the copied message here
    nngio_free_nngio_message(msg_copy);
  }

  libnngio_protobuf__libnngio_message__free_unpacked(nngio_msg, NULL);
  free(cb_data->buffer);
  free(cb_data);
}

libnngio_protobuf_error_code libnngio_protobuf_recv_async(
    libnngio_protobuf_context *ctx, LibnngioProtobuf__LibnngioMessage **message,
    libnngio_protobuf_recv_cb_info cb_info) {
  libnngio_protobuf_error_code rv = LIBNNGIO_PROTOBUF_ERR_NONE;

  if (ctx == NULL || ctx->ctx == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_ASYNC", __FILE__, __LINE__, -1,
                 "Invalid protobuf context provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
    return rv;
  }

  if (cb_info.user_cb == NULL) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_ASYNC", __FILE__, __LINE__,
                 libnngio_context_id(ctx->ctx),
                 "Invalid callback function provided.");
    rv = LIBNNGIO_PROTOBUF_ERR_INVALID_MESSAGE;
    return rv;
  }

  if (message == NULL) {
    libnngio_log(
        "NTC", "LIBNNGIO_PROTOBUF_RECV_ASYNC", __FILE__, __LINE__,
        libnngio_context_id(ctx->ctx),
        "message pointer is NULL, creating a place for the received message.");

    // Allocate memory for the message pointer if it's NULL
    message = malloc(sizeof(LibnngioProtobuf__LibnngioMessage *));
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
  cb_data->user_cb = cb_info.user_cb;
  cb_data->server_cb = cb_info.server_cb;
  cb_data->client_cb = cb_info.client_cb;
  cb_data->ctx = ctx;
  cb_data->server = cb_info.server;
  cb_data->client = cb_info.client;
  cb_data->user_data = cb_info.user_data;
  cb_data->msg =
      (void **)message;  // Note: message will be updated in the callback

  // Receive the serialized buffer asynchronously using the underlying libnngio
  // context
  ctx->transport_rv = libnngio_context_recv_async(
      ctx->ctx, cb_data->buffer, &cb_data->len, recv_async_cb, cb_data);
  if (ctx->transport_rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_PROTOBUF_RECV_ASYNC", __FILE__, __LINE__,
                 libnngio_context_id(ctx->ctx),
                 "Failed to receive LibnngioMessage asynchronously: %s",
                 nng_strerror(ctx->transport_rv));
    free(cb_data);
    rv = LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR;
    return rv;
  }

  libnngio_log("INF", "LIBNNGIO_PROTOBUF_RECV_ASYNC", __FILE__, __LINE__,
               libnngio_context_id(ctx->ctx),
               "Successfully initiated async receive of LibnngioMessage.");

  // Note: The actual message will be processed by the callback function.
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

// Service implementation functions
static LibnngioProtobuf__RpcResponse__Status call_rpc_handler(
    libnngio_server *s, const void *request_data, size_t request_size,
    void **response_data, size_t *response_size, void *user_data) {
  if (user_data == NULL || request_data == NULL || request_size == 0) {
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InvalidRequest;
  }
  LibnngioProtobuf__RpcRequest *request =
      libnngio_protobuf__rpc_request__unpack(NULL, request_size, request_data);
  if (request == NULL) {
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InvalidRequest;
  }

  char *service_name = NULL;
  char *method_name = NULL;
  libnngio_service_registration *service = NULL;
  libnngio_service_method *method = NULL;

  // Find the service and method
  for (size_t i = 0; i < s->n_services; i++) {
    if (strcmp(s->services[i].service_name, request->service_name) == 0) {
      service_name = s->services[i].service_name;
      service = &s->services[i];
    }
  }

  if (service_name == NULL) {
    libnngio_protobuf__rpc_request__free_unpacked(request, NULL);
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__ServiceNotFound;
  }

  for (size_t j = 0; j < service->n_methods; j++) {
    if (strcmp(service->methods[j].method_name, request->method_name) == 0) {
      method_name = service->methods[j].method_name;
      method = &service->methods[j];
    }
  }

  if (method_name == NULL) {
    libnngio_protobuf__rpc_request__free_unpacked(request, NULL);
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__MethodNotFound;
  }

  // Prevent recursive CallRpc calls
  if (strcmp(service_name, "LibnngioProtobuf.RpcService") == 0 &&
      strcmp(method_name, "CallRpc") == 0) {
    libnngio_protobuf__rpc_request__free_unpacked(request, NULL);
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InvalidRequest;
  }

  // Call the method handler
  LibnngioProtobuf__RpcResponse__Status status =
      method->handler(s, request->payload.data, request->payload.len,
                      response_data, response_size, method->user_data);
  libnngio_protobuf__rpc_request__free_unpacked(request, NULL);
  return status;
}

static LibnngioProtobuf__RpcResponse__Status get_services_handler(
    libnngio_server *s, const void *request_data, size_t request_size,
    void **response_data, size_t *response_size, void *user_data) {
  if (user_data == NULL) {
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }
  LibnngioProtobuf__ServiceDiscoveryResponse *response = NULL;
  libnngio_protobuf_error_code rv = LIBNNGIO_PROTOBUF_ERR_NONE;

  rv = libnngio_server_create_service_discovery_response(s, &response);
  if (rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }

  *response_size =
      libnngio_protobuf__service_discovery_response__get_packed_size(response);
  *response_data = malloc(*response_size);
  if (*response_data == NULL) {
    libnngio_protobuf__service_discovery_response__free_unpacked(response,
                                                                 NULL);
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }

  libnngio_protobuf__service_discovery_response__pack(response, *response_data);
  libnngio_protobuf__service_discovery_response__free_unpacked(response, NULL);
  return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success;
}

static libnngio_protobuf_error_code libnngio_server_create_transport_discovery_response(
    libnngio_server *s, LibnngioProtobuf__GetTransportsResponse **response) {
  if (s == NULL || response == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  *response = malloc(sizeof(LibnngioProtobuf__GetTransportsResponse));
  if (*response == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_UNKNOWN;
  }
  libnngio_protobuf__get_transports_response__init(*response);

  // for each transport context, add its info to the response
  (*response)->n_transports = s->n_transports;
  if (s->n_transports > 0) {
    (*response)->transports = malloc(s->n_transports * sizeof(char *));
    if ((*response)->transports == NULL) {
      free(*response);
      *response = NULL;
      return LIBNNGIO_PROTOBUF_ERR_UNKNOWN;
    }
    for (size_t i = 0; i < s->n_transports; i++) {
      const libnngio_config *cfg = libnngio_context_get_config(s->transports[i]->t_ctx);
      libnngio_log("DBG", "LIBNNGIO_SERVER_CREATE_TRANSPORT_DISCOVERY_RESPONSE",
                   __FILE__, __LINE__, libnngio_context_id(s->transports[i]->t_ctx),
                   "Adding transport URL '%s' to discovery response.",
                   cfg->url);
    }
  } else {
    (*response)->transports = NULL;
  }


  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

static libnngio_protobuf_error_code libnngio_server_add_transport(libnngio_server *s,
                                        libnngio_server_transport *ctx) {
  if (s == NULL || ctx == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  s->transports = realloc(s->transports,
                             (s->n_transports + 1) * sizeof(*s->transports));
  if (s->transports == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INTERNAL_ERROR;
  }

  s->transports[s->n_transports] = ctx;
  s->n_transports++;
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

static LibnngioProtobuf__RpcResponse__Status add_transport_handler(
    libnngio_server *s, const void *request_data, size_t request_size,
    void **response_data, size_t *response_size, void *user_data) {
  // extract the add transport request
  if (user_data == NULL || request_data == NULL || request_size == 0) {
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InvalidRequest;
  }

  LibnngioProtobuf__AddTransportRequest *request =
      libnngio_protobuf__add_transport_request__unpack(NULL, request_size, request_data);
  if (request == NULL) {
    libnngio_log("ERR", "ADD_TRANSPORT_HANDLER", __FILE__, __LINE__, -1,
                 "Failed to unpack AddTransportRequest.");
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InvalidRequest;
  }

  // convert add transport request to a libnngio config
  libnngio_config* cfg = libnngio_config_from_transport(request->transport);

  libnngio_transport *t = NULL;
  libnngio_protobuf_error_code rv = libnngio_transport_init(&t, cfg);
  if (rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "ADD_TRANSPORT_HANDLER", __FILE__, __LINE__, -1,
                 "Failed to initialize transport %s with URL '%s'.", cfg->name, cfg->url);
    libnngio_protobuf__add_transport_request__free_unpacked(request, NULL);
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InvalidRequest;
  }

  libnngio_context *t_ctx = NULL;
  rv = libnngio_context_init(&t_ctx, t, cfg, NULL, NULL);
  if (rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "ADD_TRANSPORT_HANDLER", __FILE__, __LINE__, -1,
                 "Failed to initialize context %s with transport URL '%s'.",
                 cfg->name, cfg->url);
    libnngio_protobuf__add_transport_request__free_unpacked(request, NULL);
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InvalidRequest;
  }

  libnngio_protobuf_context *pb_ctx = NULL;
  rv = libnngio_protobuf_context_init(&pb_ctx, t_ctx);
  if (rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "ADD_TRANSPORT_HANDLER", __FILE__, __LINE__, -1,
                 "Failed to initialize protobuf context %s with transport URL '%s'.",
                 cfg->name, cfg->url);
    libnngio_protobuf__add_transport_request__free_unpacked(request, NULL);
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }

  libnngio_server_transport *transport_ctx = malloc(sizeof(*transport_ctx));
  if (transport_ctx == NULL) {
    libnngio_log("ERR", "ADD_TRANSPORT_HANDLER", __FILE__, __LINE__, -1,
                 "Failed to allocate memory for transport context %s with URL '%s'.",
                 cfg->name, cfg->url);
    libnngio_protobuf__add_transport_request__free_unpacked(request, NULL);
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }
  transport_ctx->cfg = cfg;
  transport_ctx->transport = t;
  transport_ctx->t_ctx = t_ctx;
  transport_ctx->proto_ctx = pb_ctx;
  rv = libnngio_server_add_transport(s, transport_ctx);
  libnngio_protobuf__add_transport_request__free_unpacked(request, NULL);
  if (rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "ADD_TRANSPORT_HANDLER", __FILE__, __LINE__, -1,
                 "Failed to add transport context for URL '%s' to server.",
                 cfg->url);
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }

  // return an empty response
  *response_data = NULL;
  *response_size = 0;
  libnngio_log("INF", "ADD_TRANSPORT_HANDLER", __FILE__, __LINE__, -1,
               "Successfully added transport context for URL '%s' to server.",
               cfg->url);
  return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success;
}

static LibnngioProtobuf__RpcResponse__Status get_transports_handler(
    libnngio_server *s, const void *request_data, size_t request_size,
    void **response_data, size_t *response_size, void *user_data) {
  if (user_data == NULL) {
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }
  LibnngioProtobuf__GetTransportsResponse *response = NULL;
  libnngio_protobuf_error_code rv = LIBNNGIO_PROTOBUF_ERR_NONE;

  rv = libnngio_server_create_transport_discovery_response(s, &response);
  if (rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }

  *response_size =
      libnngio_protobuf__get_transports_response__get_packed_size(response);
  *response_data = malloc(*response_size);
  if (*response_data == NULL) {
    libnngio_protobuf__get_transports_response__free_unpacked(response,
                                                                   NULL);
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }

  libnngio_protobuf__get_transports_response__pack(response,
                                                        *response_data);
  libnngio_protobuf__get_transports_response__free_unpacked(response,
                                                                 NULL);
  return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success;
}

static libnngio_protobuf_error_code libnngio_server_remove_transport(libnngio_server *s,char* name) {
  if (s == NULL || name == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  for (size_t i = 0; i < s->n_transports; i++) {
    const libnngio_config *cfg = libnngio_context_get_config(s->transports[i]->t_ctx);
  libnngio_log("INF", "REMOVE_TRANSPORT_HANDLER", __FILE__, __LINE__, -1,
               "Checking transport %s with url '%s' in server.",
               cfg->name, cfg->url);
    if (strcmp(cfg->name, name) == 0) {
      // Found the transport to remove
      libnngio_server_transport *to_remove = s->transports[i];

      // Shift remaining contexts down
      for (size_t j = i; j < s->n_transports - 1; j++) {
        s->transports[j] = s->transports[j + 1];
      }
      s->n_transports--;

      // Resize the array
      if (s->n_transports == 0) {
        free(s->transports);
        s->transports = NULL;
      } else {
        s->transports = realloc(s->transports,
                                   s->n_transports * sizeof(*s->transports));
      }

      // Free the removed context
      free((void*)to_remove->cfg->name);
      free((void*)to_remove->cfg->url);
      free((void*)to_remove->cfg->tls_cert);
      free((void*)to_remove->cfg->tls_key);
      free((void*)to_remove->cfg->tls_ca_cert);
      free((void*)to_remove->cfg);
      libnngio_protobuf_context_free(to_remove->proto_ctx);
      libnngio_context_free(to_remove->t_ctx);
      libnngio_transport_free(to_remove->transport);
      free(to_remove);
      return LIBNNGIO_PROTOBUF_ERR_NONE;
    }
  }

  // We didn't find the transport to remove, but that's not an error
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

static LibnngioProtobuf__RpcResponse__Status remove_transport_handler(
    libnngio_server *s, const void *request_data, size_t request_size,
    void **response_data, size_t *response_size, void *user_data) {
  // extract the add transport request
  if (user_data == NULL || request_data == NULL || request_size == 0) {
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InvalidRequest;
  }

  LibnngioProtobuf__RemoveTransportRequest *request =
      libnngio_protobuf__remove_transport_request__unpack(NULL, request_size, request_data);
  if (request == NULL) {
    libnngio_log("ERR", "ADD_TRANSPORT_HANDLER", __FILE__, __LINE__, -1,
                 "Failed to unpack AddTransportRequest.");
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InvalidRequest;
  }

  char* name = strdup(request->name);

  libnngio_protobuf_error_code proto_rv = libnngio_server_remove_transport(s, name);

  free(name);
  libnngio_protobuf__remove_transport_request__free_unpacked(request, NULL);
  return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success;
}

/**
 * @brief Initialize a libnngio_server with the given protobuf context.
 */
libnngio_protobuf_error_code libnngio_server_init(
    libnngio_server **server, libnngio_protobuf_context *mgmt_ctx) {
  if (server == NULL || mgmt_ctx == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  *server = calloc(1, sizeof(libnngio_server));
  if (*server == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_UNKNOWN;
  }

  (*server)->mgmt_ctx = mgmt_ctx;
  (*server)->transports = NULL;
  (*server)->n_transports = 0;
  (*server)->services = NULL;
  (*server)->n_services = 0;
  (*server)->running = 0;

  static libnngio_service_method rpc_service_method = {0};
  rpc_service_method.method_name = "CallRpc";
  rpc_service_method.handler = call_rpc_handler;
  rpc_service_method.user_data = *server;

  libnngio_protobuf_error_code rv = libnngio_server_register_service(
      *server, "LibnngioProtobuf.RpcService", &rpc_service_method, 1);
  if (rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    free(*server);
    *server = NULL;
    return rv;
  }

  static libnngio_service_method get_services_method = {0};
  get_services_method.method_name = "GetServices";
  get_services_method.handler = get_services_handler;
  get_services_method.user_data = *server;

  rv = libnngio_server_register_service(
      *server, "LibnngioProtobuf.ServiceDiscoveryService", &get_services_method,
      1);
  if (rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_server_free(*server);
    *server = NULL;
    return rv;
  }

  static libnngio_service_method get_transports_method[3] = {0};
  get_transports_method[0].method_name = "AddTransport";
  get_transports_method[0].handler = add_transport_handler;
  get_transports_method[0].user_data = *server;
  get_transports_method[1].method_name = "GetTransports";
  get_transports_method[1].handler = get_transports_handler;
  get_transports_method[1].user_data = *server;
  get_transports_method[2].method_name = "RemoveTransport";
  get_transports_method[2].handler = remove_transport_handler;
  get_transports_method[2].user_data = *server;

  rv = libnngio_server_register_service(
      *server, "LibnngioProtobuf.TransportService", get_transports_method,
      3);
  if (rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_server_free(*server);
    *server = NULL;
    return rv;
  }

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

  // Free transport contexts
  for (size_t i = 0; i < server->n_transports; i++) {
    free((void*)server->transports[i]->cfg->name);
    free((void*)server->transports[i]->cfg->url);
    free((void*)server->transports[i]->cfg->tls_cert);
    free((void*)server->transports[i]->cfg->tls_key);
    free((void*)server->transports[i]->cfg->tls_ca_cert);
    free((void*)server->transports[i]->cfg);
    libnngio_protobuf_context_free(server->transports[i]->proto_ctx);
    libnngio_context_free(server->transports[i]->t_ctx);
    libnngio_transport_free(server->transports[i]->transport);
    free(server->transports[i]);
  }
  if (server->transports) {
    free(server->transports);
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
  if (server == NULL || service_name == NULL || methods == NULL ||
      n_methods == 0) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  // Reallocate services array
  server->services =
      realloc(server->services,
              (server->n_services + 1) * sizeof(libnngio_service_registration));
  if (server->services == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_UNKNOWN;
  }

  libnngio_service_registration *new_service =
      &server->services[server->n_services];

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

static LibnngioProtobuf__ServiceDiscoveryResponse *
create_service_discovery_response(libnngio_service_registration *services,
                                  size_t n_services) {
  LibnngioProtobuf__ServiceDiscoveryResponse *response = NULL;
  response = calloc(1, sizeof(LibnngioProtobuf__ServiceDiscoveryResponse));
  if (response == NULL) {
    return NULL;
  }
  libnngio_protobuf__service_discovery_response__init(response);

  response->n_services = n_services;
  response->services = calloc(n_services, sizeof(LibnngioProtobuf__Service *));
  if (response->services == NULL) {
    free(response);
    return NULL;
  }

  for (size_t i = 0; i < n_services; i++) {
    response->services[i] = calloc(1, sizeof(LibnngioProtobuf__Service));
    if (response->services[i] == NULL) {
      // Clean up on failure
      for (size_t j = 0; j < i; j++) {
        libnngio_protobuf__service__free_unpacked(response->services[j], NULL);
      }
      free(response->services);
      free(response);
      return NULL;
    }
    libnngio_protobuf__service__init(response->services[i]);
    response->services[i]->name = strdup(services[i].service_name);
    response->services[i]->n_methods = services[i].n_methods;
    response->services[i]->methods =
        calloc(services[i].n_methods, sizeof(char *));
    if (response->services[i]->methods == NULL) {
      // Clean up on failure
      free(response->services[i]->name);
      free(response->services[i]);
      for (size_t j = 0; j < i; j++) {
        libnngio_protobuf__service__free_unpacked(response->services[j], NULL);
      }
      free(response->services);
      free(response);
      return NULL;
    }
    for (size_t j = 0; j < services[i].n_methods; j++) {
      response->services[i]->methods[j] =
          strdup(services[i].methods[j].method_name);
      if (response->services[i]->methods[j] == NULL) {
        // Clean up on failure
        for (size_t k = 0; k < j; k++) {
          free(response->services[i]->methods[k]);
        }
        free(response->services[i]->methods);
        free(response->services[i]->name);
        free(response->services[i]);
        for (size_t k = 0; k < i; k++) {
          libnngio_protobuf__service__free_unpacked(response->services[k],
                                                    NULL);
        }
        free(response->services);
        free(response);
        return NULL;
      }
    }
  }

  return response;
}

/**
 * @brief Create a service discovery response message from the server's
 * registered services.
 */
libnngio_protobuf_error_code libnngio_server_create_service_discovery_response(
    libnngio_server *server,
    LibnngioProtobuf__ServiceDiscoveryResponse **response) {
  if (server == NULL || response == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  // Note: The message is of type LibnngioProtobuf__ServiceDiscoveryResponse
  // but the server holds an array of libnngio_service_registration
  // so we need to convert between the two representations

  LibnngioProtobuf__ServiceDiscoveryResponse *resp =
      create_service_discovery_response(server->services, server->n_services);
  if (resp == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_UNKNOWN;
  }

  *response = resp;
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Receive a service discovery request with a server.
 *
 * @param server    Server to use for receiving.
 * @param request   Pointer to receive allocated ServiceDiscoveryRequest.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_server_recv_service_discovery_request(
    libnngio_server *server,
    LibnngioProtobuf__ServiceDiscoveryRequest **request) {
  if (server == NULL || server->mgmt_ctx == NULL ||
      server->mgmt_ctx->ctx == NULL || request == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  return libnngio_protobuf_recv_service_discovery_request(server->mgmt_ctx,
                                                          request);
}

/**
 * @brief Receive a service discovery request with a server asynchronously.
 *
 * @param server    Server to use for receiving.
 * @param request   Pointer to receive allocated ServiceDiscoveryRequest.
 * @param cb_info   Callback info for handling the async receive.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code
libnngio_server_recv_service_discovery_request_async(
    libnngio_server *server,
    LibnngioProtobuf__ServiceDiscoveryRequest **request,
    libnngio_protobuf_recv_cb_info cb_info) {
  if (server == NULL || server->mgmt_ctx == NULL ||
      server->mgmt_ctx->ctx == NULL || request == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  return libnngio_protobuf_recv_service_discovery_request_async(
      server->mgmt_ctx, request, cb_info);
}

/**
 * @brief Send a service discovery response with the server.
 *
 * @param server    Server to use for sending.
 * @param response  Pointer to the ServiceDiscoveryResponse to send.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_server_send_service_discovery_response(
    libnngio_server *server,
    const LibnngioProtobuf__ServiceDiscoveryResponse *response) {
  if (server == NULL || server->mgmt_ctx == NULL ||
      server->mgmt_ctx->ctx == NULL || response == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  // Note: The message is of type LibnngioProtobuf__ServiceDiscoveryResponse
  // but libnngio_protobuf_send expects a LibnngioProtobuf__LibnngioMessage
  return libnngio_protobuf_send_service_discovery_response(server->mgmt_ctx,
                                                           response);
}

/**
 * @brief Send a service discovery response with the server asynchronously.
 *
 * @param server    Server to use for sending.
 * @param response  Pointer to the ServiceDiscoveryResponse to send.
 * @param cb_info   Callback info for handling the async send.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code
libnngio_server_send_service_discovery_response_async(
    libnngio_server *server,
    const LibnngioProtobuf__ServiceDiscoveryResponse *response,
    libnngio_protobuf_send_cb_info cb_info) {
  if (server == NULL || server->mgmt_ctx == NULL ||
      server->mgmt_ctx->ctx == NULL || response == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  return libnngio_protobuf_send_service_discovery_response_async(
      server->mgmt_ctx, response, cb_info);
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
 * @brief Send a service discovery request with the client.
 *
 * @param client    Client to use for sending.
 * @param request   Pointer to the ServiceDiscoveryRequest to send.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_client_send_service_discovery_request(
    libnngio_client *client,
    const LibnngioProtobuf__ServiceDiscoveryRequest *request) {
  if (client == NULL || client->proto_ctx == NULL ||
      client->proto_ctx->ctx == NULL || request == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  return libnngio_protobuf_send_service_discovery_request(client->proto_ctx,
                                                          request);
}

/**
 * @brief Send a service discovery request with the client asynchronously.
 *
 * @param client    Client to use for sending.
 * @param request   Pointer to the ServiceDiscoveryRequest to send.
 * @param cb_info   Callback info for handling the async send.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code
libnngio_client_send_service_discovery_request_async(
    libnngio_client *client,
    const LibnngioProtobuf__ServiceDiscoveryRequest *request,
    libnngio_protobuf_send_cb_info cb_info) {
  if (client == NULL || client->proto_ctx == NULL ||
      client->proto_ctx->ctx == NULL || request == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  return libnngio_protobuf_send_service_discovery_request_async(
      client->proto_ctx, request, cb_info);
}

/**
 * @brief Receive a service discovery response with the client.
 *
 * @param client    Client to use for receiving.
 * @param response  Pointer to receive allocated ServiceDiscoveryResponse.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_client_recv_service_discovery_response(
    libnngio_client *client,
    LibnngioProtobuf__ServiceDiscoveryResponse **response) {
  if (client == NULL || client->proto_ctx == NULL ||
      client->proto_ctx->ctx == NULL || response == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  libnngio_protobuf_error_code rv;
  rv = libnngio_protobuf_recv_service_discovery_response(client->proto_ctx,
                                                         response);
  if (rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    return rv;
  }

  rv = libnngio_client_populate_services_from_response(client, *response);
  if (rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_protobuf__service_discovery_response__free_unpacked(*response,
                                                                 NULL);
    *response = NULL;
    return rv;
  }

  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Callback to handle the service discovery response and populate the
 * client's discovered services.
 */
static void client_service_discovery_response_cb(
    libnngio_client *client, int result,
    LibnngioProtobuf__LibnngioMessage **message, void *user_data) {
  if (result != 0 || message == NULL || *message == NULL) {
    libnngio_log("ERR", "CLIENT_SERVICE_DISCOVERY_RESPONSE_CB", __FILE__,
                 __LINE__, libnngio_context_id(client->proto_ctx->ctx),
                 "Error in service discovery response callback: %d", result);
    return;
  }

  if ((*message)->msg_case !=
      LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_RESPONSE) {
    libnngio_log("ERR", "CLIENT_SERVICE_DISCOVERY_RESPONSE_CB", __FILE__,
                 __LINE__, libnngio_context_id(client->proto_ctx->ctx),
                 "Received unexpected message type in service discovery "
                 "response callback.");
    return;
  }

  LibnngioProtobuf__ServiceDiscoveryResponse *response =
      (*message)->service_discovery_response;

  libnngio_protobuf_error_code rv =
      libnngio_client_populate_services_from_response(client, response);
  if (rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "CLIENT_SERVICE_DISCOVERY_RESPONSE_CB", __FILE__,
                 __LINE__, libnngio_context_id(client->proto_ctx->ctx),
                 "Failed to populate services from response: %d", rv);
    return;
  }

  libnngio_log("INF", "CLIENT_SERVICE_DISCOVERY_RESPONSE_CB", __FILE__,
               __LINE__, libnngio_context_id(client->proto_ctx->ctx),
               "Successfully populated %zu services from discovery response.",
               client->n_discovered_services);
}

/**
 * @brief Receive a service discovery response with the client asynchronously.
 *
 * @param client    Client to use for receiving.
 * @param response  Pointer to receive allocated ServiceDiscoveryResponse.
 * @param cb_info   Callback info for handling the async receive.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code
libnngio_client_recv_service_discovery_response_async(
    libnngio_client *client,
    LibnngioProtobuf__ServiceDiscoveryResponse **response,
    libnngio_protobuf_recv_cb_info cb_info) {
  if (client == NULL || client->proto_ctx == NULL ||
      client->proto_ctx->ctx == NULL || response == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  // populate the client cb and client pointer in cb_info that way
  // when the callback is invoked we can populate the client's discovered
  // services from the received response
  cb_info.client = client;
  cb_info.client_cb = client_service_discovery_response_cb;

  return libnngio_protobuf_recv_service_discovery_response_async(
      client->proto_ctx, response, cb_info);
}

/**
 * @brief Populate the client's discovered services from a received
 * ServiceDiscoveryResponse.
 *
 * @param client    Client whose discovered services to populate.
 * @param response  Pointer to the received ServiceDiscoveryResponse.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_client_populate_services_from_response(
    libnngio_client *client,
    const LibnngioProtobuf__ServiceDiscoveryResponse *response) {
  if (client == NULL || response == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  // Free any previously discovered services
  for (size_t i = 0; i < client->n_discovered_services; i++) {
    nngio_free_service(client->discovered_services[i]);
  }
  free(client->discovered_services);
  client->discovered_services = NULL;
  client->n_discovered_services = 0;

  // Populate discovered services from the response
  client->n_discovered_services = response->n_services;
  client->discovered_services =
      calloc(response->n_services, sizeof(LibnngioProtobuf__Service *));
  if (client->discovered_services == NULL) {
    client->n_discovered_services = 0;
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
      return LIBNNGIO_PROTOBUF_ERR_UNKNOWN;
    }
  }

  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Send an RPC request with the client.
 *
 * @param client    Client to use for sending.
 * @param request   Pointer to the RpcRequest to send.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_client_send_rpc_request(
    libnngio_client *client, const LibnngioProtobuf__RpcRequest *request) {
  if (client == NULL || client->proto_ctx == NULL ||
      client->proto_ctx->ctx == NULL || request == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  return libnngio_protobuf_send_rpc_request(client->proto_ctx, request);
}

/**
 * @brief Send an RPC request with the client asynchronously.
 *
 * @param client    Client to use for sending.
 * @param request   Pointer to the RpcRequest to send.
 * @param cb_info   Callback info for handling the async send.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_client_send_rpc_request_async(
    libnngio_client *client, const LibnngioProtobuf__RpcRequest *request,
    libnngio_protobuf_send_cb_info cb_info) {
  if (client == NULL || client->proto_ctx == NULL ||
      client->proto_ctx->ctx == NULL || request == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  return libnngio_protobuf_send_rpc_request_async(client->proto_ctx, request,
                                                  cb_info);
}

/**
 * @brief Receive an RPC response with the client.
 *
 * @param client    Client to use for receiving.
 * @param response  Pointer to receive allocated RpcResponseMessage.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_client_recv_rpc_response(
    libnngio_client *client, LibnngioProtobuf__RpcResponse **response) {
  if (client == NULL || client->proto_ctx == NULL ||
      client->proto_ctx->ctx == NULL || response == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  return libnngio_protobuf_recv_rpc_response(client->proto_ctx, response);
}

/**
 * @brief Receive an RPC response with the client asynchronously.
 *
 * @param client    Client to use for receiving.
 * @param response  Pointer to receive allocated RpcResponseMessage.
 * @param cb_info   Callback info for handling the async receive.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_client_recv_rpc_response_async(
    libnngio_client *client, LibnngioProtobuf__RpcResponse **response,
    libnngio_protobuf_recv_cb_info cb_info) {
  if (client == NULL || client->proto_ctx == NULL ||
      client->proto_ctx->ctx == NULL || response == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  return libnngio_protobuf_recv_rpc_response_async(client->proto_ctx, response,
                                                   cb_info);
}

/**
 * @brief Take a service discovery request and then generate a service discovery
 * response with the server's registered services.
 *
 * @param server    Server to use for receiving and sending.
 * @param request   Pointer to receive allocated ServiceDiscoveryRequest.
 * @param response  Pointer to receive allocated ServiceDiscoveryResponse.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_server_handle_service_discovery(
    libnngio_server *server,
    LibnngioProtobuf__ServiceDiscoveryRequest **request,
    LibnngioProtobuf__ServiceDiscoveryResponse **response) {
  libnngio_protobuf_error_code rv;

  if (server == NULL || server->mgmt_ctx == NULL ||
      server->mgmt_ctx->ctx == NULL || request == NULL || response == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  libnngio_log("DBG", "LIBNNGIO_SERVER_HANDLE_SERVICE_DISCOVERY", __FILE__,
               __LINE__, libnngio_context_id(server->mgmt_ctx->ctx),
               "Handling service discovery request.");

  rv = libnngio_server_recv_service_discovery_request(server, request);
  if (rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    return rv;
  }

  libnngio_log("DBG", "LIBNNGIO_SERVER_HANDLE_SERVICE_DISCOVERY", __FILE__,
               __LINE__, libnngio_context_id(server->mgmt_ctx->ctx),
               "Received service discovery request.");

  rv = libnngio_server_create_service_discovery_response(server, response);
  if (rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_protobuf__service_discovery_request__free_unpacked(*request, NULL);
    return rv;
  }

  libnngio_log("DBG", "LIBNNGIO_SERVER_HANDLE_SERVICE_DISCOVERY", __FILE__,
               __LINE__, libnngio_context_id(server->mgmt_ctx->ctx),
               "Created service discovery response with %zu services.",
               (*response)->n_services);

  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

static void server_prepare_service_discovery_response_cb(
    libnngio_server *server, int result,
    LibnngioProtobuf__LibnngioMessage **msg, void *user_data) {
  if (result != 0 || msg == NULL || *msg == NULL) {
    libnngio_log("ERR", "SERVER_PREPARE_SERVICE_DISCOVERY_RESPONSE_CB",
                 __FILE__, __LINE__,
                 libnngio_context_id(server->mgmt_ctx->ctx),
                 "Error in prepare response callback: %d", result);
    return;
  }

  if ((*msg)->msg_case !=
      LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_SERVICE_DISCOVERY_REQUEST) {
    libnngio_log(
        "ERR", "SERVER_PREPARE_SERVICE_DISCOVERY_RESPONSE_CB", __FILE__,
        __LINE__, libnngio_context_id(server->mgmt_ctx->ctx),
        "Received unexpected message type in prepare response callback.");
    return;
  }

  // this is left here for completeness, though we don't actually use the
  // request to generate the response in this simple implementation
  LibnngioProtobuf__ServiceDiscoveryRequest *request =
      (*msg)->service_discovery_request;

  // the server storage holds the pointer to the response that we need to
  // populate create a new response message and populate it with the server's
  // registered services
  LibnngioProtobuf__ServiceDiscoveryResponse **response =
      (LibnngioProtobuf__ServiceDiscoveryResponse **)server->server_storage;

  libnngio_protobuf_error_code rv =
      libnngio_server_create_service_discovery_response(server, response);
  if (rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "SERVER_PREPARE_SERVICE_DISCOVERY_RESPONSE_CB",
                 __FILE__, __LINE__,
                 libnngio_context_id(server->mgmt_ctx->ctx),
                 "Failed to create service discovery response: %d", rv);
    return;
  }
}

/**
 * @brief Take a service discovery request and then generate a service discovery
 * response with the server's registered services asynchronously.
 *
 * @param server    Server to use for receiving and sending.
 * @param request   Pointer to receive allocated ServiceDiscoveryRequest.
 * @param response  Pointer to receive allocated ServiceDiscoveryResponse.
 * @param cb_info   Callback info for handling the async receive and send.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_server_handle_service_discovery_async(
    libnngio_server *server,
    LibnngioProtobuf__ServiceDiscoveryRequest **request,
    LibnngioProtobuf__ServiceDiscoveryResponse **response,
    libnngio_protobuf_recv_cb_info recv_cb_info) {
  libnngio_protobuf_error_code rv;
  if (server == NULL || server->mgmt_ctx == NULL ||
      server->mgmt_ctx->ctx == NULL || request == NULL || response == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  libnngio_log("DBG", "LIBNNGIO_SERVER_HANDLE_SERVICE_DISCOVERY_ASYNC",
               __FILE__, __LINE__, libnngio_context_id(server->mgmt_ctx->ctx),
               "Handling service discovery request asynchronously.");

  // set server storage to point to the response pointer
  server->server_storage = (void *)response;
  // set the server callback to prepare the response once the request is
  // received
  recv_cb_info.server = server;
  recv_cb_info.server_cb = server_prepare_service_discovery_response_cb;
  rv = libnngio_server_recv_service_discovery_request_async(server, request,
                                                            recv_cb_info);
  if (rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    return rv;
  }

  return LIBNNGIO_PROTOBUF_ERR_NONE;
}

/**
 * @brief Receive an RPC request with the server.
 *
 * @param server    Server to use for receiving.
 * @param request   Pointer to receive allocated RpcRequest.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_server_recv_rpc_request(
    libnngio_server *server, LibnngioProtobuf__RpcRequest **request) {
  if (server == NULL || server->mgmt_ctx == NULL ||
      server->mgmt_ctx->ctx == NULL || request == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  return libnngio_protobuf_recv_rpc_request(server->mgmt_ctx, request);
}

/**
 * @brief Receive an RPC request with the server asynchronously.
 *
 * @param server    Server to use for receiving.
 * @param request   Pointer to receive allocated RpcRequest.
 * @param cb_info   Callback info for handling the async receive.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_server_recv_rpc_request_async(
    libnngio_server *server, LibnngioProtobuf__RpcRequest **request,
    libnngio_protobuf_recv_cb_info cb_info) {
  if (server == NULL || server->mgmt_ctx == NULL ||
      server->mgmt_ctx->ctx == NULL || request == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  return libnngio_protobuf_recv_rpc_request_async(server->mgmt_ctx, request,
                                                  cb_info);
}

/**
 * @brief Create an RPC response message based on the given request.
 *
 * @param server   Server which is creating the response.
 * @param request  Pointer to the RpcRequestMessage to base the response on.
 * @param response Pointer to receive allocated RpcResponseMessage.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_server_create_rpc_response(
    libnngio_server *server, const LibnngioProtobuf__RpcRequest *request,
    LibnngioProtobuf__RpcResponse **response) {
  if (server == NULL || request == NULL || response == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  // Create variables to bootstrap response
  LibnngioProtobuf__RpcResponse__Status status =
      LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  void *payload = NULL;
  size_t payload_len = 0;

  // Find the service and method handlers
  char *service_name = request->service_name;
  char *method_name = request->method_name;
  char *found_service_name = NULL;
  char *found_method_name = NULL;
  libnngio_service_method *method_handler = NULL;

  for (size_t i = 0; i < server->n_services; i++) {
    if (strcmp(server->services[i].service_name, service_name) == 0) {
      found_service_name = server->services[i].service_name;
      for (size_t j = 0; j < server->services[i].n_methods; j++) {
        if (strcmp(server->services[i].methods[j].method_name, method_name) ==
            0) {
          found_method_name = server->services[i].methods[j].method_name;
          method_handler = &server->services[i].methods[j];
          break;
        }
      }
      break;
    }
  }

  if (found_service_name == NULL) {
    libnngio_log("ERR", "LIBNNGIO_SERVER_CREATE_RPC_RESPONSE", __FILE__,
                 __LINE__, libnngio_context_id(server->mgmt_ctx->ctx),
                 "No service '%s' found.", request->service_name);
    status = LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__ServiceNotFound;
    (*response) = nngio_create_rpc_response(status, payload, payload_len,
                                            "Requested service not found!");
    return LIBNNGIO_PROTOBUF_ERR_SERVICE_NOT_FOUND;
  }

  if (found_method_name == NULL) {
    libnngio_log("ERR", "LIBNNGIO_SERVER_CREATE_RPC_RESPONSE", __FILE__,
                 __LINE__, libnngio_context_id(server->mgmt_ctx->ctx),
                 "Service '%s' does not have a method '%s'.",
                 request->service_name, request->method_name);
    status = LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__MethodNotFound;
    (*response) = nngio_create_rpc_response(status, payload, payload_len,
                                            "Requested service not found!");
    return LIBNNGIO_PROTOBUF_ERR_METHOD_NOT_FOUND;
  }

  if (method_handler == NULL || method_handler->handler == NULL) {
    libnngio_log("ERR", "LIBNNGIO_SERVER_CREATE_RPC_RESPONSE", __FILE__,
                 __LINE__, libnngio_context_id(server->mgmt_ctx->ctx),
                 "No handler found for service '%s' method '%s'.",
                 request->service_name, request->method_name);
    status = LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
    (*response) = nngio_create_rpc_response(status, payload, payload_len,
                                            "Missing a method handler!");
    return LIBNNGIO_PROTOBUF_ERR_INTERNAL_ERROR;
  }

  // Call the method handler to get the response
  status = method_handler->handler(server, request->payload.data,
                                   request->payload.len, &payload, &payload_len,
                                   method_handler->user_data);

  // If the handler is successful, the payload is the data
  // If the handler is not successful, the payload is the error message

  if (status == LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success) {
    (*response) = nngio_create_rpc_response(status, payload, payload_len, "");
    free(payload);
    libnngio_log("DBG", "LIBNNGIO_SERVER_CREATE_RPC_RESPONSE", __FILE__,
                 __LINE__, libnngio_context_id(server->mgmt_ctx->ctx),
                 "Created RPC response for service '%s' method '%s'.",
                 request->service_name, request->method_name);
    return LIBNNGIO_PROTOBUF_ERR_NONE;
  } else {
    (*response) = nngio_create_rpc_response(status, NULL, 0, payload);
    libnngio_log("ERR", "LIBNNGIO_SERVER_CREATE_RPC_RESPONSE", __FILE__,
                 __LINE__, libnngio_context_id(server->mgmt_ctx->ctx),
                 "Handler for service '%s' method '%s' failed with status %d: "
                 "%s",
                 request->service_name, request->method_name, status,
                 (payload != NULL) ? (char *)payload : "No error message");
    free(payload);
    return LIBNNGIO_PROTOBUF_ERR_INTERNAL_ERROR;
  }
}

/**
 * @brief Send an RPC response with the server.
 *
 * @param server    Server to use for sending.
 * @param response  Pointer to the RpcResponseMessage to send.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_server_send_rpc_response(
    libnngio_server *server, const LibnngioProtobuf__RpcResponse *response) {
  if (server == NULL || server->mgmt_ctx == NULL ||
      server->mgmt_ctx->ctx == NULL || response == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  return libnngio_protobuf_send_rpc_response(server->mgmt_ctx, response);
}

/**
 * @brief Send an RPC response with the server asynchronously.
 *
 * @param server    Server to use for sending.
 * @param response  Pointer to the RpcResponseMessage to send.
 * @param cb_info   Callback info for handling the async send.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_server_send_rpc_response_async(
    libnngio_server *server, const LibnngioProtobuf__RpcResponse *response,
    libnngio_protobuf_send_cb_info cb_info) {
  if (server == NULL || server->mgmt_ctx == NULL ||
      server->mgmt_ctx->ctx == NULL || response == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  return libnngio_protobuf_send_rpc_response_async(server->mgmt_ctx, response,
                                                   cb_info);
}

static void server_prepare_rpc_response_cb(
    libnngio_server *server, int result,
    LibnngioProtobuf__LibnngioMessage **msg, void *user_data) {
  if (result != 0 || msg == NULL || *msg == NULL) {
    libnngio_log("ERR", "SERVER_PREPARE_RPC_RESPONSE_CB", __FILE__, __LINE__,
                 libnngio_context_id(server->mgmt_ctx->ctx),
                 "Error in prepare rpc response callback: %d", result);
    return;
  }

  if ((*msg)->msg_case !=
      LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RPC_REQUEST) {
    libnngio_log(
        "ERR", "SERVER_PREPARE_RPC_RESPONSE_CB", __FILE__, __LINE__,
        libnngio_context_id(server->mgmt_ctx->ctx),
        "Received unexpected message type in prepare rpc response callback.");
    return;
  }

  // this is left here for completeness, though we don't actually use the
  // request to generate the response in this simple implementation
  LibnngioProtobuf__RpcRequest *request = (*msg)->rpc_request;

  // the server storage holds the pointer to the response that we need to
  // populate create a new response message and populate it with the server's
  // registered services
  LibnngioProtobuf__RpcResponse **response =
      (LibnngioProtobuf__RpcResponse **)server->server_storage;

  libnngio_protobuf_error_code rv =
      libnngio_server_create_rpc_response(server, request, response);
  if (rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "SERVER_PREPARE_RPC_RESPONSE_CB", __FILE__, __LINE__,
                 libnngio_context_id(server->mgmt_ctx->ctx),
                 "Failed to create rpc response: %d", rv);
  } else {
    libnngio_log("INF", "SERVER_PREPARE_RPC_RESPONSE_CB", __FILE__, __LINE__,
                 libnngio_context_id(server->mgmt_ctx->ctx),
                 "Created RPC response.");
  }
}

/**
 * @brief Take an RPC request and then generate an RPC response by invoking the
 * appropriate service method handler.
 *
 * @param server    Server to use for receiving and sending.
 * @param request   Pointer to receive allocated RpcRequest.
 * @param response  Pointer to receive allocated RpcResponseMessage.
 * @param recv_cb_info Callback info for handling the async receive.
 * @return libnngio_protobuf_error_code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_server_handle_rpc_request_async(
    libnngio_server *server, LibnngioProtobuf__RpcRequest **request,
    LibnngioProtobuf__RpcResponse **response,
    libnngio_protobuf_recv_cb_info recv_cb_info) {
  libnngio_protobuf_error_code rv;
  if (server == NULL || server->mgmt_ctx == NULL ||
      server->mgmt_ctx->ctx == NULL || request == NULL || response == NULL) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }

  libnngio_log("DBG", "LIBNNGIO_SERVER_HANDLE_RPC_REQUEST_ASYNC", __FILE__,
               __LINE__, libnngio_context_id(server->mgmt_ctx->ctx),
               "Handling RPC request asynchronously.");

  // set server storage to point to the response pointer
  server->server_storage = (void *)response;
  // set the server callback to prepare the response once the request is
  // received
  recv_cb_info.server = server;
  recv_cb_info.server_cb = server_prepare_rpc_response_cb;
  rv = libnngio_server_recv_rpc_request_async(server, request, recv_cb_info);
  if (rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    return rv;
  }

  return LIBNNGIO_PROTOBUF_ERR_NONE;
}
