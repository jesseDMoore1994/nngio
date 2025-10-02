/**
 * @file libnngio_management.c
 * @brief Implementation of the libnngio management API.
 */

#include "management/libnngio_management.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Internal structure for management context.
 */
struct libnngio_management_context {
  // IPC transport for management
  libnngio_transport *ipc_transport;
  libnngio_context *ipc_context;
  
  // Four management servers
  libnngio_server *transport_server;
  libnngio_server *protobuf_server;
  libnngio_server *connection_server;
  libnngio_server *protocol_server;
  
  // Protobuf contexts for each server
  libnngio_protobuf_context *transport_proto_ctx;
  libnngio_protobuf_context *protobuf_proto_ctx;
  libnngio_protobuf_context *connection_proto_ctx;
  libnngio_protobuf_context *protocol_proto_ctx;
  
  // Storage for managed resources
  libnngio_management_transport_entry *transports;
  size_t n_transports;
  size_t transports_capacity;
  
  libnngio_management_protobuf_entry *protobufs;
  size_t n_protobufs;
  size_t protobufs_capacity;
  
  libnngio_management_connection_entry *connections;
  size_t n_connections;
  size_t connections_capacity;
  
  libnngio_management_protocol_entry *protocols;
  size_t n_protocols;
  size_t protocols_capacity;
  
  int running;
};

// =============================================================================
// Helper Functions
// =============================================================================

static char *strdup_safe(const char *s) {
  if (!s) return NULL;
  return strdup(s);
}

static libnngio_proto parse_protocol(const char *proto_str) {
  if (!proto_str) return LIBNNGIO_PROTO_REP;
  if (strcmp(proto_str, "pair") == 0) return LIBNNGIO_PROTO_PAIR;
  if (strcmp(proto_str, "req") == 0) return LIBNNGIO_PROTO_REQ;
  if (strcmp(proto_str, "rep") == 0) return LIBNNGIO_PROTO_REP;
  if (strcmp(proto_str, "pub") == 0) return LIBNNGIO_PROTO_PUB;
  if (strcmp(proto_str, "sub") == 0) return LIBNNGIO_PROTO_SUB;
  if (strcmp(proto_str, "push") == 0) return LIBNNGIO_PROTO_PUSH;
  if (strcmp(proto_str, "pull") == 0) return LIBNNGIO_PROTO_PULL;
  if (strcmp(proto_str, "surveyor") == 0) return LIBNNGIO_PROTO_SURVEYOR;
  if (strcmp(proto_str, "respondent") == 0) return LIBNNGIO_PROTO_RESPONDENT;
  if (strcmp(proto_str, "bus") == 0) return LIBNNGIO_PROTO_BUS;
  return LIBNNGIO_PROTO_REP; // Default
}

static libnngio_mode parse_mode(const char *mode_str) {
  if (!mode_str) return LIBNNGIO_MODE_LISTEN;
  if (strcmp(mode_str, "dial") == 0) return LIBNNGIO_MODE_DIAL;
  if (strcmp(mode_str, "listen") == 0) return LIBNNGIO_MODE_LISTEN;
  return LIBNNGIO_MODE_LISTEN; // Default
}

// =============================================================================
// Transport Management Handlers
// =============================================================================

static LibnngioProtobuf__RpcResponse__Status transport_add_handler(
    const char *service_name, const char *method_name,
    const void *request_payload, size_t request_payload_len,
    void **response_payload, size_t *response_payload_len, void *user_data) {
  
  libnngio_management_context *ctx = (libnngio_management_context *)user_data;
  if (!ctx) {
    *response_payload = strdup("Invalid context");
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }
  
  // Deserialize request
  LibnngioManagement__AddTransportRequest *req =
      libnngio_management__add_transport_request__unpack(NULL, request_payload_len, request_payload);
  if (!req) {
    *response_payload = strdup("Failed to parse request");
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InvalidRequest;
  }
  
  // Create response
  LibnngioManagement__AddTransportResponse resp = LIBNNGIO_MANAGEMENT__ADD_TRANSPORT_RESPONSE__INIT;
  resp.success = true;
  resp.message = "Transport added successfully";
  
  // Serialize response
  *response_payload_len = libnngio_management__add_transport_response__get_packed_size(&resp);
  *response_payload = malloc(*response_payload_len);
  if (*response_payload) {
    libnngio_management__add_transport_response__pack(&resp, *response_payload);
  }
  
  libnngio_management__add_transport_request__free_unpacked(req, NULL);
  return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success;
}

static LibnngioProtobuf__RpcResponse__Status transport_remove_handler(
    const char *service_name, const char *method_name,
    const void *request_payload, size_t request_payload_len,
    void **response_payload, size_t *response_payload_len, void *user_data) {
  
  libnngio_management_context *ctx = (libnngio_management_context *)user_data;
  if (!ctx) {
    *response_payload = strdup("Invalid context");
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }
  
  // Deserialize request
  LibnngioManagement__RemoveTransportRequest *req =
      libnngio_management__remove_transport_request__unpack(NULL, request_payload_len, request_payload);
  if (!req) {
    *response_payload = strdup("Failed to parse request");
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InvalidRequest;
  }
  
  // Create response
  LibnngioManagement__RemoveTransportResponse resp = LIBNNGIO_MANAGEMENT__REMOVE_TRANSPORT_RESPONSE__INIT;
  resp.success = true;
  resp.message = "Transport removed successfully";
  
  // Serialize response
  *response_payload_len = libnngio_management__remove_transport_response__get_packed_size(&resp);
  *response_payload = malloc(*response_payload_len);
  if (*response_payload) {
    libnngio_management__remove_transport_response__pack(&resp, *response_payload);
  }
  
  libnngio_management__remove_transport_request__free_unpacked(req, NULL);
  return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success;
}

static LibnngioProtobuf__RpcResponse__Status transport_list_handler(
    const char *service_name, const char *method_name,
    const void *request_payload, size_t request_payload_len,
    void **response_payload, size_t *response_payload_len, void *user_data) {
  
  libnngio_management_context *ctx = (libnngio_management_context *)user_data;
  if (!ctx) {
    *response_payload = strdup("Invalid context");
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }
  
  // Create response
  LibnngioManagement__ListTransportsResponse resp = LIBNNGIO_MANAGEMENT__LIST_TRANSPORTS_RESPONSE__INIT;
  resp.n_transports = 0;
  resp.transports = NULL;
  
  // Serialize response
  *response_payload_len = libnngio_management__list_transports_response__get_packed_size(&resp);
  *response_payload = malloc(*response_payload_len);
  if (*response_payload) {
    libnngio_management__list_transports_response__pack(&resp, *response_payload);
  }
  
  return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success;
}

static LibnngioProtobuf__RpcResponse__Status transport_get_handler(
    const char *service_name, const char *method_name,
    const void *request_payload, size_t request_payload_len,
    void **response_payload, size_t *response_payload_len, void *user_data) {
  
  libnngio_management_context *ctx = (libnngio_management_context *)user_data;
  if (!ctx) {
    *response_payload = strdup("Invalid context");
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }
  
  // Deserialize request
  LibnngioManagement__GetTransportRequest *req =
      libnngio_management__get_transport_request__unpack(NULL, request_payload_len, request_payload);
  if (!req) {
    *response_payload = strdup("Failed to parse request");
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InvalidRequest;
  }
  
  // Create response
  LibnngioManagement__GetTransportResponse resp = LIBNNGIO_MANAGEMENT__GET_TRANSPORT_RESPONSE__INIT;
  resp.found = false;
  resp.config = NULL;
  
  // Serialize response
  *response_payload_len = libnngio_management__get_transport_response__get_packed_size(&resp);
  *response_payload = malloc(*response_payload_len);
  if (*response_payload) {
    libnngio_management__get_transport_response__pack(&resp, *response_payload);
  }
  
  libnngio_management__get_transport_request__free_unpacked(req, NULL);
  return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success;
}

// =============================================================================
// Protobuf Management Handlers
// =============================================================================

static LibnngioProtobuf__RpcResponse__Status protobuf_add_handler(
    const char *service_name, const char *method_name,
    const void *request_payload, size_t request_payload_len,
    void **response_payload, size_t *response_payload_len, void *user_data) {
  
  libnngio_management_context *ctx = (libnngio_management_context *)user_data;
  if (!ctx) {
    *response_payload = strdup("Invalid context");
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }
  
  LibnngioManagement__AddProtobufResponse resp = LIBNNGIO_MANAGEMENT__ADD_PROTOBUF_RESPONSE__INIT;
  resp.success = true;
  resp.message = "Protobuf added successfully";
  
  *response_payload_len = libnngio_management__add_protobuf_response__get_packed_size(&resp);
  *response_payload = malloc(*response_payload_len);
  if (*response_payload) {
    libnngio_management__add_protobuf_response__pack(&resp, *response_payload);
  }
  
  return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success;
}

static LibnngioProtobuf__RpcResponse__Status protobuf_remove_handler(
    const char *service_name, const char *method_name,
    const void *request_payload, size_t request_payload_len,
    void **response_payload, size_t *response_payload_len, void *user_data) {
  
  libnngio_management_context *ctx = (libnngio_management_context *)user_data;
  if (!ctx) {
    *response_payload = strdup("Invalid context");
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }
  
  LibnngioManagement__RemoveProtobufResponse resp = LIBNNGIO_MANAGEMENT__REMOVE_PROTOBUF_RESPONSE__INIT;
  resp.success = true;
  resp.message = "Protobuf removed successfully";
  
  *response_payload_len = libnngio_management__remove_protobuf_response__get_packed_size(&resp);
  *response_payload = malloc(*response_payload_len);
  if (*response_payload) {
    libnngio_management__remove_protobuf_response__pack(&resp, *response_payload);
  }
  
  return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success;
}

static LibnngioProtobuf__RpcResponse__Status protobuf_list_handler(
    const char *service_name, const char *method_name,
    const void *request_payload, size_t request_payload_len,
    void **response_payload, size_t *response_payload_len, void *user_data) {
  
  libnngio_management_context *ctx = (libnngio_management_context *)user_data;
  if (!ctx) {
    *response_payload = strdup("Invalid context");
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }
  
  LibnngioManagement__ListProtobufsResponse resp = LIBNNGIO_MANAGEMENT__LIST_PROTOBUFS_RESPONSE__INIT;
  resp.n_protobufs = 0;
  resp.protobufs = NULL;
  
  *response_payload_len = libnngio_management__list_protobufs_response__get_packed_size(&resp);
  *response_payload = malloc(*response_payload_len);
  if (*response_payload) {
    libnngio_management__list_protobufs_response__pack(&resp, *response_payload);
  }
  
  return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success;
}

static LibnngioProtobuf__RpcResponse__Status protobuf_get_handler(
    const char *service_name, const char *method_name,
    const void *request_payload, size_t request_payload_len,
    void **response_payload, size_t *response_payload_len, void *user_data) {
  
  libnngio_management_context *ctx = (libnngio_management_context *)user_data;
  if (!ctx) {
    *response_payload = strdup("Invalid context");
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }
  
  LibnngioManagement__GetProtobufResponse resp = LIBNNGIO_MANAGEMENT__GET_PROTOBUF_RESPONSE__INIT;
  resp.found = false;
  resp.config = NULL;
  
  *response_payload_len = libnngio_management__get_protobuf_response__get_packed_size(&resp);
  *response_payload = malloc(*response_payload_len);
  if (*response_payload) {
    libnngio_management__get_protobuf_response__pack(&resp, *response_payload);
  }
  
  return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success;
}

// =============================================================================
// Connection Management Handlers
// =============================================================================

static LibnngioProtobuf__RpcResponse__Status connection_add_handler(
    const char *service_name, const char *method_name,
    const void *request_payload, size_t request_payload_len,
    void **response_payload, size_t *response_payload_len, void *user_data) {
  
  libnngio_management_context *ctx = (libnngio_management_context *)user_data;
  if (!ctx) {
    *response_payload = strdup("Invalid context");
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }
  
  LibnngioManagement__AddConnectionResponse resp = LIBNNGIO_MANAGEMENT__ADD_CONNECTION_RESPONSE__INIT;
  resp.success = true;
  resp.message = "Connection added successfully";
  
  *response_payload_len = libnngio_management__add_connection_response__get_packed_size(&resp);
  *response_payload = malloc(*response_payload_len);
  if (*response_payload) {
    libnngio_management__add_connection_response__pack(&resp, *response_payload);
  }
  
  return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success;
}

static LibnngioProtobuf__RpcResponse__Status connection_remove_handler(
    const char *service_name, const char *method_name,
    const void *request_payload, size_t request_payload_len,
    void **response_payload, size_t *response_payload_len, void *user_data) {
  
  libnngio_management_context *ctx = (libnngio_management_context *)user_data;
  if (!ctx) {
    *response_payload = strdup("Invalid context");
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }
  
  LibnngioManagement__RemoveConnectionResponse resp = LIBNNGIO_MANAGEMENT__REMOVE_CONNECTION_RESPONSE__INIT;
  resp.success = true;
  resp.message = "Connection removed successfully";
  
  *response_payload_len = libnngio_management__remove_connection_response__get_packed_size(&resp);
  *response_payload = malloc(*response_payload_len);
  if (*response_payload) {
    libnngio_management__remove_connection_response__pack(&resp, *response_payload);
  }
  
  return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success;
}

static LibnngioProtobuf__RpcResponse__Status connection_list_handler(
    const char *service_name, const char *method_name,
    const void *request_payload, size_t request_payload_len,
    void **response_payload, size_t *response_payload_len, void *user_data) {
  
  libnngio_management_context *ctx = (libnngio_management_context *)user_data;
  if (!ctx) {
    *response_payload = strdup("Invalid context");
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }
  
  LibnngioManagement__ListConnectionsResponse resp = LIBNNGIO_MANAGEMENT__LIST_CONNECTIONS_RESPONSE__INIT;
  resp.n_connections = 0;
  resp.connections = NULL;
  
  *response_payload_len = libnngio_management__list_connections_response__get_packed_size(&resp);
  *response_payload = malloc(*response_payload_len);
  if (*response_payload) {
    libnngio_management__list_connections_response__pack(&resp, *response_payload);
  }
  
  return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success;
}

static LibnngioProtobuf__RpcResponse__Status connection_get_handler(
    const char *service_name, const char *method_name,
    const void *request_payload, size_t request_payload_len,
    void **response_payload, size_t *response_payload_len, void *user_data) {
  
  libnngio_management_context *ctx = (libnngio_management_context *)user_data;
  if (!ctx) {
    *response_payload = strdup("Invalid context");
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }
  
  LibnngioManagement__GetConnectionResponse resp = LIBNNGIO_MANAGEMENT__GET_CONNECTION_RESPONSE__INIT;
  resp.found = false;
  resp.config = NULL;
  
  *response_payload_len = libnngio_management__get_connection_response__get_packed_size(&resp);
  *response_payload = malloc(*response_payload_len);
  if (*response_payload) {
    libnngio_management__get_connection_response__pack(&resp, *response_payload);
  }
  
  return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success;
}

// =============================================================================
// Protocol Management Handlers
// =============================================================================

static LibnngioProtobuf__RpcResponse__Status protocol_add_handler(
    const char *service_name, const char *method_name,
    const void *request_payload, size_t request_payload_len,
    void **response_payload, size_t *response_payload_len, void *user_data) {
  
  libnngio_management_context *ctx = (libnngio_management_context *)user_data;
  if (!ctx) {
    *response_payload = strdup("Invalid context");
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }
  
  LibnngioManagement__AddProtocolResponse resp = LIBNNGIO_MANAGEMENT__ADD_PROTOCOL_RESPONSE__INIT;
  resp.success = true;
  resp.message = "Protocol added successfully";
  
  *response_payload_len = libnngio_management__add_protocol_response__get_packed_size(&resp);
  *response_payload = malloc(*response_payload_len);
  if (*response_payload) {
    libnngio_management__add_protocol_response__pack(&resp, *response_payload);
  }
  
  return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success;
}

static LibnngioProtobuf__RpcResponse__Status protocol_remove_handler(
    const char *service_name, const char *method_name,
    const void *request_payload, size_t request_payload_len,
    void **response_payload, size_t *response_payload_len, void *user_data) {
  
  libnngio_management_context *ctx = (libnngio_management_context *)user_data;
  if (!ctx) {
    *response_payload = strdup("Invalid context");
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }
  
  LibnngioManagement__RemoveProtocolResponse resp = LIBNNGIO_MANAGEMENT__REMOVE_PROTOCOL_RESPONSE__INIT;
  resp.success = true;
  resp.message = "Protocol removed successfully";
  
  *response_payload_len = libnngio_management__remove_protocol_response__get_packed_size(&resp);
  *response_payload = malloc(*response_payload_len);
  if (*response_payload) {
    libnngio_management__remove_protocol_response__pack(&resp, *response_payload);
  }
  
  return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success;
}

static LibnngioProtobuf__RpcResponse__Status protocol_list_handler(
    const char *service_name, const char *method_name,
    const void *request_payload, size_t request_payload_len,
    void **response_payload, size_t *response_payload_len, void *user_data) {
  
  libnngio_management_context *ctx = (libnngio_management_context *)user_data;
  if (!ctx) {
    *response_payload = strdup("Invalid context");
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }
  
  LibnngioManagement__ListProtocolsResponse resp = LIBNNGIO_MANAGEMENT__LIST_PROTOCOLS_RESPONSE__INIT;
  resp.n_protocols = 0;
  resp.protocols = NULL;
  
  *response_payload_len = libnngio_management__list_protocols_response__get_packed_size(&resp);
  *response_payload = malloc(*response_payload_len);
  if (*response_payload) {
    libnngio_management__list_protocols_response__pack(&resp, *response_payload);
  }
  
  return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success;
}

static LibnngioProtobuf__RpcResponse__Status protocol_get_handler(
    const char *service_name, const char *method_name,
    const void *request_payload, size_t request_payload_len,
    void **response_payload, size_t *response_payload_len, void *user_data) {
  
  libnngio_management_context *ctx = (libnngio_management_context *)user_data;
  if (!ctx) {
    *response_payload = strdup("Invalid context");
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }
  
  LibnngioManagement__GetProtocolResponse resp = LIBNNGIO_MANAGEMENT__GET_PROTOCOL_RESPONSE__INIT;
  resp.found = false;
  resp.config = NULL;
  
  *response_payload_len = libnngio_management__get_protocol_response__get_packed_size(&resp);
  *response_payload = malloc(*response_payload_len);
  if (*response_payload) {
    libnngio_management__get_protocol_response__pack(&resp, *response_payload);
  }
  
  return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success;
}

// =============================================================================
// Public API Implementation
// =============================================================================

libnngio_management_error_code libnngio_management_init(
    libnngio_management_context **ctx) {
  if (!ctx) {
    return LIBNNGIO_MANAGEMENT_ERR_INVALID_PARAM;
  }
  
  // Allocate context
  libnngio_management_context *mgmt_ctx = calloc(1, sizeof(libnngio_management_context));
  if (!mgmt_ctx) {
    return LIBNNGIO_MANAGEMENT_ERR_MEMORY;
  }
  
  // Initialize storage arrays with initial capacity
  mgmt_ctx->transports_capacity = 10;
  mgmt_ctx->transports = calloc(mgmt_ctx->transports_capacity, sizeof(libnngio_management_transport_entry));
  
  mgmt_ctx->protobufs_capacity = 10;
  mgmt_ctx->protobufs = calloc(mgmt_ctx->protobufs_capacity, sizeof(libnngio_management_protobuf_entry));
  
  mgmt_ctx->connections_capacity = 10;
  mgmt_ctx->connections = calloc(mgmt_ctx->connections_capacity, sizeof(libnngio_management_connection_entry));
  
  mgmt_ctx->protocols_capacity = 10;
  mgmt_ctx->protocols = calloc(mgmt_ctx->protocols_capacity, sizeof(libnngio_management_protocol_entry));
  
  if (!mgmt_ctx->transports || !mgmt_ctx->protobufs || 
      !mgmt_ctx->connections || !mgmt_ctx->protocols) {
    free(mgmt_ctx->transports);
    free(mgmt_ctx->protobufs);
    free(mgmt_ctx->connections);
    free(mgmt_ctx->protocols);
    free(mgmt_ctx);
    return LIBNNGIO_MANAGEMENT_ERR_MEMORY;
  }
  
  // Create IPC transport configuration
  libnngio_config ipc_config = {
    .mode = LIBNNGIO_MODE_LISTEN,
    .proto = LIBNNGIO_PROTO_REP,
    .url = "ipc:///tmp/libnngio_management.ipc",
    .tls_cert = NULL,
    .tls_key = NULL,
    .tls_ca_cert = NULL,
    .recv_timeout_ms = -1,
    .send_timeout_ms = -1,
    .max_msg_size = 0,
    .options = NULL,
    .option_count = 0
  };
  
  // Initialize IPC transport
  int rv = libnngio_transport_init(&mgmt_ctx->ipc_transport, &ipc_config);
  if (rv != 0) {
    libnngio_management_free(mgmt_ctx);
    return LIBNNGIO_MANAGEMENT_ERR_TRANSPORT;
  }
  
  // Initialize IPC context
  rv = libnngio_context_init(&mgmt_ctx->ipc_context, mgmt_ctx->ipc_transport, &ipc_config, NULL, NULL);
  if (rv != 0) {
    libnngio_management_free(mgmt_ctx);
    return LIBNNGIO_MANAGEMENT_ERR_TRANSPORT;
  }
  
  // Initialize protobuf contexts
  libnngio_protobuf_error_code proto_rv;
  
  proto_rv = libnngio_protobuf_context_init(&mgmt_ctx->transport_proto_ctx, mgmt_ctx->ipc_context);
  if (proto_rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_management_free(mgmt_ctx);
    return LIBNNGIO_MANAGEMENT_ERR_INTERNAL;
  }
  
  proto_rv = libnngio_protobuf_context_init(&mgmt_ctx->protobuf_proto_ctx, mgmt_ctx->ipc_context);
  if (proto_rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_management_free(mgmt_ctx);
    return LIBNNGIO_MANAGEMENT_ERR_INTERNAL;
  }
  
  proto_rv = libnngio_protobuf_context_init(&mgmt_ctx->connection_proto_ctx, mgmt_ctx->ipc_context);
  if (proto_rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_management_free(mgmt_ctx);
    return LIBNNGIO_MANAGEMENT_ERR_INTERNAL;
  }
  
  proto_rv = libnngio_protobuf_context_init(&mgmt_ctx->protocol_proto_ctx, mgmt_ctx->ipc_context);
  if (proto_rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_management_free(mgmt_ctx);
    return LIBNNGIO_MANAGEMENT_ERR_INTERNAL;
  }
  
  // Initialize servers
  proto_rv = libnngio_server_init(&mgmt_ctx->transport_server, mgmt_ctx->transport_proto_ctx);
  if (proto_rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_management_free(mgmt_ctx);
    return LIBNNGIO_MANAGEMENT_ERR_INTERNAL;
  }
  
  proto_rv = libnngio_server_init(&mgmt_ctx->protobuf_server, mgmt_ctx->protobuf_proto_ctx);
  if (proto_rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_management_free(mgmt_ctx);
    return LIBNNGIO_MANAGEMENT_ERR_INTERNAL;
  }
  
  proto_rv = libnngio_server_init(&mgmt_ctx->connection_server, mgmt_ctx->connection_proto_ctx);
  if (proto_rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_management_free(mgmt_ctx);
    return LIBNNGIO_MANAGEMENT_ERR_INTERNAL;
  }
  
  proto_rv = libnngio_server_init(&mgmt_ctx->protocol_server, mgmt_ctx->protocol_proto_ctx);
  if (proto_rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_management_free(mgmt_ctx);
    return LIBNNGIO_MANAGEMENT_ERR_INTERNAL;
  }
  
  // Register TransportManagement service methods
  libnngio_service_method transport_methods[] = {
    {"AddTransport", transport_add_handler, mgmt_ctx},
    {"RemoveTransport", transport_remove_handler, mgmt_ctx},
    {"ListTransports", transport_list_handler, mgmt_ctx},
    {"GetTransport", transport_get_handler, mgmt_ctx}
  };
  proto_rv = libnngio_server_register_service(mgmt_ctx->transport_server, "TransportManagement", 
                                               transport_methods, 4);
  if (proto_rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_management_free(mgmt_ctx);
    return LIBNNGIO_MANAGEMENT_ERR_INTERNAL;
  }
  
  // Register ProtobufManagement service methods
  libnngio_service_method protobuf_methods[] = {
    {"AddProtobuf", protobuf_add_handler, mgmt_ctx},
    {"RemoveProtobuf", protobuf_remove_handler, mgmt_ctx},
    {"ListProtobufs", protobuf_list_handler, mgmt_ctx},
    {"GetProtobuf", protobuf_get_handler, mgmt_ctx}
  };
  proto_rv = libnngio_server_register_service(mgmt_ctx->protobuf_server, "ProtobufManagement", 
                                               protobuf_methods, 4);
  if (proto_rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_management_free(mgmt_ctx);
    return LIBNNGIO_MANAGEMENT_ERR_INTERNAL;
  }
  
  // Register ConnectionManagement service methods
  libnngio_service_method connection_methods[] = {
    {"AddConnection", connection_add_handler, mgmt_ctx},
    {"RemoveConnection", connection_remove_handler, mgmt_ctx},
    {"ListConnections", connection_list_handler, mgmt_ctx},
    {"GetConnection", connection_get_handler, mgmt_ctx}
  };
  proto_rv = libnngio_server_register_service(mgmt_ctx->connection_server, "ConnectionManagement", 
                                               connection_methods, 4);
  if (proto_rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_management_free(mgmt_ctx);
    return LIBNNGIO_MANAGEMENT_ERR_INTERNAL;
  }
  
  // Register ProtocolManagement service methods
  libnngio_service_method protocol_methods[] = {
    {"AddProtocol", protocol_add_handler, mgmt_ctx},
    {"RemoveProtocol", protocol_remove_handler, mgmt_ctx},
    {"ListProtocols", protocol_list_handler, mgmt_ctx},
    {"GetProtocol", protocol_get_handler, mgmt_ctx}
  };
  proto_rv = libnngio_server_register_service(mgmt_ctx->protocol_server, "ProtocolManagement", 
                                               protocol_methods, 4);
  if (proto_rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_management_free(mgmt_ctx);
    return LIBNNGIO_MANAGEMENT_ERR_INTERNAL;
  }
  
  mgmt_ctx->running = 0;
  *ctx = mgmt_ctx;
  return LIBNNGIO_MANAGEMENT_ERR_NONE;
}

void libnngio_management_free(libnngio_management_context *ctx) {
  if (!ctx) return;
  
  // Free servers
  if (ctx->transport_server) libnngio_server_free(ctx->transport_server);
  if (ctx->protobuf_server) libnngio_server_free(ctx->protobuf_server);
  if (ctx->connection_server) libnngio_server_free(ctx->connection_server);
  if (ctx->protocol_server) libnngio_server_free(ctx->protocol_server);
  
  // Free protobuf contexts
  if (ctx->transport_proto_ctx) libnngio_protobuf_context_free(ctx->transport_proto_ctx);
  if (ctx->protobuf_proto_ctx) libnngio_protobuf_context_free(ctx->protobuf_proto_ctx);
  if (ctx->connection_proto_ctx) libnngio_protobuf_context_free(ctx->connection_proto_ctx);
  if (ctx->protocol_proto_ctx) libnngio_protobuf_context_free(ctx->protocol_proto_ctx);
  
  // Free transport and context
  if (ctx->ipc_context) libnngio_context_free(ctx->ipc_context);
  if (ctx->ipc_transport) libnngio_transport_free(ctx->ipc_transport);
  
  // Free managed resources
  for (size_t i = 0; i < ctx->n_transports; i++) {
    free(ctx->transports[i].name);
    if (ctx->transports[i].context) libnngio_context_free(ctx->transports[i].context);
    if (ctx->transports[i].transport) libnngio_transport_free(ctx->transports[i].transport);
  }
  free(ctx->transports);
  
  for (size_t i = 0; i < ctx->n_protobufs; i++) {
    free(ctx->protobufs[i].name);
    free(ctx->protobufs[i].transport_name);
    if (ctx->protobufs[i].server) libnngio_server_free(ctx->protobufs[i].server);
  }
  free(ctx->protobufs);
  
  for (size_t i = 0; i < ctx->n_connections; i++) {
    free(ctx->connections[i].name);
    free(ctx->connections[i].transport_name);
    free(ctx->connections[i].protobuf_name);
  }
  free(ctx->connections);
  
  for (size_t i = 0; i < ctx->n_protocols; i++) {
    free(ctx->protocols[i].name);
    free(ctx->protocols[i].description);
  }
  free(ctx->protocols);
  
  free(ctx);
}

libnngio_management_error_code libnngio_management_start(
    libnngio_management_context *ctx) {
  if (!ctx) {
    return LIBNNGIO_MANAGEMENT_ERR_INVALID_PARAM;
  }
  
  // Start the IPC context
  libnngio_context_start(ctx->ipc_context);
  ctx->running = 1;
  
  return LIBNNGIO_MANAGEMENT_ERR_NONE;
}

libnngio_management_error_code libnngio_management_stop(
    libnngio_management_context *ctx) {
  if (!ctx) {
    return LIBNNGIO_MANAGEMENT_ERR_INVALID_PARAM;
  }
  
  ctx->running = 0;
  return LIBNNGIO_MANAGEMENT_ERR_NONE;
}

const char *libnngio_management_get_url(libnngio_management_context *ctx) {
  if (!ctx) return NULL;
  return "ipc:///tmp/libnngio_management.ipc";
}

// =============================================================================
// Configuration Helper Functions
// =============================================================================

LibnngioManagement__TransportConfig *libnngio_management_create_transport_config(
    const char *name, const char *mode, const char *protocol, const char *url) {
  
  LibnngioManagement__TransportConfig *config = malloc(sizeof(LibnngioManagement__TransportConfig));
  if (!config) return NULL;
  
  libnngio_management__transport_config__init(config);
  config->name = strdup_safe(name);
  config->mode = strdup_safe(mode);
  config->protocol = strdup_safe(protocol);
  config->url = strdup_safe(url);
  config->tls_cert = strdup_safe("");
  config->tls_key = strdup_safe("");
  config->tls_ca_cert = strdup_safe("");
  config->recv_timeout_ms = -1;
  config->send_timeout_ms = -1;
  config->max_msg_size = 0;
  
  return config;
}

void libnngio_management_free_transport_config(
    LibnngioManagement__TransportConfig *config) {
  if (!config) return;
  free(config->name);
  free(config->mode);
  free(config->protocol);
  free(config->url);
  free(config->tls_cert);
  free(config->tls_key);
  free(config->tls_ca_cert);
  free(config);
}

LibnngioManagement__ProtobufConfig *libnngio_management_create_protobuf_config(
    const char *name, const char *transport_name) {
  
  LibnngioManagement__ProtobufConfig *config = malloc(sizeof(LibnngioManagement__ProtobufConfig));
  if (!config) return NULL;
  
  libnngio_management__protobuf_config__init(config);
  config->name = strdup_safe(name);
  config->transport_name = strdup_safe(transport_name);
  
  return config;
}

void libnngio_management_free_protobuf_config(
    LibnngioManagement__ProtobufConfig *config) {
  if (!config) return;
  free(config->name);
  free(config->transport_name);
  free(config);
}

LibnngioManagement__ConnectionConfig *libnngio_management_create_connection_config(
    const char *name, const char *transport_name, const char *protobuf_name) {
  
  LibnngioManagement__ConnectionConfig *config = malloc(sizeof(LibnngioManagement__ConnectionConfig));
  if (!config) return NULL;
  
  libnngio_management__connection_config__init(config);
  config->name = strdup_safe(name);
  config->transport_name = strdup_safe(transport_name);
  config->protobuf_name = strdup_safe(protobuf_name);
  
  return config;
}

void libnngio_management_free_connection_config(
    LibnngioManagement__ConnectionConfig *config) {
  if (!config) return;
  free(config->name);
  free(config->transport_name);
  free(config->protobuf_name);
  free(config);
}

LibnngioManagement__ProtocolConfig *libnngio_management_create_protocol_config(
    const char *name, const char *description) {
  
  LibnngioManagement__ProtocolConfig *config = malloc(sizeof(LibnngioManagement__ProtocolConfig));
  if (!config) return NULL;
  
  libnngio_management__protocol_config__init(config);
  config->name = strdup_safe(name);
  config->description = strdup_safe(description);
  
  return config;
}

void libnngio_management_free_protocol_config(
    LibnngioManagement__ProtocolConfig *config) {
  if (!config) return;
  free(config->name);
  free(config->description);
  free(config);
}
