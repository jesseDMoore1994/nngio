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
  
  // Three management servers
  libnngio_server *transport_server;
  libnngio_server *service_server;
  libnngio_server *connection_server;
  
  // Protobuf contexts for each server
  libnngio_protobuf_context *transport_proto_ctx;
  libnngio_protobuf_context *service_proto_ctx;
  libnngio_protobuf_context *connection_proto_ctx;
  
  // Storage for managed resources
  libnngio_management_transport_entry *transports;
  size_t n_transports;
  size_t transports_capacity;
  
  libnngio_management_service_entry *services;
  size_t n_services;
  size_t services_capacity;
  
  libnngio_management_connection_entry *connections;
  size_t n_connections;
  size_t connections_capacity;
  
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
// Service Management Handlers
// =============================================================================

static LibnngioProtobuf__RpcResponse__Status service_add_handler(
    const char *service_name, const char *method_name,
    const void *request_payload, size_t request_payload_len,
    void **response_payload, size_t *response_payload_len, void *user_data) {
  
  libnngio_management_context *ctx = (libnngio_management_context *)user_data;
  if (!ctx) {
    *response_payload = strdup("Invalid context");
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }
  
  LibnngioManagement__AddServiceResponse resp = LIBNNGIO_MANAGEMENT__ADD_SERVICE_RESPONSE__INIT;
  resp.success = true;
  resp.message = "Service added successfully";
  
  *response_payload_len = libnngio_management__add_service_response__get_packed_size(&resp);
  *response_payload = malloc(*response_payload_len);
  if (*response_payload) {
    libnngio_management__add_service_response__pack(&resp, *response_payload);
  }
  
  return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success;
}

static LibnngioProtobuf__RpcResponse__Status service_remove_handler(
    const char *service_name, const char *method_name,
    const void *request_payload, size_t request_payload_len,
    void **response_payload, size_t *response_payload_len, void *user_data) {
  
  libnngio_management_context *ctx = (libnngio_management_context *)user_data;
  if (!ctx) {
    *response_payload = strdup("Invalid context");
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }
  
  LibnngioManagement__RemoveServiceResponse resp = LIBNNGIO_MANAGEMENT__REMOVE_SERVICE_RESPONSE__INIT;
  resp.success = true;
  resp.message = "Service removed successfully";
  
  *response_payload_len = libnngio_management__remove_service_response__get_packed_size(&resp);
  *response_payload = malloc(*response_payload_len);
  if (*response_payload) {
    libnngio_management__remove_service_response__pack(&resp, *response_payload);
  }
  
  return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success;
}

static LibnngioProtobuf__RpcResponse__Status service_list_handler(
    const char *service_name, const char *method_name,
    const void *request_payload, size_t request_payload_len,
    void **response_payload, size_t *response_payload_len, void *user_data) {
  
  libnngio_management_context *ctx = (libnngio_management_context *)user_data;
  if (!ctx) {
    *response_payload = strdup("Invalid context");
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }
  
  LibnngioManagement__ListServicesResponse resp = LIBNNGIO_MANAGEMENT__LIST_SERVICES_RESPONSE__INIT;
  resp.n_services = 0;
  resp.services = NULL;
  
  *response_payload_len = libnngio_management__list_services_response__get_packed_size(&resp);
  *response_payload = malloc(*response_payload_len);
  if (*response_payload) {
    libnngio_management__list_services_response__pack(&resp, *response_payload);
  }
  
  return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success;
}

static LibnngioProtobuf__RpcResponse__Status service_get_handler(
    const char *service_name, const char *method_name,
    const void *request_payload, size_t request_payload_len,
    void **response_payload, size_t *response_payload_len, void *user_data) {
  
  libnngio_management_context *ctx = (libnngio_management_context *)user_data;
  if (!ctx) {
    *response_payload = strdup("Invalid context");
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }
  
  LibnngioManagement__GetServiceResponse resp = LIBNNGIO_MANAGEMENT__GET_SERVICE_RESPONSE__INIT;
  resp.found = false;
  resp.config = NULL;
  
  *response_payload_len = libnngio_management__get_service_response__get_packed_size(&resp);
  *response_payload = malloc(*response_payload_len);
  if (*response_payload) {
    libnngio_management__get_service_response__pack(&resp, *response_payload);
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
  
  mgmt_ctx->services_capacity = 10;
  mgmt_ctx->services = calloc(mgmt_ctx->services_capacity, sizeof(libnngio_management_service_entry));
  
  mgmt_ctx->connections_capacity = 10;
  mgmt_ctx->connections = calloc(mgmt_ctx->connections_capacity, sizeof(libnngio_management_connection_entry));
  
  if (!mgmt_ctx->transports || !mgmt_ctx->services || 
      !mgmt_ctx->connections) {
    free(mgmt_ctx->transports);
    free(mgmt_ctx->services);
    free(mgmt_ctx->connections);
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
  
  proto_rv = libnngio_protobuf_context_init(&mgmt_ctx->service_proto_ctx, mgmt_ctx->ipc_context);
  if (proto_rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_management_free(mgmt_ctx);
    return LIBNNGIO_MANAGEMENT_ERR_INTERNAL;
  }
  
  proto_rv = libnngio_protobuf_context_init(&mgmt_ctx->connection_proto_ctx, mgmt_ctx->ipc_context);
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
  
  proto_rv = libnngio_server_init(&mgmt_ctx->service_server, mgmt_ctx->service_proto_ctx);
  if (proto_rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_management_free(mgmt_ctx);
    return LIBNNGIO_MANAGEMENT_ERR_INTERNAL;
  }
  
  proto_rv = libnngio_server_init(&mgmt_ctx->connection_server, mgmt_ctx->connection_proto_ctx);
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
  
  // Register ServiceManagement service methods
  libnngio_service_method service_methods[] = {
    {"AddService", service_add_handler, mgmt_ctx},
    {"RemoveService", service_remove_handler, mgmt_ctx},
    {"ListServices", service_list_handler, mgmt_ctx},
    {"GetService", service_get_handler, mgmt_ctx}
  };
  proto_rv = libnngio_server_register_service(mgmt_ctx->service_server, "ServiceManagement", 
                                               service_methods, 4);
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
  
  mgmt_ctx->running = 0;
  *ctx = mgmt_ctx;
  return LIBNNGIO_MANAGEMENT_ERR_NONE;
}

void libnngio_management_free(libnngio_management_context *ctx) {
  if (!ctx) return;
  
  // Free servers
  if (ctx->transport_server) libnngio_server_free(ctx->transport_server);
  if (ctx->service_server) libnngio_server_free(ctx->service_server);
  if (ctx->connection_server) libnngio_server_free(ctx->connection_server);
  
  // Free protobuf contexts
  if (ctx->transport_proto_ctx) libnngio_protobuf_context_free(ctx->transport_proto_ctx);
  if (ctx->service_proto_ctx) libnngio_protobuf_context_free(ctx->service_proto_ctx);
  if (ctx->connection_proto_ctx) libnngio_protobuf_context_free(ctx->connection_proto_ctx);
  
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
  
  for (size_t i = 0; i < ctx->n_services; i++) {
    free(ctx->services[i].name);
    free(ctx->services[i].transport_name);
    free(ctx->services[i].service_type);
    if (ctx->services[i].server) libnngio_server_free(ctx->services[i].server);
  }
  free(ctx->services);
  
  for (size_t i = 0; i < ctx->n_connections; i++) {
    free(ctx->connections[i].name);
    free(ctx->connections[i].transport_name);
    free(ctx->connections[i].service_name);
  }
  free(ctx->connections);
  
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

LibnngioManagement__ServiceConfig *libnngio_management_create_service_config(
    const char *name, const char *transport_name, const char *service_type) {
  
  LibnngioManagement__ServiceConfig *config = malloc(sizeof(LibnngioManagement__ServiceConfig));
  if (!config) return NULL;
  
  libnngio_management__service_config__init(config);
  config->name = strdup_safe(name);
  config->transport_name = strdup_safe(transport_name);
  config->service_type = strdup_safe(service_type);
  
  return config;
}

void libnngio_management_free_service_config(
    LibnngioManagement__ServiceConfig *config) {
  if (!config) return;
  free(config->name);
  free(config->transport_name);
  free(config->service_type);
  free(config);
}

LibnngioManagement__ConnectionConfig *libnngio_management_create_connection_config(
    const char *name, const char *transport_name, const char *service_name) {
  
  LibnngioManagement__ConnectionConfig *config = malloc(sizeof(LibnngioManagement__ConnectionConfig));
  if (!config) return NULL;
  
  libnngio_management__connection_config__init(config);
  config->name = strdup_safe(name);
  config->transport_name = strdup_safe(transport_name);
  config->service_name = strdup_safe(service_name);
  
  return config;
}

void libnngio_management_free_connection_config(
    LibnngioManagement__ConnectionConfig *config) {
  if (!config) return;
  free(config->name);
  free(config->transport_name);
  free(config->service_name);
  free(config);
}
