/**
 * @file libnngio_management.c
 * @brief Implementation of the libnngio management API.
 */

#include "management/libnngio_management.h"
#include "modsys/libnngio_modsys.h"
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
  
  // Single management server with all services
  libnngio_server *management_server;
  
  // Single protobuf context for the management server
  libnngio_protobuf_context *management_proto_ctx;
  
  // Module system for managing registered modules
  libnngio_modsys_context *modsys;
  
  // Storage for managed resources
  libnngio_management_transport_entry *transports;
  size_t n_transports;
  size_t transports_capacity;
  
  libnngio_management_service_entry *services;
  size_t n_services;
  size_t services_capacity;
  
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

/**
 * @brief Add services from a module descriptor to the management context's service list.
 * 
 * This function populates the services array from the module descriptor, creating
 * service entries for tracking purposes.
 *
 * @param ctx Management context to add services to.
 * @param module Module descriptor containing services to add.
 * @param transport_name Name of the transport these services are attached to.
 * @return 0 on success, -1 on failure.
 */
static int add_services_from_module(libnngio_management_context *ctx,
                                    const libnngio_module_descriptor *module,
                                    const char *transport_name) {
  if (!ctx || !module || !transport_name) {
    return -1;
  }
  
  // Iterate through all services in the module
  for (size_t i = 0; i < module->n_services; i++) {
    const libnngio_module_service *mod_svc = &module->services[i];
    
    // Check if we need to expand the services array
    if (ctx->n_services >= ctx->services_capacity) {
      size_t new_capacity = ctx->services_capacity * 2;
      libnngio_management_service_entry *new_services = 
          realloc(ctx->services, new_capacity * sizeof(libnngio_management_service_entry));
      if (!new_services) {
        return -1;
      }
      ctx->services = new_services;
      ctx->services_capacity = new_capacity;
    }
    
    // Add the service entry with prefixed name: "Package.ServiceName"
    libnngio_management_service_entry *entry = &ctx->services[ctx->n_services];
    
    // Create prefixed service name
    size_t prefix_len = strlen(module->protobuf_package) + strlen(mod_svc->service_name) + 2;
    char *prefixed_name = malloc(prefix_len);
    if (!prefixed_name) {
      return -1;
    }
    snprintf(prefixed_name, prefix_len, "%s.%s", module->protobuf_package, mod_svc->service_name);
    
    entry->name = prefixed_name;
    entry->transport_name = strdup_safe(transport_name);
    entry->service_type = strdup_safe(module->module_name);
    entry->server = ctx->management_server; // Reference to the management server
    
    if (!entry->name || !entry->transport_name || !entry->service_type) {
      free(entry->name);
      free(entry->transport_name);
      free(entry->service_type);
      return -1;
    }
    
    ctx->n_services++;
  }
  
  return 0;
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
  libnngio_management__list_services_response__init(&resp);
  resp.n_services = ctx->n_services;
  if (ctx->n_services > 0) {
    resp.services = malloc(ctx->n_services * sizeof(LibnngioManagement__ServiceConfig *));
    for (size_t i = 0; i < ctx->n_services; i++) {
      libnngio_management_service_entry *entry = &ctx->services[i];
      LibnngioManagement__ServiceConfig *svc_cfg = malloc(sizeof(LibnngioManagement__ServiceConfig));
      libnngio_management__service_config__init(svc_cfg);
      svc_cfg->name = entry->name;
      svc_cfg->transport_name = entry->transport_name;
      svc_cfg->service_type = entry->service_type;
      resp.services[i] = svc_cfg;
    }
  } else {
    resp.services = NULL;
  }
  
  *response_payload_len = libnngio_management__list_services_response__get_packed_size(&resp);
  *response_payload = malloc(*response_payload_len);
  if (*response_payload) {
    libnngio_management__list_services_response__pack(&resp, *response_payload);
  }

  // free resources
  if (resp.services) {
    for (size_t i = 0; i < resp.n_services; i++) {
      free(resp.services[i]);
    }
    free(resp.services);
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
// Public API Implementation
// =============================================================================

libnngio_management_error_code libnngio_management_init(
    libnngio_management_context **ctx, libnngio_ctx_cb callback) {
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
  
  if (!mgmt_ctx->transports || !mgmt_ctx->services) {
    free(mgmt_ctx->transports);
    free(mgmt_ctx->services);
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
    .recv_timeout_ms = 0,
    .send_timeout_ms = 0,
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
  
  // Initialize IPC context with provided callback (NULL for sync, callback for async)
  rv = libnngio_context_init(&mgmt_ctx->ipc_context, mgmt_ctx->ipc_transport, &ipc_config, callback, mgmt_ctx);
  if (rv != 0) {
    libnngio_management_free(mgmt_ctx);
    return LIBNNGIO_MANAGEMENT_ERR_TRANSPORT;
  }
  
  // Initialize single protobuf context for management
  libnngio_protobuf_error_code proto_rv;
  
  proto_rv = libnngio_protobuf_context_init(&mgmt_ctx->management_proto_ctx, mgmt_ctx->ipc_context);
  if (proto_rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_management_free(mgmt_ctx);
    return LIBNNGIO_MANAGEMENT_ERR_INTERNAL;
  }
  
  // Initialize single management server
  proto_rv = libnngio_server_init(&mgmt_ctx->management_server, mgmt_ctx->management_proto_ctx);
  if (proto_rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_management_free(mgmt_ctx);
    return LIBNNGIO_MANAGEMENT_ERR_INTERNAL;
  }
  
  // Initialize module system
  libnngio_modsys_error_code modsys_rv = libnngio_modsys_init(&mgmt_ctx->modsys);
  if (modsys_rv != LIBNNGIO_MODSYS_ERR_NONE) {
    libnngio_management_free(mgmt_ctx);
    return LIBNNGIO_MANAGEMENT_ERR_INTERNAL;
  }
  
  // Transport name for module registration
  const char *transport_name = "nngio-ipc";
  
  // Register management module via modsys
  const libnngio_module_descriptor *mgmt_module = libnngio_management_get_module_descriptor(mgmt_ctx);
  modsys_rv = libnngio_modsys_register_module(mgmt_ctx->modsys, mgmt_module, 
                                               mgmt_ctx->management_server, transport_name);
  if (modsys_rv != LIBNNGIO_MODSYS_ERR_NONE) {
    libnngio_management_free(mgmt_ctx);
    return LIBNNGIO_MANAGEMENT_ERR_INTERNAL;
  }
  // Add services from management module to the services list (for backward compatibility)
  if (add_services_from_module(mgmt_ctx, mgmt_module, transport_name) != 0) {
    libnngio_management_free(mgmt_ctx);
    return LIBNNGIO_MANAGEMENT_ERR_MEMORY;
  }
  
  // Register protobuf module via modsys
  const libnngio_module_descriptor *protobuf_module = libnngio_protobuf_get_module_descriptor(mgmt_ctx->management_server);
  modsys_rv = libnngio_modsys_register_module(mgmt_ctx->modsys, protobuf_module,
                                               mgmt_ctx->management_server, transport_name);
  if (modsys_rv != LIBNNGIO_MODSYS_ERR_NONE) {
    libnngio_management_free(mgmt_ctx);
    return LIBNNGIO_MANAGEMENT_ERR_INTERNAL;
  }
  // Add services from protobuf module to the services list (for backward compatibility)
  if (add_services_from_module(mgmt_ctx, protobuf_module, transport_name) != 0) {
    libnngio_management_free(mgmt_ctx);
    return LIBNNGIO_MANAGEMENT_ERR_MEMORY;
  }
  
  mgmt_ctx->running = 0;
  *ctx = mgmt_ctx;
  return LIBNNGIO_MANAGEMENT_ERR_NONE;
}

void libnngio_management_free(libnngio_management_context *ctx) {
  if (!ctx) return;
  
  // Free module system
  if (ctx->modsys) libnngio_modsys_free(ctx->modsys);
  
  // Free single management server
  if (ctx->management_server) libnngio_server_free(ctx->management_server);
  
  // Free single protobuf context
  if (ctx->management_proto_ctx) libnngio_protobuf_context_free(ctx->management_proto_ctx);
  
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
    // Note: server is a reference to management_server, freed separately above
  }
  free(ctx->services);
  
  free(ctx);
}

const char *libnngio_management_get_url(libnngio_management_context *ctx) {
  if (!ctx) return NULL;
  return "ipc:///tmp/libnngio_management.ipc";
}

libnngio_server *libnngio_management_get_server(libnngio_management_context *ctx) {
  if (!ctx) return NULL;
  return ctx->management_server;
}

libnngio_context *libnngio_management_get_transport_context(
    libnngio_management_context *ctx) {
  if (!ctx) return NULL;
  return ctx->ipc_context;
}

libnngio_management_error_code libnngio_management_register_module(
    libnngio_management_context *ctx,
    const libnngio_module_descriptor *module) {
  if (!ctx || !module) {
    return LIBNNGIO_MANAGEMENT_ERR_INVALID_PARAM;
  }
  
  // Register module via modsys
  libnngio_modsys_error_code modsys_rv = 
      libnngio_modsys_register_module(ctx->modsys, module, 
                                       ctx->management_server, "nngio-ipc");
  if (modsys_rv != LIBNNGIO_MODSYS_ERR_NONE) {
    if (modsys_rv == LIBNNGIO_MODSYS_ERR_ALREADY_EXISTS) {
      return LIBNNGIO_MANAGEMENT_ERR_ALREADY_EXISTS;
    }
    return LIBNNGIO_MANAGEMENT_ERR_INTERNAL;
  }
  
  // Add the services to the management context's service list (for backward compatibility)
  if (add_services_from_module(ctx, module, "nngio-ipc") != 0) {
    return LIBNNGIO_MANAGEMENT_ERR_MEMORY;
  }
  
  return LIBNNGIO_MANAGEMENT_ERR_NONE;
}

libnngio_management_error_code libnngio_management_unregister_module(
    libnngio_management_context *ctx,
    const char *module_name) {
  if (!ctx || !module_name) {
    return LIBNNGIO_MANAGEMENT_ERR_INVALID_PARAM;
  }
  
  // Find and remove services from the service list (for backward compatibility)
  size_t write_idx = 0;
  for (size_t i = 0; i < ctx->n_services; i++) {
    // Check if this service belongs to the module being unregistered
    if (ctx->services[i].service_type && 
        strcmp(ctx->services[i].service_type, module_name) == 0) {
      // Free this service entry
      free(ctx->services[i].name);
      free(ctx->services[i].transport_name);
      free(ctx->services[i].service_type);
    } else {
      // Keep this service
      if (write_idx != i) {
        ctx->services[write_idx] = ctx->services[i];
      }
      write_idx++;
    }
  }
  ctx->n_services = write_idx;
  
  // Unregister module via modsys
  libnngio_modsys_error_code modsys_rv = 
      libnngio_modsys_unregister_module(ctx->modsys, module_name);
  if (modsys_rv != LIBNNGIO_MODSYS_ERR_NONE) {
    if (modsys_rv == LIBNNGIO_MODSYS_ERR_NOT_FOUND) {
      return LIBNNGIO_MANAGEMENT_ERR_NOT_FOUND;
    }
    return LIBNNGIO_MANAGEMENT_ERR_INTERNAL;
  }
  
  return LIBNNGIO_MANAGEMENT_ERR_NONE;
}

size_t libnngio_management_get_module_count(libnngio_management_context *ctx) {
  if (!ctx || !ctx->modsys) return 0;
  return libnngio_modsys_get_module_count(ctx->modsys);
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

// =============================================================================
// Module Interface Implementation
// =============================================================================

/**
 * @brief Get the module descriptor for the management module.
 * 
 * Returns a descriptor that describes the management module's services.
 * Note: The methods arrays are static and should not be freed.
 * The user_data will need to be set appropriately when using this descriptor.
 *
 * @param user_data User data to pass to all handler functions
 * @return Pointer to the module descriptor.
 */
const libnngio_module_descriptor* libnngio_management_get_module_descriptor(void *user_data) {
  // Static method arrays (user_data needs to be set by caller)
  static libnngio_service_method transport_methods[4];
  static libnngio_service_method service_methods[4];
  
  // Initialize transport methods
  transport_methods[0] = (libnngio_service_method){"AddTransport", transport_add_handler, user_data};
  transport_methods[1] = (libnngio_service_method){"RemoveTransport", transport_remove_handler, user_data};
  transport_methods[2] = (libnngio_service_method){"ListTransports", transport_list_handler, user_data};
  transport_methods[3] = (libnngio_service_method){"GetTransport", transport_get_handler, user_data};
  
  // Initialize service methods
  service_methods[0] = (libnngio_service_method){"AddService", service_add_handler, user_data};
  service_methods[1] = (libnngio_service_method){"RemoveService", service_remove_handler, user_data};
  service_methods[2] = (libnngio_service_method){"ListServices", service_list_handler, user_data};
  service_methods[3] = (libnngio_service_method){"GetService", service_get_handler, user_data};
  
  // Static service descriptors
  static libnngio_module_service services[2];
  services[0] = (libnngio_module_service){"TransportManagement", transport_methods, 4};
  services[1] = (libnngio_module_service){"ServiceManagement", service_methods, 4};
  
  // Static module descriptor
  static libnngio_module_descriptor descriptor = {
    .module_name = "management",
    .protobuf_package = "LibnngioManagement",
    .services = services,
    .n_services = 2
  };
  
  return &descriptor;
}
