/**
 * @file libnngio_management.h
 * @brief Management API for libnngio.
 *
 * This module provides unified management of transport configurations,
 * service configurations, and connections through a single management server
 * with five protobuf services exposed over an IPC transport.
 *
 * The management interface includes:
 * - TransportManagement: Handle transport operations (add, remove, list, get)
 * - ServiceManagement: Handle service operations (add, remove, list, get)
 * - ConnectionManagement: Handle connection operations (add, remove, list, get)
 * - RpcService: Generic RPC call interface (from protobuf module)
 * - ServiceDiscoveryService: Service discovery interface (from protobuf module)
 *
 * Default Setup:
 * - One transport: "nngio-ipc" (IPC reply mode, "ipc:///tmp/libnngio_management.ipc")
 * - One management server with all five services registered
 * - Services are available through the management IPC transport
 */

#ifndef LIBNNGIO_MANAGEMENT_H
#define LIBNNGIO_MANAGEMENT_H

#include "protobuf/libnngio_protobuf.h"
#include "transport/libnngio_transport.h"
#include "libnngio_management.pb-c.h"

/**
 * @brief Error codes for management operations.
 */
typedef enum {
  LIBNNGIO_MANAGEMENT_ERR_NONE = 0,          ///< No error
  LIBNNGIO_MANAGEMENT_ERR_INVALID_PARAM = 1, ///< Invalid parameter
  LIBNNGIO_MANAGEMENT_ERR_NOT_FOUND = 2,     ///< Resource not found
  LIBNNGIO_MANAGEMENT_ERR_ALREADY_EXISTS = 3,///< Resource already exists
  LIBNNGIO_MANAGEMENT_ERR_INTERNAL = 4,      ///< Internal error
  LIBNNGIO_MANAGEMENT_ERR_TRANSPORT = 5,     ///< Transport error
  LIBNNGIO_MANAGEMENT_ERR_MEMORY = 6,        ///< Memory allocation error
} libnngio_management_error_code;

/**
 * @brief Opaque handle for the management context.
 */
typedef struct libnngio_management_context libnngio_management_context;

/**
 * @brief Internal storage for a transport configuration.
 */
typedef struct {
  char *name;
  libnngio_transport *transport;
  libnngio_context *context;
  libnngio_config config;
} libnngio_management_transport_entry;

/**
 * @brief Internal storage for a service configuration.
 */
typedef struct {
  char *name;
  char *transport_name;
  char *service_type;
  libnngio_server *server;
} libnngio_management_service_entry;

/**
 * @brief Initialize a management context with default configuration.
 *
 * Creates:
 * - One transport: "nngio-ipc" (IPC reply mode, "ipc:///tmp/libnngio_management.ipc")
 * - One management server with five registered services:
 *   * TransportManagement (management module)
 *   * ServiceManagement (management module)
 *   * ConnectionManagement (management module)
 *   * RpcService (protobuf module)
 *   * ServiceDiscoveryService (protobuf module)
 *
 * Mode Selection:
 * - If callback is NULL: Server operates in synchronous mode
 * - If callback is provided: Server operates in asynchronous mode with callback
 *
 * @param[out] ctx Pointer to receive allocated management context.
 * @param callback Optional callback for asynchronous mode (NULL for synchronous).
 * @return Error code indicating success or failure.
 */
libnngio_management_error_code libnngio_management_init(
    libnngio_management_context **ctx, libnngio_ctx_cb callback);

/**
 * @brief Free a management context and all associated resources.
 *
 * @param ctx Management context to free.
 */
void libnngio_management_free(libnngio_management_context *ctx);

/**
 * @brief Start the management server.
 *
 * Begins listening on the IPC transport and handling incoming requests.
 *
 * @param ctx Management context.
 * @return Error code indicating success or failure.
 */
libnngio_management_error_code libnngio_management_start(
    libnngio_management_context *ctx);

/**
 * @brief Stop the management server.
 *
 * @param ctx Management context.
 * @return Error code indicating success or failure.
 */
libnngio_management_error_code libnngio_management_stop(
    libnngio_management_context *ctx);

/**
 * @brief Get the management IPC URL.
 *
 * @param ctx Management context.
 * @return IPC URL string, or NULL if not initialized.
 */
const char *libnngio_management_get_url(libnngio_management_context *ctx);

/**
 * @brief Get the underlying management server instance.
 *
 * @param ctx Management context.
 * @return Pointer to the management server, or NULL if not initialized.
 */
libnngio_server *libnngio_management_get_server(libnngio_management_context *ctx);

/**
 * @brief Get the underlying management server instance.
 *
 * @param ctx Management context.
 * @return Pointer to the underlying transport context.
 */
libnngio_context *libnngio_management_get_transport_context(libnngio_management_context *ctx);

/**
 * @brief Register a module's services with the management server.
 * 
 * This function registers all services from a module descriptor with the management
 * server and adds them to the internal service tracking list. The services will be
 * available through the management IPC transport.
 *
 * @param ctx Management context.
 * @param module Module descriptor containing services to register.
 * @return Error code indicating success or failure.
 */
libnngio_management_error_code libnngio_management_register_module(
    libnngio_management_context *ctx,
    const struct libnngio_module_descriptor *module);

// =============================================================================
// Configuration Helper Functions
// =============================================================================

/**
 * @brief Create a transport configuration message.
 *
 * @param name Transport name.
 * @param mode Mode ("dial" or "listen").
 * @param protocol Protocol type.
 * @param url Transport URL.
 * @return Allocated TransportConfig message, or NULL on failure.
 */
LibnngioManagement__TransportConfig *libnngio_management_create_transport_config(
    const char *name, const char *mode, const char *protocol, const char *url);

/**
 * @brief Free a transport configuration message.
 *
 * @param config TransportConfig message to free.
 */
void libnngio_management_free_transport_config(
    LibnngioManagement__TransportConfig *config);

/**
 * @brief Create a service configuration message.
 *
 * @param name Service name.
 * @param transport_name Associated transport name.
 * @param service_type Type of service.
 * @return Allocated ServiceConfig message, or NULL on failure.
 */
LibnngioManagement__ServiceConfig *libnngio_management_create_service_config(
    const char *name, const char *transport_name, const char *service_type);

/**
 * @brief Free a service configuration message.
 *
 * @param config ServiceConfig message to free.
 */
void libnngio_management_free_service_config(
    LibnngioManagement__ServiceConfig *config);

// =============================================================================
// Module Interface
// =============================================================================

/**
 * @brief Get the module descriptor for the management module.
 * 
 * Returns a descriptor that describes the management module's services, methods,
 * and protobuf package. This can be used to register the module's services with
 * a server using the module interface.
 *
 * @param user_data User data to pass to all handler functions (typically the management context)
 * @return Pointer to the module descriptor.
 */
const libnngio_module_descriptor* libnngio_management_get_module_descriptor(void *user_data);

#endif // LIBNNGIO_MANAGEMENT_H
