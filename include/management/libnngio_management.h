/**
 * @file libnngio_management.h
 * @brief Management API for libnngio.
 *
 * This module provides unified management of transport configurations,
 * protobuf configurations, connections, and protocols through four separate
 * protobuf services exposed over an IPC transport.
 *
 * The management interface includes:
 * - TransportManagement: Handle transport operations (add, remove, list, get)
 * - ProtobufManagement: Handle protobuf operations (add, remove, list, get)
 * - ConnectionManagement: Handle connection operations (add, remove, list, get)
 * - ProtocolManagement: Handle protocol operations (add, remove, list, get)
 *
 * Default Setup:
 * - One transport: "nngio-ipc" (IPC reply mode, "unix://libnngio_management")
 * - Four protobuf servers: one for each management service
 * - One protocol: "management"
 * - Four connections: linking nngio-ipc transport to each management service
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
 * @brief Internal storage for a protobuf server configuration.
 */
typedef struct {
  char *name;
  char *transport_name;
  libnngio_server *server;
} libnngio_management_protobuf_entry;

/**
 * @brief Internal storage for a connection configuration.
 */
typedef struct {
  char *name;
  char *transport_name;
  char *protobuf_name;
} libnngio_management_connection_entry;

/**
 * @brief Internal storage for a protocol configuration.
 */
typedef struct {
  char *name;
  char *description;
} libnngio_management_protocol_entry;

/**
 * @brief Initialize a management context with default configuration.
 *
 * Creates:
 * - One transport: "nngio-ipc" (IPC reply mode, "unix://libnngio_management")
 * - Four protobuf servers: one for each management service
 * - One protocol: "management"
 * - Four connections: linking nngio-ipc transport to each management service
 *
 * @param[out] ctx Pointer to receive allocated management context.
 * @return Error code indicating success or failure.
 */
libnngio_management_error_code libnngio_management_init(
    libnngio_management_context **ctx);

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
 * @brief Create a protobuf configuration message.
 *
 * @param name Protobuf server name.
 * @param transport_name Associated transport name.
 * @return Allocated ProtobufConfig message, or NULL on failure.
 */
LibnngioManagement__ProtobufConfig *libnngio_management_create_protobuf_config(
    const char *name, const char *transport_name);

/**
 * @brief Free a protobuf configuration message.
 *
 * @param config ProtobufConfig message to free.
 */
void libnngio_management_free_protobuf_config(
    LibnngioManagement__ProtobufConfig *config);

/**
 * @brief Create a connection configuration message.
 *
 * @param name Connection name.
 * @param transport_name Transport name.
 * @param protobuf_name Protobuf server name.
 * @return Allocated ConnectionConfig message, or NULL on failure.
 */
LibnngioManagement__ConnectionConfig *libnngio_management_create_connection_config(
    const char *name, const char *transport_name, const char *protobuf_name);

/**
 * @brief Free a connection configuration message.
 *
 * @param config ConnectionConfig message to free.
 */
void libnngio_management_free_connection_config(
    LibnngioManagement__ConnectionConfig *config);

/**
 * @brief Create a protocol configuration message.
 *
 * @param name Protocol name.
 * @param description Protocol description.
 * @return Allocated ProtocolConfig message, or NULL on failure.
 */
LibnngioManagement__ProtocolConfig *libnngio_management_create_protocol_config(
    const char *name, const char *description);

/**
 * @brief Free a protocol configuration message.
 *
 * @param config ProtocolConfig message to free.
 */
void libnngio_management_free_protocol_config(
    LibnngioManagement__ProtocolConfig *config);

#endif // LIBNNGIO_MANAGEMENT_H
