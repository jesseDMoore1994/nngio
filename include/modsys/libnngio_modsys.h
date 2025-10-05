/**
 * @file libnngio_modsys.h
 * @brief Module system for libnngio.
 *
 * This module provides a centralized system for managing modules and their
 * lifecycles. It handles module registration, unregistration, and automatic
 * service registration with servers.
 *
 * The module system operates at the module level rather than individual services,
 * improving extensibility and maintainability.
 */

#ifndef LIBNNGIO_MODSYS_H
#define LIBNNGIO_MODSYS_H

#include "protobuf/libnngio_protobuf.h"

/**
 * @brief Error codes for module system operations.
 */
typedef enum {
  LIBNNGIO_MODSYS_ERR_NONE = 0,          ///< No error
  LIBNNGIO_MODSYS_ERR_INVALID_PARAM = 1, ///< Invalid parameter
  LIBNNGIO_MODSYS_ERR_NOT_FOUND = 2,     ///< Module not found
  LIBNNGIO_MODSYS_ERR_ALREADY_EXISTS = 3,///< Module already exists
  LIBNNGIO_MODSYS_ERR_INTERNAL = 4,      ///< Internal error
  LIBNNGIO_MODSYS_ERR_MEMORY = 5,        ///< Memory allocation error
} libnngio_modsys_error_code;

/**
 * @brief Opaque handle for the module system context.
 */
typedef struct libnngio_modsys_context libnngio_modsys_context;

/**
 * @brief Module entry tracking structure.
 * 
 * This structure tracks a registered module and its association with a server.
 */
typedef struct {
  const libnngio_module_descriptor *descriptor; ///< Module descriptor
  libnngio_server *server;                       ///< Associated server
  char *transport_name;                          ///< Transport name for services
} libnngio_modsys_module_entry;

// =============================================================================
// Core Module System Functions
// =============================================================================

/**
 * @brief Initialize a module system context.
 *
 * Creates a new module system context for tracking and managing modules.
 *
 * @param[out] ctx Pointer to receive allocated module system context.
 * @return Error code indicating success or failure.
 */
libnngio_modsys_error_code libnngio_modsys_init(
    libnngio_modsys_context **ctx);

/**
 * @brief Free a module system context and all associated resources.
 *
 * @param ctx Module system context to free.
 */
void libnngio_modsys_free(libnngio_modsys_context *ctx);

/**
 * @brief Register a module with the module system.
 *
 * This function registers a module descriptor with the module system and
 * automatically registers all of the module's services with the provided server.
 *
 * @param ctx Module system context.
 * @param module Module descriptor to register.
 * @param server Server to register the module's services with.
 * @param transport_name Transport name for service tracking.
 * @return Error code indicating success or failure.
 */
libnngio_modsys_error_code libnngio_modsys_register_module(
    libnngio_modsys_context *ctx,
    const libnngio_module_descriptor *module,
    libnngio_server *server,
    const char *transport_name);

/**
 * @brief Unregister a module from the module system.
 *
 * This function unregisters a module and automatically unregisters all of
 * the module's services from the associated server.
 *
 * @param ctx Module system context.
 * @param module_name Name of the module to unregister.
 * @return Error code indicating success or failure.
 */
libnngio_modsys_error_code libnngio_modsys_unregister_module(
    libnngio_modsys_context *ctx,
    const char *module_name);

/**
 * @brief Get the number of registered modules.
 *
 * @param ctx Module system context.
 * @return Number of registered modules, or 0 if ctx is NULL.
 */
size_t libnngio_modsys_get_module_count(libnngio_modsys_context *ctx);

/**
 * @brief Get a module entry by index.
 *
 * @param ctx Module system context.
 * @param index Index of the module entry to retrieve.
 * @return Pointer to the module entry, or NULL if index is out of bounds.
 */
const libnngio_modsys_module_entry *libnngio_modsys_get_module(
    libnngio_modsys_context *ctx,
    size_t index);

/**
 * @brief Find a module by name.
 *
 * @param ctx Module system context.
 * @param module_name Name of the module to find.
 * @return Pointer to the module entry, or NULL if not found.
 */
const libnngio_modsys_module_entry *libnngio_modsys_find_module(
    libnngio_modsys_context *ctx,
    const char *module_name);

#endif // LIBNNGIO_MODSYS_H
