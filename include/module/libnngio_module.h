/**
 * @file libnngio_module.h
 * @brief Module interface for libnngio.
 *
 * This file defines a common interface that all libnngio modules should implement
 * to provide their services. Modules can register their services, methods, and
 * protobuf package information through this interface.
 */

#ifndef LIBNNGIO_MODULE_H
#define LIBNNGIO_MODULE_H

#include "protobuf/libnngio_protobuf.h"

/**
 * @brief Module service descriptor.
 * 
 * Describes a single service provided by a module, including its name
 * and the methods it implements.
 */
typedef struct {
  const char *service_name;              ///< Name of the service
  libnngio_service_method *methods;      ///< Array of methods for this service
  size_t n_methods;                      ///< Number of methods in the service
} libnngio_module_service;

/**
 * @brief Module descriptor.
 * 
 * Describes a module, including its protobuf package name and the services
 * it provides. Each module should define one of these structures.
 */
typedef struct {
  const char *module_name;               ///< Name of the module (e.g., "management", "protobuf")
  const char *protobuf_package;          ///< Protobuf package name (e.g., "LibnngioManagement")
  libnngio_module_service *services;     ///< Array of services provided by this module
  size_t n_services;                     ///< Number of services in the module
} libnngio_module_descriptor;

/**
 * @brief Register all services from a module with a server.
 * 
 * This function registers all services from a module descriptor with the given
 * server. It iterates through all services in the module and registers each one.
 *
 * @param server The server to register services with.
 * @param module The module descriptor containing services to register.
 * @return Error code indicating success or failure.
 */
libnngio_protobuf_error_code libnngio_module_register_services(
    libnngio_server *server,
    const libnngio_module_descriptor *module);

/**
 * @brief Get the module descriptor for a module.
 * 
 * Each module should implement a function that returns its module descriptor.
 * The function name should follow the pattern: libnngio_<module>_get_module_descriptor()
 * For example:
 *   - libnngio_management_get_module_descriptor()
 *   - libnngio_protobuf_get_module_descriptor()
 *
 * @return Pointer to the module descriptor.
 */
typedef const libnngio_module_descriptor* (*libnngio_module_get_descriptor_fn)(void);

#endif // LIBNNGIO_MODULE_H
