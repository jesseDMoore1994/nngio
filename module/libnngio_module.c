/**
 * @file libnngio_module.c
 * @brief Implementation of the module interface.
 */

#include "module/libnngio_module.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

libnngio_protobuf_error_code libnngio_module_register_services(
    libnngio_server *server,
    const libnngio_module_descriptor *module) {
  
  if (!server || !module) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }
  
  // Register each service from the module with package-prefixed name
  for (size_t i = 0; i < module->n_services; i++) {
    const libnngio_module_service *svc = &module->services[i];
    
    // Create prefixed service name: "Package.ServiceName"
    size_t prefix_len = strlen(module->protobuf_package) + strlen(svc->service_name) + 2; // +2 for '.' and '\0'
    char *prefixed_name = malloc(prefix_len);
    if (!prefixed_name) {
      return LIBNNGIO_PROTOBUF_ERR_INTERNAL_ERROR;
    }
    snprintf(prefixed_name, prefix_len, "%s.%s", module->protobuf_package, svc->service_name);
    
    libnngio_protobuf_error_code rv = libnngio_server_register_service(
        server, prefixed_name, svc->methods, svc->n_methods);
    
    free(prefixed_name);
    
    if (rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
      return rv;
    }
  }
  
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}
