/**
 * @file libnngio_module.c
 * @brief Implementation of the module interface.
 */

#include "module/libnngio_module.h"
#include <stdlib.h>

libnngio_protobuf_error_code libnngio_module_register_services(
    libnngio_server *server,
    const libnngio_module_descriptor *module) {
  
  if (!server || !module) {
    return LIBNNGIO_PROTOBUF_ERR_INVALID_CONTEXT;
  }
  
  // Register each service from the module
  for (size_t i = 0; i < module->n_services; i++) {
    const libnngio_module_service *svc = &module->services[i];
    
    libnngio_protobuf_error_code rv = libnngio_server_register_service(
        server, svc->service_name, svc->methods, svc->n_methods);
    
    if (rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
      return rv;
    }
  }
  
  return LIBNNGIO_PROTOBUF_ERR_NONE;
}
