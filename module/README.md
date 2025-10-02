# Module Interface

The module interface provides a standardized way for libnngio modules to expose their services, making it easy to register them with a server.

## Overview

The module interface allows modules to define:
- **Module name**: A unique identifier for the module (e.g., "management", "protobuf")
- **Protobuf package**: The protobuf package name used by the module (e.g., "LibnngioManagement")
- **Services**: A list of services provided by the module, each with its methods and handlers

## Architecture

### Module Descriptor

A module descriptor (`libnngio_module_descriptor`) contains:
- Module name and protobuf package
- Array of services (`libnngio_module_service`)
- Each service contains an array of methods (`libnngio_service_method`)

### Service Registration

The interface provides `libnngio_module_register_services()` which registers all services from a module descriptor with a server in one call.

## Usage

### Implementing a Module

Each module should implement a function that returns its module descriptor:

```c
const libnngio_module_descriptor* libnngio_<module>_get_module_descriptor(void *user_data);
```

Example from the management module:

```c
const libnngio_module_descriptor* libnngio_management_get_module_descriptor(void *user_data) {
  // Define methods for each service
  static libnngio_service_method transport_methods[] = {
    {"AddTransport", transport_add_handler, user_data},
    {"RemoveTransport", transport_remove_handler, user_data},
    {"ListTransports", transport_list_handler, user_data},
    {"GetTransport", transport_get_handler, user_data}
  };
  
  // Define services
  static libnngio_module_service services[] = {
    {"TransportManagement", transport_methods, 4}
  };
  
  // Define module descriptor
  static libnngio_module_descriptor descriptor = {
    .module_name = "management",
    .protobuf_package = "LibnngioManagement",
    .services = services,
    .n_services = 1
  };
  
  return &descriptor;
}
```

### Registering Module Services

To register all services from a module with a server:

```c
// Get the module descriptor
const libnngio_module_descriptor *module = libnngio_management_get_module_descriptor(user_data);

// Register all services from the module
libnngio_protobuf_error_code rv = libnngio_module_register_services(server, module);
```

## Modules Using This Interface

### Management Module

Provides three services:
- **TransportManagement**: Transport configuration operations
- **ServiceManagement**: Service configuration operations  
- **ConnectionManagement**: Connection configuration operations

Package: `LibnngioManagement`

### Protobuf Module

Provides two services:
- **RpcService**: Generic RPC interface for calling any registered service method
- **ServiceDiscoveryService**: Service discovery to list all available services

Package: `LibnngioProtobuf`

## Example: Loading Multiple Modules

```c
// Initialize server
libnngio_server *server;
libnngio_server_init(&server, proto_ctx);

// Load management module services
const libnngio_module_descriptor *mgmt_module = 
    libnngio_management_get_module_descriptor(mgmt_context);
libnngio_module_register_services(server, mgmt_module);

// Load protobuf module services
const libnngio_module_descriptor *proto_module = 
    libnngio_protobuf_get_module_descriptor(server);
libnngio_module_register_services(server, proto_module);

// Now the server has all services from both modules registered
```

## Benefits

1. **Uniformity**: All modules expose their services in a consistent way
2. **Discoverability**: Easy to enumerate all available services from a module
3. **Flexibility**: Modules can be loaded dynamically
4. **Maintainability**: Clear separation between module interface and implementation
5. **Documentation**: Module descriptor serves as self-documenting API

## Files

- `include/module/libnngio_module.h`: Module interface API
- `module/libnngio_module.c`: Module registration implementation
- `README.md`: This file
