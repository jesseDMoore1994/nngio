# Management Module

The management module provides unified management of transport configurations, service configurations, and connections through three separate protobuf services exposed over an IPC transport.

## Architecture

The management module implements three separate protobuf services:

1. **TransportManagement**: Handle transport operations (add, remove, list, get)
2. **ServiceManagement**: Handle service operations (add, remove, list, get)
3. **ConnectionManagement**: Handle connection operations (add, remove, list, get)

## Default Configuration

When initialized, the management module sets up:

- **One transport**: "nngio-ipc" 
  - Type: IPC (Unix domain socket)
  - Mode: Listen (reply mode)
  - URL: `ipc:///tmp/libnngio_management.ipc`

- **Three management services**: Registered by default
  - TransportManagement server
  - ServiceManagement server
  - ConnectionManagement server

- **Three connections**: Linking the IPC transport to each management service

### Additional Services

The following services from the protobuf module can also be attached to the management IPC:
- **ServiceDiscoveryService**: For service discovery
- **RpcService**: For generic RPC calls

## Usage

### Basic Initialization

```c
#include "management/libnngio_management.h"

// Initialize management context
libnngio_management_context *ctx = NULL;
libnngio_management_error_code err = libnngio_management_init(&ctx);
if (err != LIBNNGIO_MANAGEMENT_ERR_NONE) {
    // Handle error
}

// Get the IPC URL
const char *url = libnngio_management_get_url(ctx);
printf("Management IPC URL: %s\n", url);

// Start the management server
err = libnngio_management_start(ctx);
if (err != LIBNNGIO_MANAGEMENT_ERR_NONE) {
    // Handle error
}

// ... server is now listening ...

// Stop the management server
err = libnngio_management_stop(ctx);

// Clean up
libnngio_management_free(ctx);
```

### Configuration Helpers

The module provides helper functions for creating configuration messages:

```c
// Create a transport configuration
LibnngioManagement__TransportConfig *transport_config =
    libnngio_management_create_transport_config(
        "my-transport", "listen", "rep", "ipc:///tmp/my.ipc");

// Create a service configuration
LibnngioManagement__ServiceConfig *service_config =
    libnngio_management_create_service_config(
        "my-service", "my-transport", "ServiceDiscoveryService");

// Create a connection configuration
LibnngioManagement__ConnectionConfig *connection_config =
    libnngio_management_create_connection_config(
        "my-connection", "my-transport", "my-service");

// Free configurations when done
libnngio_management_free_transport_config(transport_config);
libnngio_management_free_service_config(service_config);
libnngio_management_free_connection_config(connection_config);
```

## API Reference

### Error Codes

- `LIBNNGIO_MANAGEMENT_ERR_NONE`: No error
- `LIBNNGIO_MANAGEMENT_ERR_INVALID_PARAM`: Invalid parameter
- `LIBNNGIO_MANAGEMENT_ERR_NOT_FOUND`: Resource not found
- `LIBNNGIO_MANAGEMENT_ERR_ALREADY_EXISTS`: Resource already exists
- `LIBNNGIO_MANAGEMENT_ERR_INTERNAL`: Internal error
- `LIBNNGIO_MANAGEMENT_ERR_TRANSPORT`: Transport error
- `LIBNNGIO_MANAGEMENT_ERR_MEMORY`: Memory allocation error

### Core Functions

#### `libnngio_management_init`
Initialize a management context with default configuration.

```c
libnngio_management_error_code libnngio_management_init(
    libnngio_management_context **ctx);
```

#### `libnngio_management_free`
Free a management context and all associated resources.

```c
void libnngio_management_free(libnngio_management_context *ctx);
```

#### `libnngio_management_start`
Start the management server (begins listening on IPC transport).

```c
libnngio_management_error_code libnngio_management_start(
    libnngio_management_context *ctx);
```

#### `libnngio_management_stop`
Stop the management server.

```c
libnngio_management_error_code libnngio_management_stop(
    libnngio_management_context *ctx);
```

#### `libnngio_management_get_url`
Get the management IPC URL.

```c
const char *libnngio_management_get_url(libnngio_management_context *ctx);
```

## Protobuf Services

### TransportManagement Service

Methods:
- `AddTransport(AddTransportRequest) returns (AddTransportResponse)`
- `RemoveTransport(RemoveTransportRequest) returns (RemoveTransportResponse)`
- `ListTransports(ListTransportsRequest) returns (ListTransportsResponse)`
- `GetTransport(GetTransportRequest) returns (GetTransportResponse)`

### ServiceManagement Service

Methods:
- `AddService(AddServiceRequest) returns (AddServiceResponse)`
- `RemoveService(RemoveServiceRequest) returns (RemoveServiceResponse)`
- `ListServices(ListServicesRequest) returns (ListServicesResponse)`
- `GetService(GetServiceRequest) returns (GetServiceResponse)`

### ConnectionManagement Service

Methods:
- `AddConnection(AddConnectionRequest) returns (AddConnectionResponse)`
- `RemoveConnection(RemoveConnectionRequest) returns (RemoveConnectionResponse)`
- `ListConnections(ListConnectionsRequest) returns (ListConnectionsResponse)`
- `GetConnection(GetConnectionRequest) returns (GetConnectionResponse)`

## Building

The management module is built as part of the main nngio build process:

```bash
make proto  # Generate protobuf files
make all    # Build all libraries including management
make test   # Build and run tests
```

## Files

- `libnngio_management.proto`: Protobuf service and message definitions
- `include/management/libnngio_management.h`: Public API header
- `management/libnngio_management.c`: Implementation
- `test_management.c`: Test suite
- `README.md`: This file

## Testing

Run the management module tests:

```bash
./build/test_management
```

The tests verify:
- Management context initialization and cleanup
- Server start and stop
- Configuration helper functions
- Default service setup
