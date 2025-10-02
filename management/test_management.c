/**
 * @file test_management.c
 * @brief Test file for management module.
 *
 * This test demonstrates the initialization and basic usage of the
 * management module.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nng/nng.h>
#include "management/libnngio_management.h"
#include "protobuf/libnngio_protobuf.h"
#include "transport/libnngio_transport.h"
#include "management/libnngio_management.pb-c.h"

/**
 * @brief Test management context initialization and cleanup.
 */
void test_management_init_free() {
  libnngio_log("INF", "TEST_MANAGEMENT_INIT_FREE", __FILE__, __LINE__, -1,
               "Testing management context initialization and cleanup");
  
  libnngio_management_context *ctx = NULL;
  libnngio_management_error_code err = libnngio_management_init(&ctx);
  
  assert(err == LIBNNGIO_MANAGEMENT_ERR_NONE);
  assert(ctx != NULL);
  
  libnngio_log("INF", "TEST_MANAGEMENT_INIT_FREE", __FILE__, __LINE__, -1,
               "Management context initialized successfully");
  
  const char *url = libnngio_management_get_url(ctx);
  assert(url != NULL);
  libnngio_log("INF", "TEST_MANAGEMENT_INIT_FREE", __FILE__, __LINE__, -1,
               "Management IPC URL: %s", url);
  
  libnngio_management_free(ctx);
  libnngio_log("INF", "TEST_MANAGEMENT_INIT_FREE", __FILE__, __LINE__, -1,
               "Management context freed successfully");
}

/**
 * @brief Test management context start and stop.
 */
void test_management_start_stop() {
  libnngio_log("INF", "TEST_MANAGEMENT_START_STOP", __FILE__, __LINE__, -1,
               "Testing management server start and stop");
  
  libnngio_management_context *ctx = NULL;
  libnngio_management_error_code err = libnngio_management_init(&ctx);
  assert(err == LIBNNGIO_MANAGEMENT_ERR_NONE);
  
  err = libnngio_management_start(ctx);
  assert(err == LIBNNGIO_MANAGEMENT_ERR_NONE);
  libnngio_log("INF", "TEST_MANAGEMENT_START_STOP", __FILE__, __LINE__, -1,
               "Management server started successfully");
  
  err = libnngio_management_stop(ctx);
  assert(err == LIBNNGIO_MANAGEMENT_ERR_NONE);
  libnngio_log("INF", "TEST_MANAGEMENT_START_STOP", __FILE__, __LINE__, -1,
               "Management server stopped successfully");
  
  libnngio_management_free(ctx);
}

/**
 * @brief Test transport configuration helper functions.
 */
void test_transport_config_helpers() {
  libnngio_log("INF", "TEST_TRANSPORT_CONFIG_HELPERS", __FILE__, __LINE__, -1,
               "Testing transport configuration helper functions");
  
  LibnngioManagement__TransportConfig *config =
      libnngio_management_create_transport_config(
          "test-transport", "listen", "rep", "ipc:///tmp/test.ipc");
  
  assert(config != NULL);
  assert(strcmp(config->name, "test-transport") == 0);
  assert(strcmp(config->mode, "listen") == 0);
  assert(strcmp(config->protocol, "rep") == 0);
  assert(strcmp(config->url, "ipc:///tmp/test.ipc") == 0);
  
  libnngio_log("INF", "TEST_TRANSPORT_CONFIG_HELPERS", __FILE__, __LINE__, -1,
               "Transport config created: name=%s, mode=%s, protocol=%s, url=%s",
               config->name, config->mode, config->protocol, config->url);
  
  libnngio_management_free_transport_config(config);
  libnngio_log("INF", "TEST_TRANSPORT_CONFIG_HELPERS", __FILE__, __LINE__, -1,
               "Transport configuration freed successfully");
}

/**
 * @brief Test service configuration helper functions.
 */
void test_service_config_helpers() {
  libnngio_log("INF", "TEST_SERVICE_CONFIG_HELPERS", __FILE__, __LINE__, -1,
               "Testing service configuration helper functions");
  
  LibnngioManagement__ServiceConfig *config =
      libnngio_management_create_service_config(
          "test-service", "test-transport", "TransportManagement");
  
  assert(config != NULL);
  assert(strcmp(config->name, "test-service") == 0);
  assert(strcmp(config->transport_name, "test-transport") == 0);
  assert(strcmp(config->service_type, "TransportManagement") == 0);
  
  libnngio_log("INF", "TEST_SERVICE_CONFIG_HELPERS", __FILE__, __LINE__, -1,
               "Service config created: name=%s, transport=%s, type=%s",
               config->name, config->transport_name, config->service_type);
  
  libnngio_management_free_service_config(config);
  libnngio_log("INF", "TEST_SERVICE_CONFIG_HELPERS", __FILE__, __LINE__, -1,
               "Service configuration freed successfully");
}

/**
 * @brief Test connection configuration helper functions.
 */
void test_connection_config_helpers() {
  libnngio_log("INF", "TEST_CONNECTION_CONFIG_HELPERS", __FILE__, __LINE__, -1,
               "Testing connection configuration helper functions");
  
  LibnngioManagement__ConnectionConfig *config =
      libnngio_management_create_connection_config(
          "test-connection", "test-transport", "test-service");
  
  assert(config != NULL);
  assert(strcmp(config->name, "test-connection") == 0);
  assert(strcmp(config->transport_name, "test-transport") == 0);
  assert(strcmp(config->service_name, "test-service") == 0);
  
  libnngio_log("INF", "TEST_CONNECTION_CONFIG_HELPERS", __FILE__, __LINE__, -1,
               "Connection config created: name=%s, transport=%s, service=%s",
               config->name, config->transport_name, config->service_name);
  
  libnngio_management_free_connection_config(config);
  libnngio_log("INF", "TEST_CONNECTION_CONFIG_HELPERS", __FILE__, __LINE__, -1,
               "Connection configuration freed successfully");
}

/**
 * @brief Test service discovery with management server and client.
 * 
 * This test creates a management server, starts it, then creates a client
 * that connects to the server and performs service discovery to list all
 * available services.
 */
void test_service_discovery() {
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "========================================");
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "Testing service discovery with management server and client");
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "========================================");
  
  // Initialize and start management server
  libnngio_management_context *server_ctx = NULL;
  libnngio_management_error_code err = libnngio_management_init(&server_ctx);
  assert(err == LIBNNGIO_MANAGEMENT_ERR_NONE);
  assert(server_ctx != NULL);
  
  err = libnngio_management_start(server_ctx);
  assert(err == LIBNNGIO_MANAGEMENT_ERR_NONE);
  
  const char *url = libnngio_management_get_url(server_ctx);
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "Management server started at: %s", url);
  
  // Small delay to ensure server is ready
  nng_msleep(100);
  
  // Create client transport and context
  libnngio_config client_config = {
    .mode = LIBNNGIO_MODE_DIAL,
    .proto = LIBNNGIO_PROTO_REQ,
    .url = url,
    .tls_cert = NULL,
    .tls_key = NULL,
    .tls_ca_cert = NULL,
    .recv_timeout_ms = 5000,
    .send_timeout_ms = 5000,
    .max_msg_size = 0,
    .n_options = 0,
    .options = NULL
  };
  
  libnngio_transport *client_transport = NULL;
  int rv = libnngio_transport_init(&client_transport, &client_config);
  assert(rv == 0);
  
  libnngio_context *client_ctx = NULL;
  rv = libnngio_context_init(&client_ctx, client_transport, &client_config, NULL, NULL);
  assert(rv == 0);
  
  libnngio_protobuf_context *client_proto_ctx = NULL;
  libnngio_protobuf_error_code proto_rv = 
      libnngio_protobuf_context_init(&client_proto_ctx, client_ctx);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
  
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "Client created and connected to management server");
  
  // Start client context
  libnngio_context_start(client_ctx);
  
  // Small delay to ensure connection is established
  nng_msleep(100);
  
  // Create service discovery request (empty request)
  LibnngioProtobuf__ServiceDiscoveryRequest *request = 
      malloc(sizeof(LibnngioProtobuf__ServiceDiscoveryRequest));
  assert(request != NULL);
  libnngio_protobuf__service_discovery_request__init(request);
  
  // Send service discovery request to LibnngioProtobuf.ServiceDiscoveryService
  LibnngioProtobuf__ServiceDiscoveryResponse *response = NULL;
  proto_rv = libnngio_protobuf_send_service_discovery_request(
      client_proto_ctx, request, &response);
  
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "Service discovery request sent, result: %d", proto_rv);
  
  if (proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE && response != NULL) {
    libnngio_log("INF", "TEST_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
                 "Service discovery succeeded! Found %zu services:", response->n_services);
    
    // Verify we have the expected 5 services with prefixed names
    assert(response->n_services == 5);
    
    // Log all discovered services
    for (size_t i = 0; i < response->n_services; i++) {
      LibnngioProtobuf__Service *svc = response->services[i];
      libnngio_log("INF", "TEST_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
                   "  Service %zu: %s", i + 1, svc->name);
      libnngio_log("INF", "TEST_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
                   "    Methods: %zu", svc->n_methods);
      for (size_t j = 0; j < svc->n_methods; j++) {
        libnngio_log("INF", "TEST_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
                     "      - %s", svc->methods[j]);
      }
    }
    
    // Verify service names are prefixed correctly
    int found_transport_mgmt = 0;
    int found_service_mgmt = 0;
    int found_connection_mgmt = 0;
    int found_rpc_service = 0;
    int found_discovery_service = 0;
    
    for (size_t i = 0; i < response->n_services; i++) {
      LibnngioProtobuf__Service *svc = response->services[i];
      if (strcmp(svc->name, "LibnngioManagement.TransportManagement") == 0) {
        found_transport_mgmt = 1;
        assert(svc->n_methods == 4); // Add, Remove, List, Get
      } else if (strcmp(svc->name, "LibnngioManagement.ServiceManagement") == 0) {
        found_service_mgmt = 1;
        assert(svc->n_methods == 4);
      } else if (strcmp(svc->name, "LibnngioManagement.ConnectionManagement") == 0) {
        found_connection_mgmt = 1;
        assert(svc->n_methods == 4);
      } else if (strcmp(svc->name, "LibnngioProtobuf.RpcService") == 0) {
        found_rpc_service = 1;
        assert(svc->n_methods == 1); // CallRpc
      } else if (strcmp(svc->name, "LibnngioProtobuf.ServiceDiscoveryService") == 0) {
        found_discovery_service = 1;
        assert(svc->n_methods == 1); // GetServices
      }
    }
    
    assert(found_transport_mgmt == 1);
    assert(found_service_mgmt == 1);
    assert(found_connection_mgmt == 1);
    assert(found_rpc_service == 1);
    assert(found_discovery_service == 1);
    
    libnngio_log("INF", "TEST_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
                 "All expected services found with correct prefixes!");
    
    // Free response
    nngio_free_service_discovery_response(response);
  } else {
    libnngio_log("ERR", "TEST_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
                 "Service discovery failed with error: %d", proto_rv);
    assert(0); // Fail the test
  }
  
  // Free request
  free(request);
  
  // Clean up client
  libnngio_protobuf_context_free(client_proto_ctx);
  libnngio_context_free(client_ctx);
  libnngio_transport_free(client_transport);
  
  // Clean up server
  libnngio_management_stop(server_ctx);
  libnngio_management_free(server_ctx);
  
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "========================================");
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "Service discovery test completed successfully!");
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "========================================");
}

/**
 * @brief Structure for async test synchronization.
 */
typedef struct {
  int completed;
  int result;
  void *response;
} async_test_state;

/**
 * @brief Async callback for service discovery response.
 */
void async_service_discovery_cb(libnngio_protobuf_context *ctx, int result,
                                 LibnngioProtobuf__ServiceDiscoveryResponse *response,
                                 void *user_data) {
  async_test_state *state = (async_test_state *)user_data;
  state->completed = 1;
  state->result = result;
  state->response = response;
  
  libnngio_log("INF", "ASYNC_SERVICE_DISCOVERY_CB", __FILE__, __LINE__, -1,
               "Async callback invoked with result: %d", result);
}

/**
 * @brief Test async service discovery with management server and client.
 */
void test_service_discovery_async() {
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__, -1,
               "========================================");
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__, -1,
               "Testing async service discovery");
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__, -1,
               "========================================");
  
  // Initialize and start management server
  libnngio_management_context *server_ctx = NULL;
  libnngio_management_error_code err = libnngio_management_init(&server_ctx);
  assert(err == LIBNNGIO_MANAGEMENT_ERR_NONE);
  
  err = libnngio_management_start(server_ctx);
  assert(err == LIBNNGIO_MANAGEMENT_ERR_NONE);
  
  const char *url = libnngio_management_get_url(server_ctx);
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__, -1,
               "Management server started at: %s", url);
  
  nng_msleep(100);
  
  // Create client
  libnngio_config client_config = {
    .mode = LIBNNGIO_MODE_DIAL,
    .proto = LIBNNGIO_PROTO_REQ,
    .url = url,
    .tls_cert = NULL,
    .tls_key = NULL,
    .tls_ca_cert = NULL,
    .recv_timeout_ms = 5000,
    .send_timeout_ms = 5000,
    .max_msg_size = 0,
    .n_options = 0,
    .options = NULL
  };
  
  libnngio_transport *client_transport = NULL;
  int rv = libnngio_transport_init(&client_transport, &client_config);
  assert(rv == 0);
  
  libnngio_context *client_ctx = NULL;
  rv = libnngio_context_init(&client_ctx, client_transport, &client_config, NULL, NULL);
  assert(rv == 0);
  
  libnngio_protobuf_context *client_proto_ctx = NULL;
  libnngio_protobuf_error_code proto_rv = 
      libnngio_protobuf_context_init(&client_proto_ctx, client_ctx);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
  
  libnngio_context_start(client_ctx);
  nng_msleep(100);
  
  // Create service discovery request
  LibnngioProtobuf__ServiceDiscoveryRequest *request = 
      malloc(sizeof(LibnngioProtobuf__ServiceDiscoveryRequest));
  assert(request != NULL);
  libnngio_protobuf__service_discovery_request__init(request);
  
  // Prepare async state
  async_test_state state = {0, 0, NULL};
  
  // Send async service discovery request
  libnngio_protobuf_recv_cb_info cb_info = {
    .user_cb = (libnngio_protobuf_recv_async_cb)async_service_discovery_cb,
    .user_data = &state
  };
  
  proto_rv = libnngio_protobuf_send_service_discovery_request_async(
      client_proto_ctx, request, cb_info);
  
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__, -1,
               "Async service discovery request sent, waiting for response...");
  
  // Wait for async callback
  int max_wait = 50; // 5 seconds max
  while (!state.completed && max_wait > 0) {
    nng_msleep(100);
    max_wait--;
  }
  
  assert(state.completed == 1);
  assert(state.result == LIBNNGIO_PROTOBUF_ERR_NONE);
  assert(state.response != NULL);
  
  LibnngioProtobuf__ServiceDiscoveryResponse *response = 
      (LibnngioProtobuf__ServiceDiscoveryResponse *)state.response;
  
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__, -1,
               "Async service discovery succeeded! Found %zu services", 
               response->n_services);
  
  // Verify all 5 services
  assert(response->n_services == 5);
  
  for (size_t i = 0; i < response->n_services; i++) {
    LibnngioProtobuf__Service *svc = response->services[i];
    libnngio_log("INF", "TEST_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__, -1,
                 "  Service %zu: %s (%zu methods)", i + 1, svc->name, svc->n_methods);
  }
  
  // Cleanup
  nngio_free_service_discovery_response(response);
  free(request);
  libnngio_protobuf_context_free(client_proto_ctx);
  libnngio_context_free(client_ctx);
  libnngio_transport_free(client_transport);
  libnngio_management_stop(server_ctx);
  libnngio_management_free(server_ctx);
  
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__, -1,
               "========================================");
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__, -1,
               "Async service discovery test completed!");
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__, -1,
               "========================================");
}

/**
 * @brief Async callback for RPC response.
 */
void async_rpc_response_cb(libnngio_protobuf_context *ctx, int result,
                           LibnngioProtobuf__RpcResponse *response,
                           void *user_data) {
  async_test_state *state = (async_test_state *)user_data;
  state->completed = 1;
  state->result = result;
  state->response = response;
  
  libnngio_log("INF", "ASYNC_RPC_RESPONSE_CB", __FILE__, __LINE__, -1,
               "Async RPC callback invoked with result: %d", result);
}

/**
 * @brief Test using RPC service to invoke discovered services synchronously.
 */
void test_rpc_service_invoke_sync() {
  libnngio_log("INF", "TEST_RPC_SERVICE_INVOKE_SYNC", __FILE__, __LINE__, -1,
               "========================================");
  libnngio_log("INF", "TEST_RPC_SERVICE_INVOKE_SYNC", __FILE__, __LINE__, -1,
               "Testing RPC service to invoke discovered services (sync)");
  libnngio_log("INF", "TEST_RPC_SERVICE_INVOKE_SYNC", __FILE__, __LINE__, -1,
               "========================================");
  
  // Initialize and start management server
  libnngio_management_context *server_ctx = NULL;
  libnngio_management_error_code err = libnngio_management_init(&server_ctx);
  assert(err == LIBNNGIO_MANAGEMENT_ERR_NONE);
  
  err = libnngio_management_start(server_ctx);
  assert(err == LIBNNGIO_MANAGEMENT_ERR_NONE);
  
  const char *url = libnngio_management_get_url(server_ctx);
  nng_msleep(100);
  
  // Create client
  libnngio_config client_config = {
    .mode = LIBNNGIO_MODE_DIAL,
    .proto = LIBNNGIO_PROTO_REQ,
    .url = url,
    .tls_cert = NULL,
    .tls_key = NULL,
    .tls_ca_cert = NULL,
    .recv_timeout_ms = 5000,
    .send_timeout_ms = 5000,
    .max_msg_size = 0,
    .n_options = 0,
    .options = NULL
  };
  
  libnngio_transport *client_transport = NULL;
  int rv = libnngio_transport_init(&client_transport, &client_config);
  assert(rv == 0);
  
  libnngio_context *client_ctx = NULL;
  rv = libnngio_context_init(&client_ctx, client_transport, &client_config, NULL, NULL);
  assert(rv == 0);
  
  libnngio_protobuf_context *client_proto_ctx = NULL;
  libnngio_protobuf_error_code proto_rv = 
      libnngio_protobuf_context_init(&client_proto_ctx, client_ctx);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
  
  libnngio_context_start(client_ctx);
  nng_msleep(100);
  
  // Create RPC request to invoke TransportManagement.List method
  LibnngioManagement__ListTransportsRequest list_req = 
      LIBNNGIO_MANAGEMENT__LIST_TRANSPORTS_REQUEST__INIT;
  
  size_t payload_len = libnngio_management__list_transports_request__get_packed_size(&list_req);
  void *payload = malloc(payload_len);
  libnngio_management__list_transports_request__pack(&list_req, payload);
  
  LibnngioProtobuf__RpcRequest *rpc_request = 
      nngio_create_rpc_request(
          "LibnngioManagement.TransportManagement",
          "List",
          payload,
          payload_len);
  
  free(payload);
  
  libnngio_log("INF", "TEST_RPC_SERVICE_INVOKE_SYNC", __FILE__, __LINE__, -1,
               "Invoking %s.%s via RPC service", 
               rpc_request->service_name, rpc_request->method_name);
  
  // Send RPC request
  LibnngioProtobuf__RpcResponse *rpc_response = NULL;
  proto_rv = libnngio_protobuf_send_rpc_request(client_proto_ctx, rpc_request, &rpc_response);
  
  if (proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE && rpc_response != NULL) {
    libnngio_log("INF", "TEST_RPC_SERVICE_INVOKE_SYNC", __FILE__, __LINE__, -1,
                 "RPC call succeeded! Status: %d", rpc_response->status);
    
    // The response payload should contain LibnngioManagement__ListTransportsResponse
    if (rpc_response->status == LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success) {
      LibnngioManagement__ListTransportsResponse *list_resp =
          libnngio_management__list_transports_response__unpack(
              NULL, rpc_response->payload.len, rpc_response->payload.data);
      
      if (list_resp != NULL) {
        libnngio_log("INF", "TEST_RPC_SERVICE_INVOKE_SYNC", __FILE__, __LINE__, -1,
                     "Found %zu transports", list_resp->n_transports);
        
        // We expect at least the management IPC transport
        assert(list_resp->n_transports >= 1);
        
        for (size_t i = 0; i < list_resp->n_transports; i++) {
          libnngio_log("INF", "TEST_RPC_SERVICE_INVOKE_SYNC", __FILE__, __LINE__, -1,
                       "  Transport %zu: %s", i + 1, list_resp->transports[i]->name);
        }
        
        libnngio_management__list_transports_response__free_unpacked(list_resp, NULL);
      }
    }
    
    nngio_free_rpc_response(rpc_response);
  } else {
    libnngio_log("ERR", "TEST_RPC_SERVICE_INVOKE_SYNC", __FILE__, __LINE__, -1,
                 "RPC call failed with error: %d", proto_rv);
    assert(0);
  }
  
  nngio_free_rpc_request(rpc_request);
  
  // Cleanup
  libnngio_protobuf_context_free(client_proto_ctx);
  libnngio_context_free(client_ctx);
  libnngio_transport_free(client_transport);
  libnngio_management_stop(server_ctx);
  libnngio_management_free(server_ctx);
  
  libnngio_log("INF", "TEST_RPC_SERVICE_INVOKE_SYNC", __FILE__, __LINE__, -1,
               "========================================");
  libnngio_log("INF", "TEST_RPC_SERVICE_INVOKE_SYNC", __FILE__, __LINE__, -1,
               "Sync RPC service invoke test completed!");
  libnngio_log("INF", "TEST_RPC_SERVICE_INVOKE_SYNC", __FILE__, __LINE__, -1,
               "========================================");
}

/**
 * @brief Test using RPC service to invoke discovered services asynchronously.
 */
void test_rpc_service_invoke_async() {
  libnngio_log("INF", "TEST_RPC_SERVICE_INVOKE_ASYNC", __FILE__, __LINE__, -1,
               "========================================");
  libnngio_log("INF", "TEST_RPC_SERVICE_INVOKE_ASYNC", __FILE__, __LINE__, -1,
               "Testing RPC service to invoke discovered services (async)");
  libnngio_log("INF", "TEST_RPC_SERVICE_INVOKE_ASYNC", __FILE__, __LINE__, -1,
               "========================================");
  
  // Initialize and start management server
  libnngio_management_context *server_ctx = NULL;
  libnngio_management_error_code err = libnngio_management_init(&server_ctx);
  assert(err == LIBNNGIO_MANAGEMENT_ERR_NONE);
  
  err = libnngio_management_start(server_ctx);
  assert(err == LIBNNGIO_MANAGEMENT_ERR_NONE);
  
  const char *url = libnngio_management_get_url(server_ctx);
  nng_msleep(100);
  
  // Create client
  libnngio_config client_config = {
    .mode = LIBNNGIO_MODE_DIAL,
    .proto = LIBNNGIO_PROTO_REQ,
    .url = url,
    .tls_cert = NULL,
    .tls_key = NULL,
    .tls_ca_cert = NULL,
    .recv_timeout_ms = 5000,
    .send_timeout_ms = 5000,
    .max_msg_size = 0,
    .n_options = 0,
    .options = NULL
  };
  
  libnngio_transport *client_transport = NULL;
  int rv = libnngio_transport_init(&client_transport, &client_config);
  assert(rv == 0);
  
  libnngio_context *client_ctx = NULL;
  rv = libnngio_context_init(&client_ctx, client_transport, &client_config, NULL, NULL);
  assert(rv == 0);
  
  libnngio_protobuf_context *client_proto_ctx = NULL;
  libnngio_protobuf_error_code proto_rv = 
      libnngio_protobuf_context_init(&client_proto_ctx, client_ctx);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
  
  libnngio_context_start(client_ctx);
  nng_msleep(100);
  
  // Create RPC request to invoke ServiceManagement.List method
  LibnngioManagement__ListServicesRequest list_req = 
      LIBNNGIO_MANAGEMENT__LIST_SERVICES_REQUEST__INIT;
  
  size_t payload_len = libnngio_management__list_services_request__get_packed_size(&list_req);
  void *payload = malloc(payload_len);
  libnngio_management__list_services_request__pack(&list_req, payload);
  
  LibnngioProtobuf__RpcRequest *rpc_request = 
      nngio_create_rpc_request(
          "LibnngioManagement.ServiceManagement",
          "List",
          payload,
          payload_len);
  
  free(payload);
  
  libnngio_log("INF", "TEST_RPC_SERVICE_INVOKE_ASYNC", __FILE__, __LINE__, -1,
               "Invoking %s.%s via RPC service (async)", 
               rpc_request->service_name, rpc_request->method_name);
  
  // Prepare async state
  async_test_state state = {0, 0, NULL};
  
  // Send async RPC request
  libnngio_protobuf_recv_cb_info cb_info = {
    .user_cb = (libnngio_protobuf_recv_async_cb)async_rpc_response_cb,
    .user_data = &state
  };
  
  proto_rv = libnngio_protobuf_send_rpc_request_async(
      client_proto_ctx, rpc_request, cb_info);
  
  libnngio_log("INF", "TEST_RPC_SERVICE_INVOKE_ASYNC", __FILE__, __LINE__, -1,
               "Async RPC request sent, waiting for response...");
  
  // Wait for async callback
  int max_wait = 50;
  while (!state.completed && max_wait > 0) {
    nng_msleep(100);
    max_wait--;
  }
  
  assert(state.completed == 1);
  assert(state.result == LIBNNGIO_PROTOBUF_ERR_NONE);
  assert(state.response != NULL);
  
  LibnngioProtobuf__RpcResponse *rpc_response = 
      (LibnngioProtobuf__RpcResponse *)state.response;
  
  libnngio_log("INF", "TEST_RPC_SERVICE_INVOKE_ASYNC", __FILE__, __LINE__, -1,
               "Async RPC call succeeded! Status: %d", rpc_response->status);
  
  if (rpc_response->status == LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success) {
    LibnngioManagement__ListServicesResponse *list_resp =
        libnngio_management__list_services_response__unpack(
            NULL, rpc_response->payload.len, rpc_response->payload.data);
    
    if (list_resp != NULL) {
      libnngio_log("INF", "TEST_RPC_SERVICE_INVOKE_ASYNC", __FILE__, __LINE__, -1,
                   "Found %zu services", list_resp->n_services);
      
      // We expect all 5 services
      assert(list_resp->n_services == 5);
      
      for (size_t i = 0; i < list_resp->n_services; i++) {
        libnngio_log("INF", "TEST_RPC_SERVICE_INVOKE_ASYNC", __FILE__, __LINE__, -1,
                     "  Service %zu: %s (type: %s)", 
                     i + 1, 
                     list_resp->services[i]->name,
                     list_resp->services[i]->service_type);
      }
      
      libnngio_management__list_services_response__free_unpacked(list_resp, NULL);
    }
  }
  
  nngio_free_rpc_response(rpc_response);
  nngio_free_rpc_request(rpc_request);
  
  // Cleanup
  libnngio_protobuf_context_free(client_proto_ctx);
  libnngio_context_free(client_ctx);
  libnngio_transport_free(client_transport);
  libnngio_management_stop(server_ctx);
  libnngio_management_free(server_ctx);
  
  libnngio_log("INF", "TEST_RPC_SERVICE_INVOKE_ASYNC", __FILE__, __LINE__, -1,
               "========================================");
  libnngio_log("INF", "TEST_RPC_SERVICE_INVOKE_ASYNC", __FILE__, __LINE__, -1,
               "Async RPC service invoke test completed!");
  libnngio_log("INF", "TEST_RPC_SERVICE_INVOKE_ASYNC", __FILE__, __LINE__, -1,
               "========================================");
}

int main() {
  libnngio_log_init("info");
  
  libnngio_log("INF", "TEST_MANAGEMENT", __FILE__, __LINE__, -1,
               "========================================");
  libnngio_log("INF", "TEST_MANAGEMENT", __FILE__, __LINE__, -1,
               "Starting Management Module Tests");
  libnngio_log("INF", "TEST_MANAGEMENT", __FILE__, __LINE__, -1,
               "========================================");
  
  test_management_init_free();
  test_management_start_stop();
  test_transport_config_helpers();
  test_service_config_helpers();
  test_connection_config_helpers();
  test_service_discovery();
  test_service_discovery_async();
  test_rpc_service_invoke_sync();
  test_rpc_service_invoke_async();
  
  libnngio_log("INF", "TEST_MANAGEMENT", __FILE__, __LINE__, -1,
               "========================================");
  libnngio_log("INF", "TEST_MANAGEMENT", __FILE__, __LINE__, -1,
               "All Management Module Tests Passed!");
  libnngio_log("INF", "TEST_MANAGEMENT", __FILE__, __LINE__, -1,
               "========================================");
  
  return 0;
}
