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
  
  libnngio_log("INF", "TEST_MANAGEMENT", __FILE__, __LINE__, -1,
               "========================================");
  libnngio_log("INF", "TEST_MANAGEMENT", __FILE__, __LINE__, -1,
               "All Management Module Tests Passed!");
  libnngio_log("INF", "TEST_MANAGEMENT", __FILE__, __LINE__, -1,
               "========================================");
  
  return 0;
}
