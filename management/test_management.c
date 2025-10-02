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

#include "management/libnngio_management.h"

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
 * @brief Test protobuf configuration helper functions.
 */
void test_protobuf_config_helpers() {
  libnngio_log("INF", "TEST_PROTOBUF_CONFIG_HELPERS", __FILE__, __LINE__, -1,
               "Testing protobuf configuration helper functions");
  
  LibnngioManagement__ProtobufConfig *config =
      libnngio_management_create_protobuf_config(
          "test-protobuf", "test-transport");
  
  assert(config != NULL);
  assert(strcmp(config->name, "test-protobuf") == 0);
  assert(strcmp(config->transport_name, "test-transport") == 0);
  
  libnngio_log("INF", "TEST_PROTOBUF_CONFIG_HELPERS", __FILE__, __LINE__, -1,
               "Protobuf config created: name=%s, transport=%s",
               config->name, config->transport_name);
  
  libnngio_management_free_protobuf_config(config);
  libnngio_log("INF", "TEST_PROTOBUF_CONFIG_HELPERS", __FILE__, __LINE__, -1,
               "Protobuf configuration freed successfully");
}

/**
 * @brief Test connection configuration helper functions.
 */
void test_connection_config_helpers() {
  libnngio_log("INF", "TEST_CONNECTION_CONFIG_HELPERS", __FILE__, __LINE__, -1,
               "Testing connection configuration helper functions");
  
  LibnngioManagement__ConnectionConfig *config =
      libnngio_management_create_connection_config(
          "test-connection", "test-transport", "test-protobuf");
  
  assert(config != NULL);
  assert(strcmp(config->name, "test-connection") == 0);
  assert(strcmp(config->transport_name, "test-transport") == 0);
  assert(strcmp(config->protobuf_name, "test-protobuf") == 0);
  
  libnngio_log("INF", "TEST_CONNECTION_CONFIG_HELPERS", __FILE__, __LINE__, -1,
               "Connection config created: name=%s, transport=%s, protobuf=%s",
               config->name, config->transport_name, config->protobuf_name);
  
  libnngio_management_free_connection_config(config);
  libnngio_log("INF", "TEST_CONNECTION_CONFIG_HELPERS", __FILE__, __LINE__, -1,
               "Connection configuration freed successfully");
}

/**
 * @brief Test protocol configuration helper functions.
 */
void test_protocol_config_helpers() {
  libnngio_log("INF", "TEST_PROTOCOL_CONFIG_HELPERS", __FILE__, __LINE__, -1,
               "Testing protocol configuration helper functions");
  
  LibnngioManagement__ProtocolConfig *config =
      libnngio_management_create_protocol_config(
          "test-protocol", "A test protocol for demonstration");
  
  assert(config != NULL);
  assert(strcmp(config->name, "test-protocol") == 0);
  assert(strcmp(config->description, "A test protocol for demonstration") == 0);
  
  libnngio_log("INF", "TEST_PROTOCOL_CONFIG_HELPERS", __FILE__, __LINE__, -1,
               "Protocol config created: name=%s, description=%s",
               config->name, config->description);
  
  libnngio_management_free_protocol_config(config);
  libnngio_log("INF", "TEST_PROTOCOL_CONFIG_HELPERS", __FILE__, __LINE__, -1,
               "Protocol configuration freed successfully");
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
  test_protobuf_config_helpers();
  test_connection_config_helpers();
  test_protocol_config_helpers();
  
  libnngio_log("INF", "TEST_MANAGEMENT", __FILE__, __LINE__, -1,
               "========================================");
  libnngio_log("INF", "TEST_MANAGEMENT", __FILE__, __LINE__, -1,
               "All Management Module Tests Passed!");
  libnngio_log("INF", "TEST_MANAGEMENT", __FILE__, __LINE__, -1,
               "========================================");
  
  return 0;
}
