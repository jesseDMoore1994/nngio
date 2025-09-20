/**
 * This is a test file for protobuf integration.
 * It includes the necessary protobuf headers and defines a main function.
 */

#include <nng/nng.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protobuf/libnngio_protobuf.h"

/**
 * @brief Test function for protobuf serialization and deserialization.
 * It validates that messages can be correctly to and from the wire format
 * to the internal message structures.
 */
void test_protobuf_serde() {
  NngioProtobuf__RpcRequestMessage rpc_request_msg =
      NNGIO_PROTOBUF__RPC_REQUEST_MESSAGE__INIT;
  NngioProtobuf__NngioMessage nngio_msg = NNGIO_PROTOBUF__NNGIO_MESSAGE__INIT;
  void *buf = NULL;
  size_t len = 0;

  nngio_msg.uuid = libnngio_protobuf_gen_uuid();
  nngio_msg.msg_case = NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RPC_REQUEST;
  nngio_msg.rpc_request = &rpc_request_msg;
  nngio_protobuf__rpc_request_message__init(nngio_msg.rpc_request);
  nngio_msg.rpc_request->service_name = strdup("TestService");
  nngio_msg.rpc_request->method_name = strdup("TestMethod");
  nngio_msg.rpc_request->payload.len = 5;
  nngio_msg.rpc_request->payload.data = malloc(5);
  memcpy(nngio_msg.rpc_request->payload.data, "Hello", 5);

  len = nngio_protobuf__nngio_message__get_packed_size(&nngio_msg);
  buf = malloc(len);
  nngio_protobuf__nngio_message__pack(&nngio_msg, buf);

  free(nngio_msg.uuid);
  free(nngio_msg.rpc_request->service_name);
  free(nngio_msg.rpc_request->method_name);
  free(nngio_msg.rpc_request->payload.data);

  NngioProtobuf__NngioMessage *unpacked_msg =
      nngio_protobuf__nngio_message__unpack(NULL, len, buf);
  if (unpacked_msg == NULL) {
    libnngio_log("ERR", "TEST_PROTOBUF_SERDE", __FILE__, __LINE__, -1,
                 "Failed to unpack message");
    free(buf);
    return;
  }

  if (unpacked_msg->msg_case !=
      NNGIO_PROTOBUF__NNGIO_MESSAGE__MSG_RPC_REQUEST) {
    libnngio_log("ERR", "TEST_PROTOBUF_SERDE", __FILE__, __LINE__, -1,
                 "Unexpected message type: %s",
                 libnngio_protobuf_nngio_msg_case_str(unpacked_msg->msg_case));
  } else {
    libnngio_log("DBG", "TEST_PROTOBUF_SERDE", __FILE__, __LINE__, -1,
                 "Successfully unpacked RPC request message");
    libnngio_log("DBG", "TEST_PROTOBUF_SERDE", __FILE__, __LINE__, -1,
                 "Message type: %s",
                 libnngio_protobuf_nngio_msg_case_str(unpacked_msg->msg_case));
    libnngio_log("DBG", "TEST_PROTOBUF_SERDE", __FILE__, __LINE__, -1,
                 "Service: %s, Method: %s, Payload: %.*s",
                 unpacked_msg->rpc_request->service_name,
                 unpacked_msg->rpc_request->method_name,
                 (int)unpacked_msg->rpc_request->payload.len,
                 unpacked_msg->rpc_request->payload.data);
  }

  nngio_protobuf__nngio_message__free_unpacked(unpacked_msg, NULL);
  free(buf);
}

static const char *echo_methods[] = {"SayHello", "SayGoodbye"};
static const char *math_methods[] = {"Add", "Subtract", "Multiply"};
void test_protobuf_helpers() {
  // ---- Test Service ----
  NngioProtobuf__Service *svc = nngio_create_service("Echo", echo_methods, 2);
  if (!svc) {
    fprintf(stderr, "Failed to create Echo service\n");
    assert(0);
  }
  nngio_free_service(svc);

  // ---- Test ServiceDiscoveryResponse ----
  NngioProtobuf__Service *svc1 = nngio_create_service("Echo", echo_methods, 2);
  NngioProtobuf__Service *svc2 = nngio_create_service("Math", math_methods, 3);
  NngioProtobuf__Service *services[2] = {svc1, svc2};
  NngioProtobuf__ServiceDiscoveryResponse *resp =
      nngio_create_service_discovery_response(services, 2);
  if (!resp) {
    fprintf(stderr, "Failed to create response\n");
    nngio_free_service(svc1);
    nngio_free_service(svc2);
    assert(0);
  }
  nngio_free_service_discovery_response(resp);

  // ---- Test RpcRequestMessage ----
  const char payload[] = {0xDE, 0xAD, 0xBE, 0xEF};
  NngioProtobuf__RpcRequestMessage *req =
      nngio_create_rpc_request("Echo", "SayHello", payload, sizeof(payload));
  if (!req) {
    fprintf(stderr, "Failed to create RPC request\n");
    assert(0);
  }
  nngio_free_rpc_request(req);

  // ---- Test RpcResponseMessage ----
  NngioProtobuf__RpcResponseMessage *rresp = nngio_create_rpc_response(
      NNGIO_PROTOBUF__RPC_RESPONSE_MESSAGE__STATUS__Success, payload,
      sizeof(payload), NULL);
  if (!rresp) {
    fprintf(stderr, "Failed to create RPC response\n");
    assert(0);
  }
  nngio_free_rpc_response(rresp);

  // ---- Test RawMessage ----
  NngioProtobuf__RawMessage *raw =
      nngio_create_raw_message(payload, sizeof(payload));
  if (!raw) {
    fprintf(stderr, "Failed to create RawMessage\n");
    assert(0);
  }
  nngio_free_raw_message(raw);

  // ---- Test NngioMessage (RPC Request) ----
  req = nngio_create_rpc_request("Echo", "SayHello", payload, sizeof(payload));
  NngioProtobuf__NngioMessage *nmsg =
      nngio_create_nngio_message_with_rpc_request("uuid-123", req);
  if (!nmsg) {
    fprintf(stderr, "Failed to create NngioMessage (RPC request)\n");
    nngio_free_rpc_request(req);
    assert(0);
  }
  nngio_free_nngio_message(nmsg);  // This will free req too

  // ---- Test NngioMessage (RPC Response) ----
  rresp = nngio_create_rpc_response(
      NNGIO_PROTOBUF__RPC_RESPONSE_MESSAGE__STATUS__Success, payload,
      sizeof(payload), NULL);
  nmsg = nngio_create_nngio_message_with_rpc_response("uuid-456", rresp);
  if (!nmsg) {
    fprintf(stderr, "Failed to create NngioMessage (RPC response)\n");
    nngio_free_rpc_response(rresp);
    assert(0);
  }
  nngio_free_nngio_message(nmsg);

  // ---- Test NngioMessage (Raw Message) ----
  raw = nngio_create_raw_message(payload, sizeof(payload));
  nmsg = nngio_create_nngio_message_with_raw("uuid-789", raw);
  if (!nmsg) {
    fprintf(stderr, "Failed to create NngioMessage (raw)\n");
    nngio_free_raw_message(raw);
    assert(0);
  }
  nngio_free_nngio_message(nmsg);

  // ---- Test NngioMessage (ServiceDiscoveryRequest) ----
  NngioProtobuf__ServiceDiscoveryRequest *sdreq =
      malloc(sizeof(NngioProtobuf__ServiceDiscoveryRequest));
  if (!sdreq) {
    fprintf(stderr, "Failed to allocate ServiceDiscoveryRequest\n");
    assert(0);
  }
  nngio_protobuf__service_discovery_request__init(sdreq);
  nmsg = nngio_create_nngio_message_with_service_discovery_request("uuid-101",
                                                                   sdreq);
  if (!nmsg) {
    fprintf(stderr, "Failed to create NngioMessage (SD request)\n");
    nngio_protobuf__service_discovery_request__free_unpacked(sdreq, NULL);
    assert(0);
  }
  nngio_free_nngio_message(nmsg);

  // ---- Test NngioMessage (ServiceDiscoveryResponse) ----
  svc1 = nngio_create_service("Echo", echo_methods, 2);
  svc2 = nngio_create_service("Math", math_methods, 3);
  NngioProtobuf__Service *services2[2] = {svc1, svc2};
  resp = nngio_create_service_discovery_response(services2, 2);
  nmsg = nngio_create_nngio_message_with_service_discovery_response("uuid-102",
                                                                    resp);
  if (!nmsg) {
    fprintf(stderr, "Failed to create NngioMessage (SD response)\n");
    nngio_free_service_discovery_response(resp);
    assert(0);
  }
  nngio_free_nngio_message(nmsg);
}

void test_protobuf_raw_message() {
  libnngio_protobuf_error_code err;

  libnngio_transport *rep = NULL, *req = NULL;
  libnngio_config rep_cfg = {0}, req_cfg = {0};
  libnngio_context *rep_ctx = NULL, *req_ctx = NULL;
  char url[64];
  snprintf(url, sizeof(url), "tcp://127.0.0.0:5555");

  rep_cfg.url = url;
  rep_cfg.mode = LIBNNGIO_MODE_LISTEN;
  rep_cfg.proto = LIBNNGIO_PROTO_REP;
  req_cfg.url = url;
  req_cfg.mode = LIBNNGIO_MODE_DIAL;
  req_cfg.proto = LIBNNGIO_PROTO_REQ;

  int rv = libnngio_transport_init(&rep, &rep_cfg);
  if (rv != 0) {
    assert(rv == 0);
  }
  rv = libnngio_transport_init(&req, &req_cfg);
  if (rv != 0) {
    libnngio_transport_free(rep);
    assert(rv == 0);
  }
  rv = libnngio_context_init(&rep_ctx, rep, &rep_cfg, NULL, NULL);
  if (rv != 0) {
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(rv == 0);
  }
  rv = libnngio_context_init(&req_ctx, req, &req_cfg, NULL, NULL);
  if (rv != 0) {
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(rv == 0);
  }

  libnngio_log("INF", "TEST_PROTOBUF_RAW_MESSAGE", __FILE__, __LINE__, -1,
               "REQ/REP transports and contexts initialized on %s", url);

  libnngio_protobuf_context *rep_proto_ctx = NULL, *req_proto_ctx = NULL;
  err = libnngio_protobuf_context_init(&rep_proto_ctx, rep_ctx);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }
  err = libnngio_protobuf_context_init(&req_proto_ctx, req_ctx);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }

  libnngio_log("INF", "TEST_PROTOBUF_RAW_MESSAGE", __FILE__, __LINE__, -1,
               "Protobuf contexts initialized successfully.");

  // Prepare raw message
  const char *raw_msg = "Hello, Protobuf!";
  size_t raw_msg_len = strlen(raw_msg) + 1;  // Include null terminator
  NngioProtobuf__RawMessage *raw =
      nngio_create_raw_message(raw_msg, raw_msg_len);
  libnngio_log("INF", "TEST_PROTOBUF_RAW_MESSAGE", __FILE__, __LINE__, -1,
               "Prepared raw message for sending: %s", raw_msg);

#ifdef NNGIO_MOCK_MAIN
  // Mocking: set expected receive buffer for REP context
  NngioProtobuf__RawMessage *fakeraw =
      nngio_create_raw_message(raw_msg, raw_msg_len);
  NngioProtobuf__NngioMessage *fakenmsg =
      nngio_create_nngio_message_with_raw("uuid-789", fakeraw);
  size_t packed_size = nngio_protobuf__nngio_message__get_packed_size(fakenmsg);
  uint8_t *buffer = malloc(packed_size);
  nngio_protobuf__nngio_message__pack(fakenmsg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  free(buffer);
  nngio_free_nngio_message(fakenmsg);
#endif

  // Prepare to receive raw message
  NngioProtobuf__RawMessage *recv_raw_message = NULL;

  libnngio_log("INF", "TEST_PROTOBUF_RAW_MESSAGE", __FILE__, __LINE__, -1,
               "Prepared raw message for sending.");

  // Send raw message
  err = libnngio_protobuf_send_raw_message(req_proto_ctx, raw);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "TEST_PROTOBUF_RAW_MESSAGE", __FILE__, __LINE__, -1,
                 "Failed to send raw message: %s",
                 libnngio_protobuf_strerror(err));
    if (err == LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR) {
      libnngio_log("ERR", "TEST_PROTOBUF_RAW_MESSAGE", __FILE__, __LINE__, -1,
                   "Transport error occurred while sending raw message.");
    }
    nngio_free_raw_message(raw);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }
  libnngio_log("INF", "TEST_PROTOBUF_RAW_MESSAGE", __FILE__, __LINE__, -1,
               "Raw message sent successfully.");

  // Receive raw message
  err = libnngio_protobuf_recv_raw_message(rep_proto_ctx, &recv_raw_message);
  libnngio_log("DBG", "TEST_PROTOBUF_RAW_MESSAGE", __FILE__, __LINE__, -1,
               "message after return from recv: len=%zu, data=%s",
               recv_raw_message->data.len, recv_raw_message->data.data);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "TEST_PROTOBUF_RAW_MESSAGE", __FILE__, __LINE__, -1,
                 "Failed to receive raw message: %s",
                 libnngio_protobuf_strerror(err));
    nngio_free_raw_message(raw);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }

  // Validate received message
  if (recv_raw_message->data.len != raw_msg_len ||
      memcmp(recv_raw_message->data.data, raw_msg, raw_msg_len) != 0) {
    libnngio_log("ERR", "TEST_PROTOBUF_RAW_MESSAGE", __FILE__, __LINE__, -1,
                 "Received raw message does not match sent message.");
    libnngio_log("ERR", "TEST_PROTOBUF_RAW_MESSAGE", __FILE__, __LINE__, -1,
                 "Sent length: %zu, Received length: %zu", raw_msg_len,
                 recv_raw_message->data.len);
    libnngio_log("ERR", "TEST_PROTOBUF_RAW_MESSAGE", __FILE__, __LINE__, -1,
                 "Sent: %s, Received: %s", raw_msg,
                 recv_raw_message->data.data);
    nngio_protobuf__raw_message__free_unpacked(recv_raw_message, NULL);
    nngio_free_raw_message(raw);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(0);
  } else {
    libnngio_log("INF", "TEST_PROTOBUF_RAW_MESSAGE", __FILE__, __LINE__, -1,
                 "Received raw message matches sent message: %s",
                 recv_raw_message->data.data);
  }

  nngio_free_raw_message(recv_raw_message);
  nngio_free_raw_message(raw);
  libnngio_protobuf_context_free(req_proto_ctx);
  libnngio_protobuf_context_free(rep_proto_ctx);
  libnngio_context_free(req_ctx);
  libnngio_context_free(rep_ctx);
  libnngio_transport_free(rep);
  libnngio_transport_free(req);
}

void test_protobuf_rpc() {
  libnngio_protobuf_error_code err;

  libnngio_transport *rep = NULL, *req = NULL;
  libnngio_config rep_cfg = {0}, req_cfg = {0};
  libnngio_context *rep_ctx = NULL, *req_ctx = NULL;
  char url[64];
  snprintf(url, sizeof(url), "tcp://127.0.0.0:5555");

  rep_cfg.url = url;
  rep_cfg.mode = LIBNNGIO_MODE_LISTEN;
  rep_cfg.proto = LIBNNGIO_PROTO_REP;
  req_cfg.url = url;
  req_cfg.mode = LIBNNGIO_MODE_DIAL;
  req_cfg.proto = LIBNNGIO_PROTO_REQ;

  int rv = libnngio_transport_init(&rep, &rep_cfg);
  if (rv != 0) {
    assert(rv == 0);
  }
  rv = libnngio_transport_init(&req, &req_cfg);
  if (rv != 0) {
    libnngio_transport_free(rep);
    assert(rv == 0);
  }
  rv = libnngio_context_init(&rep_ctx, rep, &rep_cfg, NULL, NULL);
  if (rv != 0) {
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(rv == 0);
  }
  rv = libnngio_context_init(&req_ctx, req, &req_cfg, NULL, NULL);
  if (rv != 0) {
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(rv == 0);
  }

  libnngio_log("INF", "TEST_PROTOBUF_RPC", __FILE__, __LINE__, -1,
               "REQ/REP transports and contexts initialized on %s", url);

  libnngio_protobuf_context *rep_proto_ctx = NULL, *req_proto_ctx = NULL;
  err = libnngio_protobuf_context_init(&rep_proto_ctx, rep_ctx);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }
  err = libnngio_protobuf_context_init(&req_proto_ctx, req_ctx);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }

  libnngio_log("INF", "TEST_PROTOBUF_RPC", __FILE__, __LINE__, -1,
               "Protobuf contexts initialized successfully.");

  // Prepare RPC request message
  NngioProtobuf__RpcRequestMessage *rpc_request_msg = nngio_create_rpc_request(
      "TestService", "TestMethod", (const uint8_t *)"Hello", 5);

#ifdef NNGIO_MOCK_MAIN
  // Mocking: set expected receive buffer for REP context
  NngioProtobuf__RpcRequestMessage *fakerpc = nngio_create_rpc_request(
      "TestService", "TestMethod", (const uint8_t *)"Hello", 5);
  NngioProtobuf__NngioMessage *fakemsg =
      nngio_create_nngio_message_with_rpc_request("uuid-123", fakerpc);
  size_t packed_size = nngio_protobuf__nngio_message__get_packed_size(fakemsg);
  uint8_t *buffer = malloc(packed_size);
  nngio_protobuf__nngio_message__pack(fakemsg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  nngio_free_nngio_message(fakemsg);
  free(buffer);
#endif

  // Prepare to receive RPC request message
  NngioProtobuf__RpcRequestMessage *recv_request_msg = NULL;

  libnngio_log("INF", "TEST_PROTOBUF_RPC", __FILE__, __LINE__, -1,
               "Prepared RPC request message for sending.");

  // Send RPC request
  err = libnngio_protobuf_send_rpc_request(req_proto_ctx, rpc_request_msg);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "TEST_PROTOBUF_RPC", __FILE__, __LINE__, -1,
                 "Failed to send RPC request: %s",
                 libnngio_protobuf_strerror(err));
    if (err == LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR) {
      libnngio_log("ERR", "TEST_PROTOBUF_RPC", __FILE__, __LINE__, -1,
                   "Transport error occurred while sending RPC request.");
      libnngio_log("ERR", "TEST_PROTOBUF_RPC", __FILE__, __LINE__, -1,
                   "REQ transport last error code: %s",
                   nng_strerror(libnngio_protobuf_context_get_transport_rv(
                       req_proto_ctx)));
    }
    nngio_free_rpc_request(recv_request_msg);
    nngio_free_rpc_request(rpc_request_msg);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(req);
    libnngio_transport_free(rep);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }

  // Receive RPC request
  err = libnngio_protobuf_recv_rpc_request(rep_proto_ctx, &recv_request_msg);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "TEST_PROTOBUF_RPC", __FILE__, __LINE__, -1,
                 "Failed to receive RPC request: %s",
                 libnngio_protobuf_strerror(err));
    if (err == LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR) {
      libnngio_log("ERR", "TEST_PROTOBUF_RPC", __FILE__, __LINE__, -1,
                   "Transport error occurred while sending RPC request.");
      libnngio_log("ERR", "TEST_PROTOBUF_RPC", __FILE__, __LINE__, -1,
                   "REP transport last error code: %s",
                   nng_strerror(libnngio_protobuf_context_get_transport_rv(
                       rep_proto_ctx)));
    }
    nngio_free_rpc_request(recv_request_msg);
    nngio_free_rpc_request(rpc_request_msg);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(req);
    libnngio_transport_free(rep);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }

  // Validate received message
  if (strcmp(recv_request_msg->service_name, rpc_request_msg->service_name) !=
      0) {
    libnngio_log("ERR", "TEST_PROTOBUF_RPC", __FILE__, __LINE__, -1,
                 "Service name mismatch: expected %s, got %s",
                 rpc_request_msg->service_name, recv_request_msg->service_name);
    assert(0);
  }
  if (strcmp(recv_request_msg->method_name, rpc_request_msg->method_name) !=
      0) {
    libnngio_log("ERR", "TEST_PROTOBUF_RPC", __FILE__, __LINE__, -1,
                 "Method name mismatch: expected %s, got %s",
                 rpc_request_msg->method_name, recv_request_msg->method_name);
    assert(0);
  }
  if (recv_request_msg->payload.len != rpc_request_msg->payload.len ||
      memcmp(recv_request_msg->payload.data, rpc_request_msg->payload.data,
             rpc_request_msg->payload.len) != 0) {
    libnngio_log("ERR", "TEST_PROTOBUF_RPC", __FILE__, __LINE__, -1,
                 "Payload mismatch");
    assert(0);
  }

  libnngio_log("INF", "TEST_PROTOBUF_RPC", __FILE__, __LINE__, -1,
               "RPC request sent and received successfully.");
  libnngio_log("INF", "TEST_PROTOBUF_RPC", __FILE__, __LINE__, -1,
               "Service: %s, Method: %s, Payload: %.*s",
               recv_request_msg->service_name, recv_request_msg->method_name,
               (int)recv_request_msg->payload.len,
               recv_request_msg->payload.data);

  libnngio_log("INF", "TEST_PROTOBUF_RPC", __FILE__, __LINE__, -1,
               "Sending RPC response...");
  // Prepare RPC response message
  NngioProtobuf__RpcResponseMessage *rpc_response_msg =
      nngio_create_rpc_response(
          NNGIO_PROTOBUF__RPC_RESPONSE_MESSAGE__STATUS__Success,
          (const uint8_t *)"Goodbye", 7, NULL);

#ifdef NNGIO_MOCK_MAIN
  // Mocking: set expected receive buffer for REP context
  NngioProtobuf__RpcResponseMessage *fakerpc_response =
      nngio_create_rpc_response(
          NNGIO_PROTOBUF__RPC_RESPONSE_MESSAGE__STATUS__Success,
          (const uint8_t *)"Goodbye", 7, NULL);
  NngioProtobuf__NngioMessage *fake_response_msg =
      nngio_create_nngio_message_with_rpc_response("uuid-456",
                                                   fakerpc_response);
  packed_size =
      nngio_protobuf__nngio_message__get_packed_size(fake_response_msg);
  buffer = malloc(packed_size);
  nngio_protobuf__nngio_message__pack(fake_response_msg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  nngio_free_nngio_message(fake_response_msg);
  free(buffer);
#endif

  // Prepare to receive RPC response message
  NngioProtobuf__RpcResponseMessage *recv_response_msg = NULL;

  libnngio_log("INF", "TEST_PROTOBUF_RPC", __FILE__, __LINE__, -1,
               "Prepared RPC response message for sending.");

  // Send RPC response
  err = libnngio_protobuf_send_rpc_response(rep_proto_ctx, rpc_response_msg);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "TEST_PROTOBUF_RPC", __FILE__, __LINE__, -1,
                 "Failed to send RPC response: %s",
                 libnngio_protobuf_strerror(err));
    if (err == LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR) {
      libnngio_log("ERR", "TEST_PROTOBUF_RPC", __FILE__, __LINE__, -1,
                   "Transport error occurred while sending RPC response.");
      libnngio_log("ERR", "TEST_PROTOBUF_RPC", __FILE__, __LINE__, -1,
                   "REP transport last error code: %s",
                   nng_strerror(libnngio_protobuf_context_get_transport_rv(
                       rep_proto_ctx)));
    }
    nngio_free_rpc_response(recv_response_msg);
    nngio_free_rpc_response(rpc_response_msg);
    nngio_free_rpc_request(recv_request_msg);
    nngio_free_rpc_request(rpc_request_msg);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(req);
    libnngio_transport_free(rep);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }

  // Receive RPC response
  err = libnngio_protobuf_recv_rpc_response(req_proto_ctx, &recv_response_msg);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "TEST_PROTOBUF_RPC", __FILE__, __LINE__, -1,
                 "Failed to receive RPC response: %s",
                 libnngio_protobuf_strerror(err));
    if (err == LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR) {
      libnngio_log("ERR", "TEST_PROTOBUF_RPC", __FILE__, __LINE__, -1,
                   "Transport error occurred while sending RPC response.");
      libnngio_log("ERR", "TEST_PROTOBUF_RPC", __FILE__, __LINE__, -1,
                   "REQ transport last error code: %s",
                   nng_strerror(libnngio_protobuf_context_get_transport_rv(
                       req_proto_ctx)));
    }
    nngio_free_rpc_response(recv_response_msg);
    nngio_free_rpc_response(rpc_response_msg);
    nngio_free_rpc_request(recv_request_msg);
    nngio_free_rpc_request(rpc_request_msg);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(req);
    libnngio_transport_free(rep);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }

  // Validate received message
  if (recv_response_msg->status != rpc_response_msg->status) {
    libnngio_log("ERR", "TEST_PROTOBUF_RPC", __FILE__, __LINE__, -1,
                 "Status mismatch: expected %d, got %d",
                 rpc_response_msg->status, recv_response_msg->status);
    assert(0);
  }
  if (recv_response_msg->payload.len != rpc_response_msg->payload.len ||
      memcmp(recv_response_msg->payload.data, rpc_response_msg->payload.data,
             rpc_response_msg->payload.len) != 0) {
    libnngio_log("ERR", "TEST_PROTOBUF_RPC", __FILE__, __LINE__, -1,
                 "Payload mismatch");
    assert(0);
  }

  // all this selective freeing is done because the messages are on the stack
  // and only the internal pointers need to be freed, otherwise I think that
  // the nngio_protobuf__rpc_response_message__free_unpacked could be used
  // but that would require heap allocation of the messages
  nngio_free_rpc_response(recv_response_msg);
  nngio_free_rpc_response(rpc_response_msg);
  nngio_free_rpc_request(recv_request_msg);
  nngio_free_rpc_request(rpc_request_msg);
  libnngio_protobuf_context_free(req_proto_ctx);
  libnngio_protobuf_context_free(rep_proto_ctx);
  libnngio_context_free(req_ctx);
  libnngio_context_free(rep_ctx);
  libnngio_transport_free(req);
  libnngio_transport_free(rep);
}

void test_protobuf_service_discovery() {
  libnngio_protobuf_error_code err;

  libnngio_transport *rep = NULL, *req = NULL;
  libnngio_config rep_cfg = {0}, req_cfg = {0};
  libnngio_context *rep_ctx = NULL, *req_ctx = NULL;
  char url[64];
  snprintf(url, sizeof(url), "tcp://127.0.0.0:5555");

  rep_cfg.url = url;
  rep_cfg.mode = LIBNNGIO_MODE_LISTEN;
  rep_cfg.proto = LIBNNGIO_PROTO_REP;
  req_cfg.url = url;
  req_cfg.mode = LIBNNGIO_MODE_DIAL;
  req_cfg.proto = LIBNNGIO_PROTO_REQ;

  int rv = libnngio_transport_init(&rep, &rep_cfg);
  if (rv != 0) {
    assert(rv == 0);
  }
  rv = libnngio_transport_init(&req, &req_cfg);
  if (rv != 0) {
    libnngio_transport_free(rep);
    assert(rv == 0);
  }
  rv = libnngio_context_init(&rep_ctx, rep, &rep_cfg, NULL, NULL);
  if (rv != 0) {
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(rv == 0);
  }
  rv = libnngio_context_init(&req_ctx, req, &req_cfg, NULL, NULL);
  if (rv != 0) {
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(rv == 0);
  }

  libnngio_log("INF", "TEST_PROTOBUF_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "REQ/REP transports and contexts initialized on %s", url);

  libnngio_protobuf_context *rep_proto_ctx = NULL, *req_proto_ctx = NULL;
  err = libnngio_protobuf_context_init(&rep_proto_ctx, rep_ctx);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }
  err = libnngio_protobuf_context_init(&req_proto_ctx, req_ctx);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }

  libnngio_log("INF", "TEST_PROTOBUF_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "Protobuf contexts initialized successfully.");

  // Prepare to request services
  NngioProtobuf__ServiceDiscoveryRequest *service_request =
      malloc(sizeof(NngioProtobuf__ServiceDiscoveryRequest));
  nngio_protobuf__service_discovery_request__init(service_request);
  // No fields to set for now

#ifdef NNGIO_MOCK_MAIN
  // Mocking: set expected receive buffer for REP context
  NngioProtobuf__ServiceDiscoveryRequest *fakerq =
      malloc(sizeof(NngioProtobuf__ServiceDiscoveryRequest));
  nngio_protobuf__service_discovery_request__init(fakerq);
  NngioProtobuf__NngioMessage *temp_msg =
      nngio_create_nngio_message_with_service_discovery_request("uuid-101",
                                                                fakerq);
  size_t packed_size = nngio_protobuf__nngio_message__get_packed_size(temp_msg);
  uint8_t *buffer = malloc(packed_size);
  nngio_protobuf__nngio_message__pack(temp_msg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  free(buffer);
  nngio_free_nngio_message(temp_msg);
#endif

  // Prepare to receive service discovery request message
  NngioProtobuf__ServiceDiscoveryRequest *recv_service_request = NULL;
  libnngio_log("INF", "TEST_PROTOBUF_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "Prepared service discovery request message for sending.");

  // Send service discovery request
  err = libnngio_protobuf_send_service_discovery_request(req_proto_ctx,
                                                         service_request);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY", __FILE__, __LINE__,
                 -1, "Failed to send service discovery request: %s",
                 libnngio_protobuf_strerror(err));
    if (err == LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR) {
      libnngio_log(
          "ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
          "Transport error occurred while sending service discovery request.");
      libnngio_log("ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY", __FILE__, __LINE__,
                   -1, "REQ transport last error code: %s",
                   nng_strerror(libnngio_protobuf_context_get_transport_rv(
                       req_proto_ctx)));
    }
  }

  // Receive service discovery request
  err = libnngio_protobuf_recv_service_discovery_request(rep_proto_ctx,
                                                         &recv_service_request);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY", __FILE__, __LINE__,
                 -1, "Failed to receive service discovery request: %s",
                 libnngio_protobuf_strerror(err));
    if (err == LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR) {
      libnngio_log(
          "ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
          "Transport error occurred while sending service discovery request.");
      libnngio_log("ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY", __FILE__, __LINE__,
                   -1, "REP transport last error code: %s",
                   nng_strerror(libnngio_protobuf_context_get_transport_rv(
                       rep_proto_ctx)));
    }
  } else {
    libnngio_log("INF", "TEST_PROTOBUF_SERVICE_DISCOVERY", __FILE__, __LINE__,
                 -1,
                 "Service discovery request sent and received successfully.");
  }

  // Validate received message
  // No fields to validate for now

  libnngio_log("INF", "TEST_PROTOBUF_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "Sending service discovery response...");

  // Prepare service discovery response message
  NngioProtobuf__Service *service1 =
      nngio_create_service("Echo", echo_methods, 2);
  NngioProtobuf__Service *service2 =
      nngio_create_service("Math", math_methods, 3);
  NngioProtobuf__Service *services[2] = {service1, service2};
  NngioProtobuf__ServiceDiscoveryResponse *service_response =
      nngio_create_service_discovery_response(services, 2);

#ifdef NNGIO_MOCK_MAIN
  // Mocking: set expected receive buffer for REQ context
  NngioProtobuf__Service *fakeservice1 =
      nngio_create_service("Echo", echo_methods, 2);
  NngioProtobuf__Service *fakeservice2 =
      nngio_create_service("Math", math_methods, 3);
  NngioProtobuf__Service *fakeservices[2] = {fakeservice1, fakeservice2};
  NngioProtobuf__ServiceDiscoveryResponse *fakeresp =
      nngio_create_service_discovery_response(fakeservices, 2);
  NngioProtobuf__NngioMessage *temp_resp_msg =
      nngio_create_nngio_message_with_service_discovery_response("uuid-202",
                                                                 fakeresp);
  packed_size = nngio_protobuf__nngio_message__get_packed_size(temp_resp_msg);
  buffer = malloc(packed_size);
  nngio_protobuf__nngio_message__pack(temp_resp_msg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  free(buffer);
  nngio_free_nngio_message(temp_resp_msg);
#endif

  // Prepare to receive service discovery response message
  NngioProtobuf__ServiceDiscoveryResponse *recv_service_response = NULL;
  libnngio_log("INF", "TEST_PROTOBUF_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "Prepared service discovery response message for sending.");

  // Send service discovery response
  err = libnngio_protobuf_send_service_discovery_response(rep_proto_ctx,
                                                          service_response);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY", __FILE__, __LINE__,
                 -1, "Failed to send service discovery response: %s",
                 libnngio_protobuf_strerror(err));
    if (err == LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR) {
      libnngio_log(
          "ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
          "Transport error occurred while sending service discovery response.");
      libnngio_log("ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY", __FILE__, __LINE__,
                   -1, "REP transport last error code: %s",
                   nng_strerror(libnngio_protobuf_context_get_transport_rv(
                       rep_proto_ctx)));
    }
  }

  // Receive service discovery response
  err = libnngio_protobuf_recv_service_discovery_response(
      req_proto_ctx, &recv_service_response);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY", __FILE__, __LINE__,
                 -1, "Failed to receive service discovery response: %s",
                 libnngio_protobuf_strerror(err));
    if (err == LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR) {
      libnngio_log(
          "ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
          "Transport error occurred while sending service discovery response.");
      libnngio_log("ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY", __FILE__, __LINE__,
                   -1, "REQ transport last error code: %s",
                   nng_strerror(libnngio_protobuf_context_get_transport_rv(
                       req_proto_ctx)));
    }
  } else {
    libnngio_log("INF", "TEST_PROTOBUF_SERVICE_DISCOVERY", __FILE__, __LINE__,
                 -1,
                 "Service discovery response sent and received successfully.");
  }

  // Validate received message
  if (recv_service_response->n_services != service_response->n_services) {
    libnngio_log("ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY", __FILE__, __LINE__,
                 -1, "Number of services mismatch: expected %d, got %d",
                 service_response->n_services,
                 recv_service_response->n_services);
    assert(0);
  }
  for (size_t i = 0; i < service_response->n_services; i++) {
    NngioProtobuf__Service *sent_service = service_response->services[i];
    NngioProtobuf__Service *recv_service = recv_service_response->services[i];
    if (strcmp(sent_service->name, recv_service->name) != 0) {
      libnngio_log("ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY", __FILE__, __LINE__,
                   -1, "Service name mismatch at index %d: expected %s, got %s",
                   (int)i, sent_service->name, recv_service->name);
      assert(0);
    }
    if (sent_service->n_methods != recv_service->n_methods) {
      libnngio_log(
          "ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
          "Number of methods mismatch for service %s: expected %d, got %d",
          sent_service->name, sent_service->n_methods, recv_service->n_methods);
      assert(0);
    }
    for (size_t j = 0; j < sent_service->n_methods; j++) {
      if (strcmp(sent_service->methods[j], recv_service->methods[j]) != 0) {
        libnngio_log("ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY", __FILE__,
                     __LINE__, -1,
                     "Method name mismatch for service %s at index %d: "
                     "expected %s, got %s",
                     sent_service->name, (int)j, sent_service->methods[j],
                     recv_service->methods[j]);
        assert(0);
      }
    }
  }

  libnngio_log("INF", "TEST_PROTOBUF_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "Service discovery response validated.");

  nngio_free_service_discovery_response(recv_service_response);
  nngio_free_service_discovery_response(service_response);
  free(recv_service_request);
  free(service_request);
  libnngio_protobuf_context_free(req_proto_ctx);
  libnngio_protobuf_context_free(rep_proto_ctx);
  libnngio_context_free(req_ctx);
  libnngio_context_free(rep_ctx);
  libnngio_transport_free(req);
  libnngio_transport_free(rep);
}

/**
 * @brief A simple structure to synchronize async test state.
 */
typedef struct {
  volatile int done;                 /**< Flag to indicate completion */
  int result;                        /**< Result of the async operation */
  NngioProtobuf__NngioMessage **msg; /**< Message pointer */
} async_test_sync;

/**
 * @brief Test async recv callback
 */
void async_recv_cb(libnngio_protobuf_context *ctx, int result,
                   NngioProtobuf__NngioMessage **msg, void *user_data) {
  libnngio_log("INF", "TEST_ASYNC_RECV_CB", __FILE__, __LINE__, -1,
               "Async recv callback called with result=%d", result);
  libnngio_log("INF", "TEST_ASYNC_RECV_CB", __FILE__, __LINE__, -1,
               "Message UUID: %s", msg && *msg ? (*msg)->uuid : "NULL");
  libnngio_log("INF", "TEST_ASYNC_RECV_CB", __FILE__, __LINE__, -1,
               "Message case: %s",
               msg && *msg
                   ? libnngio_protobuf_nngio_msg_case_str((*msg)->msg_case)
                   : "NULL");
  async_test_sync *sync = (async_test_sync *)user_data;
  sync->result = result;
  sync->done = 1;
  nngio_free_nngio_message(*msg);
}

/**
 * @brief Test async send callback
 */
void async_send_cb(libnngio_protobuf_context *ctx, int result,
                   NngioProtobuf__NngioMessage *msg, void *user_data) {
  async_test_sync *sync = (async_test_sync *)user_data;
  char *msg_case = NULL;
  if (msg) {
    msg_case = libnngio_protobuf_nngio_msg_case_str(msg->msg_case);
  } else {
    msg_case = "Unknown message case";
  }
  libnngio_log("INF", "TEST_ASYNC_SEND_CB", __FILE__, __LINE__, -1,
               "Async send callback called with result=%d, msg_type=%s", result,
               msg_case);
  libnngio_log("INF", "TEST_ASYNC_SEND_CB", __FILE__, __LINE__, 0,
               "Message UUID: %s", msg ? msg->uuid : "NULL");
  sync->result = result;
  sync->done = 1;
  //nngio_free_nngio_message(msg);
}

void test_protobuf_raw_message_async() {
  libnngio_protobuf_error_code err;

  libnngio_transport *rep = NULL, *req = NULL;
  libnngio_config rep_cfg = {0}, req_cfg = {0};
  libnngio_context *rep_ctx = NULL, *req_ctx = NULL;
  char url[64];
  snprintf(url, sizeof(url), "tcp://127.0.0.0:5555");

  rep_cfg.url = url;
  rep_cfg.mode = LIBNNGIO_MODE_LISTEN;
  rep_cfg.proto = LIBNNGIO_PROTO_REP;
  req_cfg.url = url;
  req_cfg.mode = LIBNNGIO_MODE_DIAL;
  req_cfg.proto = LIBNNGIO_PROTO_REQ;

  int rv = libnngio_transport_init(&rep, &rep_cfg);
  if (rv != 0) {
    assert(rv == 0);
  }
  rv = libnngio_transport_init(&req, &req_cfg);
  if (rv != 0) {
    libnngio_transport_free(rep);
    assert(rv == 0);
  }
  rv = libnngio_context_init(&rep_ctx, rep, &rep_cfg, NULL, NULL);
  if (rv != 0) {
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(rv == 0);
  }
  rv = libnngio_context_init(&req_ctx, req, &req_cfg, NULL, NULL);
  if (rv != 0) {
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(rv == 0);
  }

  libnngio_log("INF", "TEST_PROTOBUF_RAW_MESSAGE_ASYNC", __FILE__, __LINE__, -1,
               "REQ/REP transports and contexts initialized on %s", url);

  libnngio_protobuf_context *rep_proto_ctx = NULL, *req_proto_ctx = NULL;
  err = libnngio_protobuf_context_init(&rep_proto_ctx, rep_ctx);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }
  err = libnngio_protobuf_context_init(&req_proto_ctx, req_ctx);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }

  libnngio_log("INF", "TEST_PROTOBUF_RAW_MESSAGE_ASYNC", __FILE__, __LINE__, -1,
               "Protobuf contexts initialized successfully.");

  // Prepare raw message
  const char *raw_msg = "Hello, Protobuf!";
  size_t raw_msg_len = strlen(raw_msg) + 1;  // Include null terminator
  NngioProtobuf__RawMessage *raw =
      nngio_create_raw_message(raw_msg, raw_msg_len);
  libnngio_log("INF", "TEST_PROTOBUF_RAW_MESSAGE_ASYNC", __FILE__, __LINE__, -1,
               "Prepared raw message for sending: %s", raw_msg);

#ifdef NNGIO_MOCK_MAIN
  // Mocking: set expected receive buffer for REP context
  NngioProtobuf__RawMessage *fakeraw =
      nngio_create_raw_message(raw_msg, raw_msg_len);
  NngioProtobuf__NngioMessage *fakenmsg = nngio_create_nngio_message_with_raw(
      "11aa5292-1e8d-4c4f-8d38-cb1d53e0e34b", fakeraw);
  size_t packed_size = nngio_protobuf__nngio_message__get_packed_size(fakenmsg);
  uint8_t *buffer = malloc(packed_size);
  nngio_protobuf__nngio_message__pack(fakenmsg, buffer);
  libnngio_mock_set_recv_async_result(0);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  free(buffer);
  nngio_free_nngio_message(fakenmsg);
#endif

  async_test_sync recv_sync = {0}, send_sync = {0};

  // Prepare to receive raw message
  NngioProtobuf__RawMessage *recv_raw_message = NULL;

  libnngio_log("INF", "TEST_PROTOBUF_RAW_MESSAGE_ASYNC", __FILE__, __LINE__, -1,
               "Prepared raw message for sending.");

  // Receive raw message asynchronously
  err = libnngio_protobuf_recv_raw_message_async(
      rep_proto_ctx, &recv_raw_message, async_recv_cb, &recv_sync);
  libnngio_log("DBG", "TEST_PROTOBUF_RAW_MESSAGE_ASYNC", __FILE__, __LINE__, -1,
               "Prepared to receive raw message asynchronously.");
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "TEST_PROTOBUF_RAW_MESSAGE_ASYNC", __FILE__, __LINE__,
                 -1, "Failed to receive raw message: %s",
                 libnngio_protobuf_strerror(err));
    nngio_free_raw_message(raw);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }

  libnngio_log("INF", "TEST_PROTOBUF_RAW_MESSAGE_ASYNC", __FILE__, __LINE__, -1,
               "Beginning async send of raw message...");

  // Send raw message asynchronously
  err = libnngio_protobuf_send_raw_message_async(req_proto_ctx, raw,
                                                 async_send_cb, &send_sync);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "TEST_PROTOBUF_RAW_MESSAGE_ASYNC", __FILE__, __LINE__,
                 -1, "Failed to send raw message: %s",
                 libnngio_protobuf_strerror(err));
    if (err == LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR) {
      libnngio_log("ERR", "TEST_PROTOBUF_RAW_MESSAGE_ASYNC", __FILE__, __LINE__,
                   -1, "Transport error occurred while sending raw message.");
    }
    nngio_free_raw_message(raw);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }
  libnngio_log("INF", "TEST_PROTOBUF_RAW_MESSAGE_ASYNC", __FILE__, __LINE__, -1,
               "Raw message sent asynchronously.");

  // Wait for send to complete
  while (!send_sync.done) {
    nng_msleep(10);
  }
  if (send_sync.result != 0) {
    libnngio_log("ERR", "TEST_PROTOBUF_RAW_MESSAGE_ASYNC", __FILE__, __LINE__,
                 -1, "Async send failed with result: %d", send_sync.result);
    nngio_free_raw_message(raw);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(0);
  }
  libnngio_log("INF", "TEST_PROTOBUF_RAW_MESSAGE_ASYNC", __FILE__, __LINE__, -1,
               "Async send completed successfully.");

  // Wait for receive to complete
  while (!recv_sync.done) {
    nng_msleep(10);
  }
  if (recv_sync.result != 0) {
    libnngio_log("ERR", "TEST_PROTOBUF_RAW_MESSAGE_ASYNC", __FILE__, __LINE__,
                 -1, "Async receive failed with result: %d", recv_sync.result);
    nngio_free_raw_message(raw);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(0);
  }

  // pull message out of callback storage
  libnngio_log(
      "INF", "TEST_PROTOBUF_RAW_MESSAGE_ASYNC", __FILE__, __LINE__, -1,
      "Async receive completed successfully. Received length: %zu, data: %s",
      recv_raw_message->data.len, recv_raw_message->data.data);

  // Validate received message
  if (recv_raw_message->data.len != raw_msg_len ||
      memcmp(recv_raw_message->data.data, raw_msg, raw_msg_len) != 0) {
    libnngio_log("ERR", "TEST_PROTOBUF_RAW_MESSAGE_ASYNC", __FILE__, __LINE__,
                 -1, "Received raw message does not match sent message.");
    libnngio_log("ERR", "TEST_PROTOBUF_RAW_MESSAGE_ASYNC", __FILE__, __LINE__,
                 -1, "Sent length: %zu, Received length: %zu", raw_msg_len,
                 recv_raw_message->data.len);
    libnngio_log("ERR", "TEST_PROTOBUF_RAW_MESSAGE_ASYNC", __FILE__, __LINE__,
                 -1, "Sent: %s, Received: %s", raw_msg,
                 recv_raw_message->data.data);
    nngio_free_raw_message(recv_raw_message);
    nngio_free_raw_message(raw);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(0);
  } else {
    libnngio_log("INF", "TEST_PROTOBUF_RAW_MESSAGE_ASYNC", __FILE__, __LINE__,
                 -1, "Received raw message matches sent message: %s",
                 recv_raw_message->data.data);
  }

  nngio_free_raw_message(recv_raw_message);
  nngio_free_raw_message(raw);
  libnngio_protobuf_context_free(req_proto_ctx);
  libnngio_protobuf_context_free(rep_proto_ctx);
  libnngio_context_free(req_ctx);
  libnngio_context_free(rep_ctx);
  libnngio_transport_free(rep);
  libnngio_transport_free(req);
}

void test_protobuf_rpc_async(void) {
  libnngio_protobuf_error_code err;

  libnngio_transport *rep = NULL, *req = NULL;
  libnngio_config rep_cfg = {0}, req_cfg = {0};
  libnngio_context *rep_ctx = NULL, *req_ctx = NULL;
  char url[64];
  snprintf(url, sizeof(url), "tcp://127.0.0.0:5555");

  rep_cfg.url = url;
  rep_cfg.mode = LIBNNGIO_MODE_LISTEN;
  rep_cfg.proto = LIBNNGIO_PROTO_REP;
  req_cfg.url = url;
  req_cfg.mode = LIBNNGIO_MODE_DIAL;
  req_cfg.proto = LIBNNGIO_PROTO_REQ;

  int rv = libnngio_transport_init(&rep, &rep_cfg);
  if (rv != 0) {
    assert(rv == 0);
  }
  rv = libnngio_transport_init(&req, &req_cfg);
  if (rv != 0) {
    libnngio_transport_free(rep);
    assert(rv == 0);
  }
  rv = libnngio_context_init(&rep_ctx, rep, &rep_cfg, NULL, NULL);
  if (rv != 0) {
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(rv == 0);
  }
  rv = libnngio_context_init(&req_ctx, req, &req_cfg, NULL, NULL);
  if (rv != 0) {
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(rv == 0);
  }

  libnngio_log("INF", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
               "REQ/REP transports and contexts initialized on %s", url);

  libnngio_protobuf_context *rep_proto_ctx = NULL, *req_proto_ctx = NULL;
  err = libnngio_protobuf_context_init(&rep_proto_ctx, rep_ctx);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }
  err = libnngio_protobuf_context_init(&req_proto_ctx, req_ctx);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }

  libnngio_log("INF", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Protobuf contexts initialized successfully.");

  // Prepare RPC request message
  NngioProtobuf__RpcRequestMessage *rpc_request_msg = nngio_create_rpc_request(
      "TestService", "TestMethod", (const uint8_t *)"Hello", 5);

#ifdef NNGIO_MOCK_MAIN
  // Mocking: set expected receive buffer for REP context
  NngioProtobuf__RpcRequestMessage *fakerpc = nngio_create_rpc_request(
      "TestService", "TestMethod", (const uint8_t *)"Hello", 5);
  NngioProtobuf__NngioMessage *fakemsg =
      nngio_create_nngio_message_with_rpc_request("uuid-123", fakerpc);
  size_t packed_size = nngio_protobuf__nngio_message__get_packed_size(fakemsg);
  uint8_t *buffer = malloc(packed_size);
  nngio_protobuf__nngio_message__pack(fakemsg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  nngio_free_nngio_message(fakemsg);
  free(buffer);
#endif

  async_test_sync recv_sync = {0}, send_sync = {0};

  // Prepare to receive RPC request message
  NngioProtobuf__RpcRequestMessage *recv_request_msg = NULL;

  libnngio_log("INF", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Prepared RPC request message for sending.");

  // Receive rpc request message asynchronously
  err = libnngio_protobuf_recv_rpc_request_async(
      rep_proto_ctx, &recv_request_msg, async_recv_cb, &recv_sync);
  libnngio_log("DBG", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Prepared to receive RPC request asynchronously.");
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
                 "Failed to receive rpc request: %s",
                 libnngio_protobuf_strerror(err));
    nngio_free_rpc_request(rpc_request_msg);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }

  libnngio_log("INF", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Beginning async send of rpc request...");

  // Send raw message asynchronously
  err = libnngio_protobuf_send_rpc_request_async(req_proto_ctx, rpc_request_msg,
                                                 async_send_cb, &send_sync);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
                 "Failed to send rpc request: %s",
                 libnngio_protobuf_strerror(err));
    if (err == LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR) {
      libnngio_log("ERR", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
                   "Transport error occurred while sending rpc request.");
    }
    nngio_free_rpc_request(rpc_request_msg);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }
  libnngio_log("INF", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Raw message sent asynchronously.");

  // Wait for send to complete
  while (!send_sync.done) {
    nng_msleep(10);
  }
  if (send_sync.result != 0) {
    libnngio_log("ERR", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
                 "Async send failed with result: %d", send_sync.result);
    nngio_free_rpc_request(rpc_request_msg);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(0);
  }
  libnngio_log("INF", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Async send completed successfully.");

  // Wait for receive to complete
  while (!recv_sync.done) {
    nng_msleep(10);
  }
  if (recv_sync.result != 0) {
    libnngio_log("ERR", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
                 "Async receive failed with result: %d", recv_sync.result);
    nngio_free_rpc_request(rpc_request_msg);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(0);
  }

  // Validate received message
  if (strcmp(recv_request_msg->service_name, rpc_request_msg->service_name) !=
      0) {
    libnngio_log("ERR", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
                 "Service name mismatch: expected %s, got %s",
                 rpc_request_msg->service_name, recv_request_msg->service_name);
    assert(0);
  }
  if (strcmp(recv_request_msg->method_name, rpc_request_msg->method_name) !=
      0) {
    libnngio_log("ERR", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
                 "Method name mismatch: expected %s, got %s",
                 rpc_request_msg->method_name, recv_request_msg->method_name);
    assert(0);
  }
  if (recv_request_msg->payload.len != rpc_request_msg->payload.len ||
      memcmp(recv_request_msg->payload.data, rpc_request_msg->payload.data,
             rpc_request_msg->payload.len) != 0) {
    libnngio_log("ERR", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
                 "Payload mismatch");
    assert(0);
  }

  libnngio_log("INF", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
               "RPC request sent and received successfully.");
  libnngio_log("INF", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Service: %s, Method: %s, Payload: %.*s",
               recv_request_msg->service_name, recv_request_msg->method_name,
               (int)recv_request_msg->payload.len,
               recv_request_msg->payload.data);

  libnngio_log("INF", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Sending RPC response...");
  // Prepare RPC response message
  NngioProtobuf__RpcResponseMessage *rpc_response_msg =
      nngio_create_rpc_response(
          NNGIO_PROTOBUF__RPC_RESPONSE_MESSAGE__STATUS__Success,
          (const uint8_t *)"Goodbye", 7, NULL);

#ifdef NNGIO_MOCK_MAIN
  // Mocking: set expected receive buffer for REP context
  NngioProtobuf__RpcResponseMessage *fakerpc_response =
      nngio_create_rpc_response(
          NNGIO_PROTOBUF__RPC_RESPONSE_MESSAGE__STATUS__Success,
          (const uint8_t *)"Goodbye", 7, NULL);
  NngioProtobuf__NngioMessage *fake_response_msg =
      nngio_create_nngio_message_with_rpc_response("uuid-456",
                                                   fakerpc_response);
  packed_size =
      nngio_protobuf__nngio_message__get_packed_size(fake_response_msg);
  buffer = malloc(packed_size);
  nngio_protobuf__nngio_message__pack(fake_response_msg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  nngio_free_nngio_message(fake_response_msg);
  free(buffer);
#endif

  memset(&recv_sync, 0, sizeof(async_test_sync));
  memset(&send_sync, 0, sizeof(async_test_sync));

  // Prepare to receive RPC response message
  NngioProtobuf__RpcResponseMessage *recv_response_msg = NULL;

  libnngio_log("INF", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Prepared RPC response message for sending.");

  // Receive rpc request message asynchronously
  err = libnngio_protobuf_recv_rpc_response_async(
      rep_proto_ctx, &recv_response_msg, async_recv_cb, &recv_sync);
  libnngio_log("DBG", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Prepared to receive RPC request asynchronously.");
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
                 "Failed to receive rpc request: %s",
                 libnngio_protobuf_strerror(err));
    nngio_free_rpc_request(recv_request_msg);
    nngio_free_rpc_request(rpc_request_msg);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }

  libnngio_log("INF", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Beginning async send of rpc request...");

  // Send raw message asynchronously
  err = libnngio_protobuf_send_rpc_response_async(
      req_proto_ctx, rpc_response_msg, async_send_cb, &send_sync);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
                 "Failed to send rpc request: %s",
                 libnngio_protobuf_strerror(err));
    if (err == LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR) {
      libnngio_log("ERR", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
                   "Transport error occurred while sending rpc request.");
    }
    nngio_free_rpc_response(recv_response_msg);
    nngio_free_rpc_request(recv_request_msg);
    nngio_free_rpc_request(rpc_request_msg);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }
  libnngio_log("INF", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Raw message sent asynchronously.");

  // Wait for send to complete
  while (!send_sync.done) {
    nng_msleep(10);
  }
  if (send_sync.result != 0) {
    libnngio_log("ERR", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
                 "Async send failed with result: %d", send_sync.result);
    nngio_free_rpc_response(rpc_response_msg);
    nngio_free_rpc_response(recv_response_msg);
    nngio_free_rpc_request(recv_request_msg);
    nngio_free_rpc_request(rpc_request_msg);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(0);
  }
  libnngio_log("INF", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Async send completed successfully.");

  // Wait for receive to complete
  while (!recv_sync.done) {
    nng_msleep(10);
  }
  if (recv_sync.result != 0) {
    libnngio_log("ERR", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
                 "Async receive failed with result: %d", recv_sync.result);
    nngio_free_rpc_response(rpc_response_msg);
    nngio_free_rpc_response(recv_response_msg);
    nngio_free_rpc_request(recv_request_msg);
    nngio_free_rpc_request(rpc_request_msg);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(0);
  }

  // Validate received message
  if (recv_response_msg->status != rpc_response_msg->status) {
    libnngio_log("ERR", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
                 "Status mismatch: expected %d, got %d",
                 rpc_response_msg->status, recv_response_msg->status);
    assert(0);
  }
  if (recv_response_msg->payload.len != rpc_response_msg->payload.len ||
      memcmp(recv_response_msg->payload.data, rpc_response_msg->payload.data,
             rpc_response_msg->payload.len) != 0) {
    libnngio_log("ERR", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
                 "Payload mismatch");
    assert(0);
  }

  // all this selective freeing is done because the messages are on the stack
  // and only the internal pointers need to be freed, otherwise I think that
  // the nngio_protobuf__rpc_response_message__free_unpacked could be used
  // but that would require heap allocation of the messages
  nngio_free_rpc_response(recv_response_msg);
  nngio_free_rpc_response(rpc_response_msg);
  nngio_free_rpc_request(recv_request_msg);
  nngio_free_rpc_request(rpc_request_msg);
  libnngio_protobuf_context_free(req_proto_ctx);
  libnngio_protobuf_context_free(rep_proto_ctx);
  libnngio_context_free(req_ctx);
  libnngio_context_free(rep_ctx);
  libnngio_transport_free(req);
  libnngio_transport_free(rep);
}

void test_protobuf_service_discovery_async() {
  libnngio_protobuf_error_code err;

  libnngio_transport *rep = NULL, *req = NULL;
  libnngio_config rep_cfg = {0}, req_cfg = {0};
  libnngio_context *rep_ctx = NULL, *req_ctx = NULL;
  char url[64];
  snprintf(url, sizeof(url), "tcp://127.0.0.0:5555");

  rep_cfg.url = url;
  rep_cfg.mode = LIBNNGIO_MODE_LISTEN;
  rep_cfg.proto = LIBNNGIO_PROTO_REP;
  req_cfg.url = url;
  req_cfg.mode = LIBNNGIO_MODE_DIAL;
  req_cfg.proto = LIBNNGIO_PROTO_REQ;

  int rv = libnngio_transport_init(&rep, &rep_cfg);
  if (rv != 0) {
    assert(rv == 0);
  }
  rv = libnngio_transport_init(&req, &req_cfg);
  if (rv != 0) {
    libnngio_transport_free(rep);
    assert(rv == 0);
  }
  rv = libnngio_context_init(&rep_ctx, rep, &rep_cfg, NULL, NULL);
  if (rv != 0) {
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(rv == 0);
  }
  rv = libnngio_context_init(&req_ctx, req, &req_cfg, NULL, NULL);
  if (rv != 0) {
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(rv == 0);
  }

  libnngio_log("INF", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__,
               __LINE__, -1,
               "REQ/REP transports and contexts initialized on %s", url);

  libnngio_protobuf_context *rep_proto_ctx = NULL, *req_proto_ctx = NULL;
  err = libnngio_protobuf_context_init(&rep_proto_ctx, rep_ctx);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }
  err = libnngio_protobuf_context_init(&req_proto_ctx, req_ctx);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }

  libnngio_log("INF", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__,
               __LINE__, -1, "Protobuf contexts initialized successfully.");

  // Prepare to request services
  NngioProtobuf__ServiceDiscoveryRequest *service_request =
      malloc(sizeof(NngioProtobuf__ServiceDiscoveryRequest));
  nngio_protobuf__service_discovery_request__init(service_request);
  // No fields to set for now

#ifdef NNGIO_MOCK_MAIN
  // Mocking: set expected receive buffer for REP context
  NngioProtobuf__ServiceDiscoveryRequest *fakerq =
      malloc(sizeof(NngioProtobuf__ServiceDiscoveryRequest));
  nngio_protobuf__service_discovery_request__init(fakerq);
  NngioProtobuf__NngioMessage *temp_msg =
      nngio_create_nngio_message_with_service_discovery_request("uuid-101",
                                                                fakerq);
  size_t packed_size = nngio_protobuf__nngio_message__get_packed_size(temp_msg);
  uint8_t *buffer = malloc(packed_size);
  nngio_protobuf__nngio_message__pack(temp_msg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  free(buffer);
  nngio_free_nngio_message(temp_msg);
#endif

  async_test_sync recv_sync = {0}, send_sync = {0};

  // Prepare to receive service discovery request message
  NngioProtobuf__ServiceDiscoveryRequest *recv_service_request = NULL;
  libnngio_log("INF", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__,
               __LINE__, -1,
               "Prepared service discovery request message for sending.");

  // Receive rpc request message asynchronously
  err = libnngio_protobuf_recv_service_discovery_request_async(
      rep_proto_ctx, &recv_service_request, async_recv_cb, &recv_sync);
  libnngio_log("DBG", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__,
               __LINE__, -1, "Prepared to receive RPC request asynchronously.");
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
                 "Failed to receive rpc request: %s",
                 libnngio_protobuf_strerror(err));
    free(service_request);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }

  libnngio_log("INF", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__,
               __LINE__, -1, "Beginning async send of rpc request...");

  // Send raw message asynchronously
  err = libnngio_protobuf_send_service_discovery_request_async(
      req_proto_ctx, service_request, async_send_cb, &send_sync);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__,
                 __LINE__, -1, "Failed to send rpc request: %s",
                 libnngio_protobuf_strerror(err));
    if (err == LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR) {
      libnngio_log("ERR", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
                   "Transport error occurred while sending rpc request.");
    }
    free(service_request);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }
  libnngio_log("INF", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__,
               __LINE__, -1, "Raw message sent asynchronously.");

  // Wait for send to complete
  while (!send_sync.done) {
    nng_msleep(10);
  }
  if (send_sync.result != 0) {
    libnngio_log("ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__,
                 __LINE__, -1, "Async send failed with result: %d",
                 send_sync.result);
    free(service_request);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(0);
  }
  libnngio_log("INF", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__,
               __LINE__, -1, "Async send completed successfully.");

  // Wait for receive to complete
  while (!recv_sync.done) {
    nng_msleep(10);
  }
  if (recv_sync.result != 0) {
    libnngio_log("ERR", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
                 "Async receive failed with result: %d", recv_sync.result);
    free(service_request);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(0);
  }

  // Validate received message
  // No fields to validate for now

  libnngio_log("INF", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__,
               __LINE__, -1, "Sending service discovery response...");

  // Prepare service discovery response message
  NngioProtobuf__Service *service1 =
      nngio_create_service("Echo", echo_methods, 2);
  NngioProtobuf__Service *service2 =
      nngio_create_service("Math", math_methods, 3);
  NngioProtobuf__Service *services[2] = {service1, service2};
  NngioProtobuf__ServiceDiscoveryResponse *service_response =
      nngio_create_service_discovery_response(services, 2);

#ifdef NNGIO_MOCK_MAIN
  // Mocking: set expected receive buffer for REQ context
  NngioProtobuf__Service *fakeservice1 =
      nngio_create_service("Echo", echo_methods, 2);
  NngioProtobuf__Service *fakeservice2 =
      nngio_create_service("Math", math_methods, 3);
  NngioProtobuf__Service *fakeservices[2] = {fakeservice1, fakeservice2};
  NngioProtobuf__ServiceDiscoveryResponse *fakeresp =
      nngio_create_service_discovery_response(fakeservices, 2);
  NngioProtobuf__NngioMessage *temp_resp_msg =
      nngio_create_nngio_message_with_service_discovery_response("uuid-202",
                                                                 fakeresp);
  packed_size = nngio_protobuf__nngio_message__get_packed_size(temp_resp_msg);
  buffer = malloc(packed_size);
  nngio_protobuf__nngio_message__pack(temp_resp_msg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  free(buffer);
  nngio_free_nngio_message(temp_resp_msg);
#endif

  memset(&recv_sync, 0, sizeof(async_test_sync));
  memset(&send_sync, 0, sizeof(async_test_sync));

  // Prepare to receive service discovery response message
  NngioProtobuf__ServiceDiscoveryResponse *recv_service_response = NULL;
  libnngio_log("INF", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__,
               __LINE__, -1,
               "Prepared service discovery response message for sending.");

  // Receive rpc request message asynchronously
  err = libnngio_protobuf_recv_service_discovery_response_async(
      rep_proto_ctx, &recv_service_response, async_recv_cb, &recv_sync);
  libnngio_log("DBG", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__,
               __LINE__, -1, "Prepared to receive RPC request asynchronously.");
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
                 "Failed to receive rpc request: %s",
                 libnngio_protobuf_strerror(err));
    free(service_request);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }

  libnngio_log("INF", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__,
               __LINE__, -1, "Beginning async send of rpc request...");

  // Send raw message asynchronously
  err = libnngio_protobuf_send_service_discovery_response_async(
      req_proto_ctx, service_response, async_send_cb, &send_sync);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__,
                 __LINE__, -1, "Failed to send rpc response: %s",
                 libnngio_protobuf_strerror(err));
    if (err == LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR) {
      libnngio_log("ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__,
                   __LINE__, -1,
                   "Transport error occurred while sending rpc request.");
    }
    nngio_free_service_discovery_response(service_response);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }
  libnngio_log("INF", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__,
               __LINE__, -1, "Raw message sent asynchronously.");

  // Wait for send to complete
  while (!send_sync.done) {
    nng_msleep(10);
  }
  if (send_sync.result != 0) {
    libnngio_log("ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__,
                 __LINE__, -1, "Async send failed with result: %d",
                 send_sync.result);
    nngio_free_service_discovery_response(service_response);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(0);
  }
  libnngio_log("INF", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__,
               __LINE__, -1, "Async send completed successfully.");

  // Wait for receive to complete
  while (!recv_sync.done) {
    nng_msleep(10);
  }
  if (recv_sync.result != 0) {
    libnngio_log("ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__,
                 __LINE__, -1, "Async receive failed with result: %d",
                 recv_sync.result);
    nngio_free_service_discovery_response(service_response);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(0);
  }

  // Validate received message
  if (recv_service_response->n_services != service_response->n_services) {
    libnngio_log(
        "ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__, -1,
        "Number of services mismatch: expected %d, got %d",
        service_response->n_services, recv_service_response->n_services);
    assert(0);
  }
  for (size_t i = 0; i < service_response->n_services; i++) {
    NngioProtobuf__Service *sent_service = service_response->services[i];
    NngioProtobuf__Service *recv_service = recv_service_response->services[i];
    if (strcmp(sent_service->name, recv_service->name) != 0) {
      libnngio_log("ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__,
                   __LINE__, -1,
                   "Service name mismatch at index %d: expected %s, got %s",
                   (int)i, sent_service->name, recv_service->name);
      assert(0);
    }
    if (sent_service->n_methods != recv_service->n_methods) {
      libnngio_log(
          "ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
          -1, "Number of methods mismatch for service %s: expected %d, got %d",
          sent_service->name, sent_service->n_methods, recv_service->n_methods);
      assert(0);
    }
    for (size_t j = 0; j < sent_service->n_methods; j++) {
      if (strcmp(sent_service->methods[j], recv_service->methods[j]) != 0) {
        libnngio_log("ERR", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__,
                     __LINE__, -1,
                     "Method name mismatch for service %s at index %d: "
                     "expected %s, got %s",
                     sent_service->name, (int)j, sent_service->methods[j],
                     recv_service->methods[j]);
        assert(0);
      }
    }
  }

  libnngio_log("INF", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__,
               __LINE__, -1, "Service discovery response validated.");

  nngio_free_service_discovery_response(recv_service_response);
  nngio_free_service_discovery_response(service_response);
  free(recv_service_request);
  free(service_request);
  libnngio_protobuf_context_free(req_proto_ctx);
  libnngio_protobuf_context_free(rep_proto_ctx);
  libnngio_context_free(req_ctx);
  libnngio_context_free(rep_ctx);
  libnngio_transport_free(req);
  libnngio_transport_free(rep);
}

void test_protobuf_send_recv() {
  // initialize REQ/REP transports and contexts
  libnngio_transport *rep = NULL, *req = NULL;
  libnngio_config rep_cfg = {0}, req_cfg = {0};
  libnngio_context *rep_ctx = NULL, *req_ctx = NULL;
  char url[64];
  snprintf(url, sizeof(url), "tcp://127.0.0.1:5555");
  rep_cfg.url = url;
  rep_cfg.mode = LIBNNGIO_MODE_LISTEN;
  rep_cfg.proto = LIBNNGIO_PROTO_REP;
  req_cfg.url = url;
  req_cfg.mode = LIBNNGIO_MODE_DIAL;
  req_cfg.proto = LIBNNGIO_PROTO_REQ;

  int rv;
  rv = libnngio_transport_init(&rep, &rep_cfg);
  if (rv != 0) {
    assert(rv == 0);
  }
  rv = libnngio_transport_init(&req, &req_cfg);
  if (rv != 0) {
    libnngio_transport_free(rep);
    assert(rv == 0);
  }

  rv = libnngio_context_init(&rep_ctx, rep, &rep_cfg, NULL, NULL);
  if (rv != 0) {
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(rv == 0);
  }

  rv = libnngio_context_init(&req_ctx, req, &req_cfg, NULL, NULL);
  if (rv != 0) {
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(rv == 0);
  }

  libnngio_log("INF", "TEST_PROTOBUF_SEND_RECV", __FILE__, __LINE__, -1,
               "REQ/REP transports and contexts initialized on %s", url);

  libnngio_protobuf_context *rep_proto_ctx = NULL, *req_proto_ctx = NULL;
  libnngio_protobuf_error_code err;
  err = libnngio_protobuf_context_init(&rep_proto_ctx, rep_ctx);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }

  err = libnngio_protobuf_context_init(&req_proto_ctx, req_ctx);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }

  libnngio_log("INF", "TEST_PROTOBUF_SEND_RECV", __FILE__, __LINE__, -1,
               "Protobuf contexts initialized successfully.");

  char* uuid = libnngio_protobuf_gen_uuid();
  libnngio_log("INF", "TEST_PROTOBUF_SEND_RECV", __FILE__, __LINE__, -1,
               "Generated UUID: %s", uuid);

  // Prepare to send a raw message
  NngioProtobuf__RawMessage *raw_msg =
      nngio_create_raw_message((const uint8_t *)"Hello, World!", 13);
  NngioProtobuf__NngioMessage *msg =
      nngio_create_nngio_message_with_raw(uuid, raw_msg);

#ifdef NNGIO_MOCK_MAIN
  // Mocking: set expected receive buffer for REP context
  NngioProtobuf__RawMessage *fakeraw =
      nngio_create_raw_message((const uint8_t *)"Hello, World!", 13);
  NngioProtobuf__NngioMessage *fake_msg =
      nngio_create_nngio_message_with_raw(uuid, fakeraw);
  size_t packed_size = nngio_protobuf__nngio_message__get_packed_size(fake_msg);
  uint8_t *buffer = malloc(packed_size);
  nngio_protobuf__nngio_message__pack(fake_msg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  nngio_free_nngio_message(fake_msg);
  free(buffer);
#endif

  libnngio_log("INF", "TEST_PROTOBUF_SEND_RECV", __FILE__, __LINE__, -1,
               "Prepared raw message for sending.");

  // Send raw message
  err = libnngio_protobuf_send(req_proto_ctx, msg);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "TEST_PROTOBUF_SEND_RECV", __FILE__, __LINE__, -1,
                 "Failed to send raw message: %s",
                 libnngio_protobuf_strerror(err));
    if (err == LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR) {
      libnngio_log("ERR", "TEST_PROTOBUF_SEND_RECV", __FILE__, __LINE__, -1,
                   "Transport error occurred while sending raw message.");
    }
    nngio_free_raw_message(raw_msg);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }
  libnngio_log("INF", "TEST_PROTOBUF_SEND_RECV", __FILE__, __LINE__, -1,
               "Raw message sent successfully.");

  // Prepare to receive raw message
  NngioProtobuf__NngioMessage *recv_msg = NULL;

  // Receive raw message
  err = libnngio_protobuf_recv(rep_proto_ctx, (NngioProtobuf__NngioMessage **)&recv_msg);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "TEST_PROTOBUF_SEND_RECV", __FILE__, __LINE__, -1,
                 "Failed to receive raw message: %s",
                 libnngio_protobuf_strerror(err));
    nngio_free_nngio_message(msg);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }

  // Validate received message
  if (recv_msg->raw_message->data.len != msg->raw_message->data.len ||
      memcmp(recv_msg->raw_message->data.data, msg->raw_message->data.data,
             msg->raw_message->data.len) != 0) {
    libnngio_log("ERR", "TEST_PROTOBUF_SEND_RECV", __FILE__, __LINE__, -1,
                 "Payload mismatch");
    nngio_free_nngio_message(recv_msg);
    nngio_free_nngio_message(msg);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(0);
  }

  libnngio_log("INF", "TEST_PROTOBUF_SEND_RECV", __FILE__, __LINE__, -1,
               "Raw message sent and received successfully.");
  libnngio_log("INF", "TEST_PROTOBUF_SEND_RECV", __FILE__, __LINE__, -1,
               "data: %.*s", (int)recv_msg->raw_message->data.len,
               recv_msg->raw_message->data.data);

  free(uuid);
  nngio_free_nngio_message(recv_msg);
  nngio_free_nngio_message(msg);
  libnngio_protobuf_context_free(req_proto_ctx);
  libnngio_protobuf_context_free(rep_proto_ctx);
  libnngio_context_free(req_ctx);
  libnngio_context_free(rep_ctx);
  libnngio_transport_free(req);
  libnngio_transport_free(rep);
}

void test_protobuf_send_recv_async() {
  libnngio_transport *rep = NULL, *req = NULL;
  libnngio_config rep_cfg = {0}, req_cfg = {0};
  libnngio_context *rep_ctx = NULL, *req_ctx = NULL;
  char url[64];
  snprintf(url, sizeof(url), "tcp://127.0.0.1:5555");
  rep_cfg.url = url;
  rep_cfg.mode = LIBNNGIO_MODE_LISTEN;
  rep_cfg.proto = LIBNNGIO_PROTO_REP;
  req_cfg.url = url;
  req_cfg.mode = LIBNNGIO_MODE_DIAL;
  req_cfg.proto = LIBNNGIO_PROTO_REQ;

  int rv;
  rv = libnngio_transport_init(&rep, &rep_cfg);
  if (rv != 0) {
    assert(rv == 0);
  }
  rv = libnngio_transport_init(&req, &req_cfg);
  if (rv != 0) {
    libnngio_transport_free(rep);
    assert(rv == 0);
  }

  rv = libnngio_context_init(&rep_ctx, rep, &rep_cfg, NULL, NULL);
  if (rv != 0) {
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(rv == 0);
  }

  rv = libnngio_context_init(&req_ctx, req, &req_cfg, NULL, NULL);
  if (rv != 0) {
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(rv == 0);
  }

  libnngio_log("INF", "TEST_PROTOBUF_SEND_RECV_ASYNC", __FILE__, __LINE__, -1,
               "REQ/REP transports and contexts initialized on %s", url);

  libnngio_protobuf_context *rep_proto_ctx = NULL, *req_proto_ctx = NULL;
  libnngio_protobuf_error_code err;
  err = libnngio_protobuf_context_init(&rep_proto_ctx, rep_ctx);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }

  err = libnngio_protobuf_context_init(&req_proto_ctx, req_ctx);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }

  libnngio_log("INF", "TEST_PROTOBUF_SEND_RECV_ASYNC", __FILE__, __LINE__, -1,
               "Protobuf contexts initialized successfully.");

  char* uuid = libnngio_protobuf_gen_uuid();
  libnngio_log("INF", "TEST_PROTOBUF_SEND_RECV_ASYNC", __FILE__, __LINE__, -1,
               "Generated UUID: %s", uuid);

  // Prepare to send a raw message
  NngioProtobuf__RawMessage *raw_msg =
      nngio_create_raw_message((const uint8_t *)"Hello, World!", 13);
  NngioProtobuf__NngioMessage *msg =
      nngio_create_nngio_message_with_raw(uuid, raw_msg);

  libnngio_log("INF", "TEST_PROTOBUF_SEND_RECV_ASYNC", __FILE__, __LINE__, -1,
               "Prepared raw message for sending with UUID: %s, msg: %p, raw: %p",
               uuid, (void*)msg, (void*)raw_msg);
  libnngio_log("INF", "TEST_PROTOBUF_SEND_RECV_ASYNC", __FILE__, __LINE__, -1,
               "Raw message data: %.*s", (int)raw_msg->data.len, raw_msg->data.data);

  libnngio_log("INF", "TEST_PROTOBUF_SEND_RECV_ASYNC", __FILE__, __LINE__, -1,
               "msg pointer: %p", (void*)msg);

#ifdef NNGIO_MOCK_MAIN
  // Mocking: set expected receive buffer for REP context
  NngioProtobuf__RawMessage *fakeraw =
      nngio_create_raw_message((const uint8_t *)"Hello, World!", 13);
  NngioProtobuf__NngioMessage *fake_msg =
      nngio_create_nngio_message_with_raw(uuid, fakeraw);
  size_t packed_size = nngio_protobuf__nngio_message__get_packed_size(fake_msg);
  uint8_t *buffer = malloc(packed_size);
  nngio_protobuf__nngio_message__pack(fake_msg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  nngio_free_nngio_message(fake_msg);
  free(buffer);
#endif

  async_test_sync recv_sync = {0}, send_sync = {0};

  libnngio_log("INF", "TEST_PROTOBUF_SEND_RECV_ASYNC", __FILE__, __LINE__, -1,
               "Prepared raw message for sending.");

  // Prepare to receive raw message
  NngioProtobuf__NngioMessage **recv_msg = NULL;
  recv_msg = malloc(sizeof(NngioProtobuf__NngioMessage *));
  *recv_msg = NULL;

  // Receive raw message asynchronously
  err = libnngio_protobuf_recv_async(rep_proto_ctx, recv_msg,
                                    async_recv_cb, &recv_sync);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "TEST_PROTOBUF_SEND_RECV_ASYNC", __FILE__, __LINE__, -1,
                 "Failed to receive raw message: %s",
                 libnngio_protobuf_strerror(err));
    nngio_free_nngio_message(msg);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }
  libnngio_log("INF", "TEST_PROTOBUF_SEND_RECV_ASYNC", __FILE__, __LINE__, -1,
               "Prepared to receive raw message asynchronously.");

  // Send raw message asynchronously
  err = libnngio_protobuf_send_async(req_proto_ctx, msg, async_send_cb, &send_sync);
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "TEST_PROTOBUF_SEND_RECV_ASYNC", __FILE__, __LINE__, -1,
                 "Failed to send raw message: %s",
                 libnngio_protobuf_strerror(err));
    if (err == LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR) {
      libnngio_log("ERR", "TEST_PROTOBUF_SEND_RECV_ASYNC", __FILE__, __LINE__, -1,
                   "Transport error occurred while sending raw message.");
    }
    nngio_free_nngio_message(msg);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(err == LIBNNGIO_PROTOBUF_ERR_NONE);
  }
  libnngio_log("INF", "TEST_PROTOBUF_SEND_RECV_ASYNC", __FILE__, __LINE__, -1,
               "Raw message send initiated asynchronously.");

  // Wait for send to complete
  while (!send_sync.done) {
    nng_msleep(10);
  }
  if (send_sync.result != 0) {
    libnngio_log("ERR", "TEST_PROTOBUF_SEND_RECV_ASYNC", __FILE__, __LINE__, -1,
                 "Async send failed with result: %d", send_sync.result);
    nngio_free_nngio_message(msg);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(0);
  }
  libnngio_log("INF", "TEST_PROTOBUF_SEND_RECV_ASYNC", __FILE__, __LINE__, -1,
               "Async send completed successfully.");

  // Wait for receive to complete
  while (!recv_sync.done) {
    nng_msleep(10);
  }
  if (recv_sync.result != 0) {
    libnngio_log("ERR", "TEST_PROTOBUF_SEND_RECV_ASYNC", __FILE__, __LINE__, -1,
                 "Async receive failed with result: %d", recv_sync.result);
    nngio_free_nngio_message(msg);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(0);
  }
  assert(recv_msg != NULL);


  libnngio_log("INF", "TEST_PROTOBUF_SEND_RECV_ASYNC", __FILE__, __LINE__, -1,
               "Async receive completed successfully, recv_msg: %p, *recv_msg: %p",
               (void*)recv_msg, (void*)(*recv_msg));

  // Validate received message
  if ((*recv_msg)->raw_message->data.len != msg->raw_message->data.len ||
      memcmp((*recv_msg)->raw_message->data.data, msg->raw_message->data.data,
             msg->raw_message->data.len) != 0) {
    libnngio_log("ERR", "TEST_PROTOBUF_SEND_RECV_ASYNC_ASYNC", __FILE__, __LINE__, -1,
                 "Payload mismatch");
    libnngio_log("ERR", "TEST_PROTOBUF_SEND_RECV_ASYNC_ASYNC", __FILE__, __LINE__, -1,
                 "Expected (%zu): %.*s", msg->raw_message->data.len,
                 (int)msg->raw_message->data.len, msg->raw_message->data.data);
    libnngio_log("ERR", "TEST_PROTOBUF_SEND_RECV_ASYNC_ASYNC", __FILE__, __LINE__, -1,
                 "Received (%zu): %.*s", (*recv_msg)->raw_message->data.len,
                 (int)(*recv_msg)->raw_message->data.len, (*recv_msg)->raw_message->data.data);
    nngio_free_nngio_message(*recv_msg);
    nngio_free_nngio_message(msg);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(req_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(0);
  }

  libnngio_log("INF", "TEST_PROTOBUF_SEND_RECV", __FILE__, __LINE__, -1,
               "Raw message sent and received successfully.");
  libnngio_log("INF", "TEST_PROTOBUF_SEND_RECV", __FILE__, __LINE__, -1,
               "data: %.*s", (int)(*recv_msg)->raw_message->data.len,
               (*recv_msg)->raw_message->data.data);

  free(uuid);
  nngio_free_nngio_message(*recv_msg);
  free(recv_msg);
  nngio_free_nngio_message(msg);
  libnngio_protobuf_context_free(req_proto_ctx);
  libnngio_protobuf_context_free(rep_proto_ctx);
  libnngio_context_free(req_ctx);
  libnngio_context_free(rep_ctx);
  libnngio_transport_free(req);
  libnngio_transport_free(rep);
}

// Service implementation test handlers

static NngioProtobuf__RpcResponseMessage__Status echo_say_hello_handler(
    const char *service_name, const char *method_name,
    const void *request_payload, size_t request_payload_len,
    void **response_payload, size_t *response_payload_len,
    void *user_data) {
  (void)service_name;
  (void)method_name;
  (void)user_data;
  
  // Simple echo: prepend "Hello, " to the input
  const char *prefix = "Hello, ";
  size_t prefix_len = strlen(prefix);
  
  *response_payload_len = prefix_len + request_payload_len;
  *response_payload = malloc(*response_payload_len);
  if (*response_payload == NULL) {
    *response_payload_len = 0;
    return NNGIO_PROTOBUF__RPC_RESPONSE_MESSAGE__STATUS__InternalError;
  }
  
  memcpy(*response_payload, prefix, prefix_len);
  memcpy((char*)*response_payload + prefix_len, request_payload, request_payload_len);
  
  return NNGIO_PROTOBUF__RPC_RESPONSE_MESSAGE__STATUS__Success;
}

static NngioProtobuf__RpcResponseMessage__Status math_add_handler(
    const char *service_name, const char *method_name,
    const void *request_payload, size_t request_payload_len,
    void **response_payload, size_t *response_payload_len,
    void *user_data) {
  (void)service_name;
  (void)method_name;
  (void)user_data;
  
  // Expect two 4-byte integers in request
  if (request_payload_len != 8) {
    *response_payload = NULL;
    *response_payload_len = 0;
    return NNGIO_PROTOBUF__RPC_RESPONSE_MESSAGE__STATUS__InvalidRequest;
  }
  
  const int *inputs = (const int*)request_payload;
  int result = inputs[0] + inputs[1];
  
  *response_payload_len = sizeof(int);
  *response_payload = malloc(*response_payload_len);
  if (*response_payload == NULL) {
    *response_payload_len = 0;
    return NNGIO_PROTOBUF__RPC_RESPONSE_MESSAGE__STATUS__InternalError;
  }
  
  memcpy(*response_payload, &result, sizeof(int));
  return NNGIO_PROTOBUF__RPC_RESPONSE_MESSAGE__STATUS__Success;
}

void test_service_implementation() {
  libnngio_log("INF", "TEST_SERVICE_IMPLEMENTATION", __FILE__, __LINE__, -1,
               "Testing service registration, discovery, and RPC calls...");

  // Initialize transport and contexts
  libnngio_config rep_cfg = {
      .mode = LIBNNGIO_MODE_LISTEN,
      .proto = LIBNNGIO_PROTO_REP,
      .url = "tcp://127.0.0.1:6666",
      .tls_cert = NULL,
      .tls_key = NULL,
      .tls_ca_cert = NULL};

  libnngio_config req_cfg = {
      .mode = LIBNNGIO_MODE_DIAL,
      .proto = LIBNNGIO_PROTO_REQ,
      .url = "tcp://127.0.0.1:6666",
      .tls_cert = NULL,
      .tls_key = NULL,
      .tls_ca_cert = NULL};

  libnngio_transport *rep = NULL, *req = NULL;
  libnngio_context *rep_ctx = NULL, *req_ctx = NULL;
  libnngio_protobuf_context *rep_proto_ctx = NULL, *req_proto_ctx = NULL;

  int rv = libnngio_transport_init(&rep, &rep_cfg);
  if (rv != 0) {
    assert(rv == 0);
  }
  rv = libnngio_transport_init(&req, &req_cfg);
  if (rv != 0) {
    libnngio_transport_free(rep);
    assert(rv == 0);
  }
  rv = libnngio_context_init(&rep_ctx, rep, &rep_cfg, NULL, NULL);
  if (rv != 0) {
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(rv == 0);
  }
  rv = libnngio_context_init(&req_ctx, req, &req_cfg, NULL, NULL);
  if (rv != 0) {
    libnngio_context_free(rep_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(rv == 0);
  }

  // Initialize protobuf contexts
  libnngio_protobuf_error_code proto_rv = libnngio_protobuf_context_init(&rep_proto_ctx, rep_ctx);
  if (proto_rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_context_free(rep_ctx);
    libnngio_context_free(req_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
  }

  proto_rv = libnngio_protobuf_context_init(&req_proto_ctx, req_ctx);
  if (proto_rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_context_free(req_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
  }

  // Initialize server and register services
  libnngio_server *server = NULL;
  proto_rv = libnngio_server_init(&server, rep_proto_ctx);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  // Register Echo service
  libnngio_service_method echo_methods_reg[] = {
    {"SayHello", echo_say_hello_handler, NULL},
    {"SayGoodbye", echo_say_hello_handler, NULL}
  };
  proto_rv = libnngio_server_register_service(server, "Echo", echo_methods_reg, 2);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  // Register Math service
  libnngio_service_method math_methods_reg[] = {
    {"Add", math_add_handler, NULL},
    {"Subtract", math_add_handler, NULL},
    {"Multiply", math_add_handler, NULL}
  };
  proto_rv = libnngio_server_register_service(server, "Math", math_methods_reg, 3);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  libnngio_log("INF", "TEST_SERVICE_IMPLEMENTATION", __FILE__, __LINE__, -1,
               "Server initialized with Echo and Math services.");

  // Initialize client
  libnngio_client *client = NULL;
  proto_rv = libnngio_client_init(&client, req_proto_ctx);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  libnngio_log("INF", "TEST_SERVICE_IMPLEMENTATION", __FILE__, __LINE__, -1,
               "Client initialized.");

  // Test service discovery
  libnngio_log("INF", "TEST_SERVICE_IMPLEMENTATION", __FILE__, __LINE__, -1,
               "Testing service discovery...");

#ifdef NNGIO_MOCK_MAIN
  // Mock service discovery response
  NngioProtobuf__Service *mock_echo = nngio_create_service("Echo", echo_methods, 2);
  NngioProtobuf__Service *mock_math = nngio_create_service("Math", math_methods, 3);
  NngioProtobuf__Service *mock_services[2] = {mock_echo, mock_math};
  NngioProtobuf__ServiceDiscoveryResponse *mock_response =
      nngio_create_service_discovery_response(mock_services, 2);
  NngioProtobuf__NngioMessage *mock_response_msg =
      nngio_create_nngio_message_with_service_discovery_response("uuid-discovery", mock_response);
  
  size_t packed_size = nngio_protobuf__nngio_message__get_packed_size(mock_response_msg);
  uint8_t *buffer = malloc(packed_size);
  nngio_protobuf__nngio_message__pack(mock_response_msg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  free(buffer);
  nngio_free_nngio_message(mock_response_msg);
#endif

  // Call the actual service discovery function
  proto_rv = libnngio_client_discover_services(client);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  assert(client->n_discovered_services == 2);
  assert(strcmp(client->discovered_services[0]->name, "Echo") == 0);
  assert(strcmp(client->discovered_services[1]->name, "Math") == 0);

  libnngio_log("INF", "TEST_SERVICE_IMPLEMENTATION", __FILE__, __LINE__, -1,
               "Service discovery completed. Found %zu services.", client->n_discovered_services);

  // Test Echo RPC call
  libnngio_log("INF", "TEST_SERVICE_IMPLEMENTATION", __FILE__, __LINE__, -1,
               "Testing Echo RPC call...");

  const char *echo_input = "World";
  void *echo_output = NULL;
  size_t echo_output_len = 0;

#ifdef NNGIO_MOCK_MAIN
  // Mock RPC response for Echo service
  NngioProtobuf__RpcResponseMessage *mock_rpc_response =
      nngio_create_rpc_response(NNGIO_PROTOBUF__RPC_RESPONSE_MESSAGE__STATUS__SUCCESS,
                               "Hello, World", strlen("Hello, World"), NULL);
  NngioProtobuf__NngioMessage *mock_rpc_msg =
      nngio_create_nngio_message_with_rpc_response("uuid-rpc", mock_rpc_response);
  
  size_t packed_size = nngio_protobuf__nngio_message__get_packed_size(mock_rpc_msg);
  uint8_t *buffer = malloc(packed_size);
  nngio_protobuf__nngio_message__pack(mock_rpc_msg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  free(buffer);
  nngio_free_nngio_message(mock_rpc_msg);
#endif

  // Call the actual RPC method
  proto_rv = libnngio_client_call_rpc(client, "Echo", "SayHello", 
                                     echo_input, strlen(echo_input),
                                     &echo_output, &echo_output_len);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
  assert(echo_output != NULL);
  assert(echo_output_len == strlen("Hello, World"));
  assert(memcmp(echo_output, "Hello, World", echo_output_len) == 0);

  libnngio_log("INF", "TEST_SERVICE_IMPLEMENTATION", __FILE__, __LINE__, -1,
               "Echo RPC call successful. Response: %.*s", (int)echo_output_len, (char*)echo_output);

  free(echo_output);

  // Test Math RPC call
  libnngio_log("INF", "TEST_SERVICE_IMPLEMENTATION", __FILE__, __LINE__, -1,
               "Testing Math RPC call...");

  int math_inputs[2] = {5, 3};
  void *math_output = NULL;
  size_t math_output_len = 0;

#ifdef NNGIO_MOCK_MAIN
  // Mock RPC response for Math service
  int expected_result = 8;
  NngioProtobuf__RpcResponseMessage *mock_math_response =
      nngio_create_rpc_response(NNGIO_PROTOBUF__RPC_RESPONSE_MESSAGE__STATUS__SUCCESS,
                               &expected_result, sizeof(int), NULL);
  NngioProtobuf__NngioMessage *mock_math_msg =
      nngio_create_nngio_message_with_rpc_response("uuid-math", mock_math_response);
  
  size_t packed_size = nngio_protobuf__nngio_message__get_packed_size(mock_math_msg);
  uint8_t *buffer = malloc(packed_size);
  nngio_protobuf__nngio_message__pack(mock_math_msg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  free(buffer);
  nngio_free_nngio_message(mock_math_msg);
#endif

  // Call the actual Math RPC method
  proto_rv = libnngio_client_call_rpc(client, "Math", "Add",
                                     math_inputs, sizeof(math_inputs),
                                     &math_output, &math_output_len);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
  assert(math_output != NULL);
  assert(math_output_len == sizeof(int));
  assert(*(int*)math_output == 8);

  libnngio_log("INF", "TEST_SERVICE_IMPLEMENTATION", __FILE__, __LINE__, -1,
               "Math RPC call successful. %d + %d = %d", math_inputs[0], math_inputs[1], *(int*)math_output);

  free(math_output);

  // Clean up
  libnngio_client_free(client);
  libnngio_server_free(server);
  libnngio_protobuf_context_free(rep_proto_ctx);
  libnngio_protobuf_context_free(req_proto_ctx);
  libnngio_context_free(rep_ctx);
  libnngio_context_free(req_ctx);
  libnngio_transport_free(rep);
  libnngio_transport_free(req);

  libnngio_log("INF", "TEST_SERVICE_IMPLEMENTATION", __FILE__, __LINE__, -1,
               "Service implementation test completed successfully.");
}

/**
 * @brief Main function to run the protobuf tests
 */
int main() {
  atexit(libnngio_cleanup);

  const char *loglevelstr = getenv("NNGIO_LOGLEVEL");
  printf("Beginning protobuf tests...\n");
  libnngio_log_init(loglevelstr);
  test_protobuf_serde();
  test_protobuf_helpers();
  test_protobuf_raw_message();
  test_protobuf_rpc();
  test_protobuf_service_discovery();
  test_protobuf_raw_message_async();
  test_protobuf_rpc_async();
  test_protobuf_service_discovery_async();
  test_protobuf_send_recv();
  test_protobuf_send_recv_async();
  test_service_implementation();
  return 0;
}

