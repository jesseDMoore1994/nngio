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
  LibnngioProtobuf__RpcRequest rpc_request_msg =
      LIBNNGIO_PROTOBUF__RPC_REQUEST__INIT;
  LibnngioProtobuf__LibnngioMessage nngio_msg =
      LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__INIT;
  void *buf = NULL;
  size_t len = 0;

  nngio_msg.uuid = libnngio_protobuf_gen_uuid();
  nngio_msg.msg_case = LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RPC_REQUEST;
  nngio_msg.rpc_request = &rpc_request_msg;
  libnngio_protobuf__rpc_request__init(nngio_msg.rpc_request);
  nngio_msg.rpc_request->service_name = strdup("TestService");
  nngio_msg.rpc_request->method_name = strdup("TestMethod");
  nngio_msg.rpc_request->payload.len = 5;
  nngio_msg.rpc_request->payload.data = malloc(5);
  memcpy(nngio_msg.rpc_request->payload.data, "Hello", 5);

  len = libnngio_protobuf__libnngio_message__get_packed_size(&nngio_msg);
  buf = malloc(len);
  libnngio_protobuf__libnngio_message__pack(&nngio_msg, buf);

  free(nngio_msg.uuid);
  free(nngio_msg.rpc_request->service_name);
  free(nngio_msg.rpc_request->method_name);
  free(nngio_msg.rpc_request->payload.data);

  LibnngioProtobuf__LibnngioMessage *unpacked_msg =
      libnngio_protobuf__libnngio_message__unpack(NULL, len, buf);
  if (unpacked_msg == NULL) {
    libnngio_log("ERR", "TEST_PROTOBUF_SERDE", __FILE__, __LINE__, -1,
                 "Failed to unpack message");
    free(buf);
    return;
  }

  if (unpacked_msg->msg_case !=
      LIBNNGIO_PROTOBUF__LIBNNGIO_MESSAGE__MSG_RPC_REQUEST) {
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

  libnngio_protobuf__libnngio_message__free_unpacked(unpacked_msg, NULL);
  free(buf);
}

static const char *echo_methods[] = {"SayHello", "SayGoodbye"};
static const char *math_methods[] = {"Add", "Subtract", "Multiply"};
void test_protobuf_helpers() {
  // ---- Test Service ----
  LibnngioProtobuf__Service *svc =
      nngio_create_service("Echo", echo_methods, 2);
  if (!svc) {
    fprintf(stderr, "Failed to create Echo service\n");
    assert(0);
  }
  nngio_free_service(svc);

  // ---- Test ServiceDiscoveryResponse ----
  LibnngioProtobuf__Service *svc1 =
      nngio_create_service("Echo", echo_methods, 2);
  LibnngioProtobuf__Service *svc2 =
      nngio_create_service("Math", math_methods, 3);
  LibnngioProtobuf__Service *services[2] = {svc1, svc2};
  LibnngioProtobuf__ServiceDiscoveryResponse *resp =
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
  LibnngioProtobuf__RpcRequest *req =
      nngio_create_rpc_request("Echo", "SayHello", payload, sizeof(payload));
  if (!req) {
    fprintf(stderr, "Failed to create RPC request\n");
    assert(0);
  }
  nngio_free_rpc_request(req);

  // ---- Test RpcResponseMessage ----
  LibnngioProtobuf__RpcResponse *rresp = nngio_create_rpc_response(
      LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success, payload,
      sizeof(payload), NULL);
  if (!rresp) {
    fprintf(stderr, "Failed to create RPC response\n");
    assert(0);
  }
  nngio_free_rpc_response(rresp);

  // ---- Test RawMessage ----
  LibnngioProtobuf__Raw *raw =
      nngio_create_raw_message(payload, sizeof(payload));
  if (!raw) {
    fprintf(stderr, "Failed to create RawMessage\n");
    assert(0);
  }
  nngio_free_raw_message(raw);

  // ---- Test NngioMessage (RPC Request) ----
  req = nngio_create_rpc_request("Echo", "SayHello", payload, sizeof(payload));
  LibnngioProtobuf__LibnngioMessage *nmsg =
      nngio_create_nngio_message_with_rpc_request("uuid-123", req);
  if (!nmsg) {
    fprintf(stderr, "Failed to create NngioMessage (RPC request)\n");
    nngio_free_rpc_request(req);
    assert(0);
  }
  nngio_free_nngio_message(nmsg);  // This will free req too

  // ---- Test NngioMessage (RPC Response) ----
  rresp = nngio_create_rpc_response(
      LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success, payload,
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
  LibnngioProtobuf__ServiceDiscoveryRequest *sdreq =
      malloc(sizeof(LibnngioProtobuf__ServiceDiscoveryRequest));
  if (!sdreq) {
    fprintf(stderr, "Failed to allocate ServiceDiscoveryRequest\n");
    assert(0);
  }
  libnngio_protobuf__service_discovery_request__init(sdreq);
  nmsg = nngio_create_nngio_message_with_service_discovery_request("uuid-101",
                                                                   sdreq);
  if (!nmsg) {
    fprintf(stderr, "Failed to create NngioMessage (SD request)\n");
    libnngio_protobuf__service_discovery_request__free_unpacked(sdreq, NULL);
    assert(0);
  }
  nngio_free_nngio_message(nmsg);

  // ---- Test NngioMessage (ServiceDiscoveryResponse) ----
  svc1 = nngio_create_service("Echo", echo_methods, 2);
  svc2 = nngio_create_service("Math", math_methods, 3);
  LibnngioProtobuf__Service *services2[2] = {svc1, svc2};
  resp = nngio_create_service_discovery_response(services2, 2);
  nmsg = nngio_create_nngio_message_with_service_discovery_response("uuid-102",
                                                                    resp);
  if (!nmsg) {
    fprintf(stderr, "Failed to create NngioMessage (SD response)\n");
    nngio_free_service_discovery_response(resp);
    assert(0);
  }
  nngio_free_nngio_message(nmsg);

  // ---- Test Transports ----
  libnngio_config cfg = {0};
  cfg.mode = LIBNNGIO_MODE_DIAL;
  cfg.proto = LIBNNGIO_PROTO_REQ;
  cfg.url = "tcp://127.0.0.1:5555";
  // AddTransportRequest and AddTransportResponse
  LibnngioProtobuf__AddTransportRequest *atreq =
      nngio_create_add_transport_request(&cfg);
  nmsg =
      nngio_create_nngio_message_with_add_transport_request("uuid-100", atreq);
  if (!nmsg) {
    fprintf(stderr, "Failed to create NngioMessage (AddTransportRequest)\n");
    libnngio_protobuf__add_transport_request__free_unpacked(atreq, NULL);
    assert(0);
  }
  nngio_free_nngio_message(nmsg);
  // Note: AddTransportResponse not implemented, because it is simply an empty
  // message

  // GetTransportsRequest and GetTransportsResponse
  // Note: GetTransportsRequest not implemented, because it is simply an empty
  // message
  libnngio_config **configs = malloc(1 * sizeof(libnngio_config *));
  configs[0] = malloc(sizeof(libnngio_config));
  memset(configs[0], 0, sizeof(libnngio_config));
  configs[0]->name = "req-1";
  configs[0]->mode = LIBNNGIO_MODE_DIAL;
  configs[0]->proto = LIBNNGIO_PROTO_REQ;
  configs[0]->url = "tcp://127.0.0.1:5555";
  LibnngioProtobuf__GetTransportsResponse *gtresp =
      nngio_create_get_transports_response(configs, 1);
  nmsg = nngio_create_nngio_message_with_get_transports_response("uuid-103",
                                                                 gtresp);
  if (!nmsg) {
    fprintf(stderr, "Failed to create NngioMessage (GetTransportsResponse)\n");
    libnngio_protobuf__get_transports_response__free_unpacked(gtresp, NULL);
    assert(0);
  }
  nngio_free_nngio_message(nmsg);
  free(configs[0]);
  free(configs);

  // RemoveTransportRequest and RemoveTransportResponse
  LibnngioProtobuf__RemoveTransportRequest *rtreq =
      nngio_create_remove_transport_request("req-1", LIBNNGIO_MODE_DIAL,
                                            LIBNNGIO_PROTO_REQ,
                                            "tcp://127.0.0.1:5555");
  nmsg = nngio_create_nngio_message_with_remove_transport_request("uuid-104",
                                                                  rtreq);
  if (!nmsg) {
    fprintf(stderr, "Failed to create NngioMessage (RemoveTransportRequest)\n");
    libnngio_protobuf__remove_transport_request__free_unpacked(rtreq, NULL);
    assert(0);
  }
  nngio_free_nngio_message(nmsg);
  // Note: RemoveTransportResponse not implemented, because it is simply an
  // empty message
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
  LibnngioProtobuf__Raw *raw = nngio_create_raw_message(raw_msg, raw_msg_len);
  libnngio_log("INF", "TEST_PROTOBUF_RAW_MESSAGE", __FILE__, __LINE__, -1,
               "Prepared raw message for sending: %s", raw_msg);

#ifdef NNGIO_MOCK_TRANSPORT
  // Mocking: set expected receive buffer for REP context
  LibnngioProtobuf__Raw *fakeraw =
      nngio_create_raw_message(raw_msg, raw_msg_len);
  LibnngioProtobuf__LibnngioMessage *fakenmsg =
      nngio_create_nngio_message_with_raw("uuid-789", fakeraw);
  size_t packed_size =
      libnngio_protobuf__libnngio_message__get_packed_size(fakenmsg);
  uint8_t *buffer = malloc(packed_size);
  libnngio_protobuf__libnngio_message__pack(fakenmsg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  free(buffer);
  nngio_free_nngio_message(fakenmsg);
#endif

  // Prepare to receive raw message
  LibnngioProtobuf__Raw *recv_raw_message = NULL;

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
    libnngio_protobuf__raw__free_unpacked(recv_raw_message, NULL);
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
  LibnngioProtobuf__RpcRequest *rpc_request_msg = nngio_create_rpc_request(
      "TestService", "TestMethod", (const uint8_t *)"Hello", 5);

#ifdef NNGIO_MOCK_TRANSPORT
  // Mocking: set expected receive buffer for REP context
  LibnngioProtobuf__RpcRequest *fakerpc = nngio_create_rpc_request(
      "TestService", "TestMethod", (const uint8_t *)"Hello", 5);
  LibnngioProtobuf__LibnngioMessage *fakemsg =
      nngio_create_nngio_message_with_rpc_request("uuid-123", fakerpc);
  size_t packed_size =
      libnngio_protobuf__libnngio_message__get_packed_size(fakemsg);
  uint8_t *buffer = malloc(packed_size);
  libnngio_protobuf__libnngio_message__pack(fakemsg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  nngio_free_nngio_message(fakemsg);
  free(buffer);
#endif

  // Prepare to receive RPC request message
  LibnngioProtobuf__RpcRequest *recv_request_msg = NULL;

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
  LibnngioProtobuf__RpcResponse *rpc_response_msg = nngio_create_rpc_response(
      LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success,
      (const uint8_t *)"Goodbye", 7, NULL);

#ifdef NNGIO_MOCK_TRANSPORT
  // Mocking: set expected receive buffer for REP context
  LibnngioProtobuf__RpcResponse *fakerpc_response = nngio_create_rpc_response(
      LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success,
      (const uint8_t *)"Goodbye", 7, NULL);
  LibnngioProtobuf__LibnngioMessage *fake_response_msg =
      nngio_create_nngio_message_with_rpc_response("uuid-456",
                                                   fakerpc_response);
  packed_size =
      libnngio_protobuf__libnngio_message__get_packed_size(fake_response_msg);
  buffer = malloc(packed_size);
  libnngio_protobuf__libnngio_message__pack(fake_response_msg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  nngio_free_nngio_message(fake_response_msg);
  free(buffer);
#endif

  // Prepare to receive RPC response message
  LibnngioProtobuf__RpcResponse *recv_response_msg = NULL;

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
  // the libnngio_protobuf__rpc_response__free_unpacked could be used
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
  LibnngioProtobuf__ServiceDiscoveryRequest *service_request =
      malloc(sizeof(LibnngioProtobuf__ServiceDiscoveryRequest));
  libnngio_protobuf__service_discovery_request__init(service_request);
  // No fields to set for now

#ifdef NNGIO_MOCK_TRANSPORT
  // Mocking: set expected receive buffer for REP context
  LibnngioProtobuf__ServiceDiscoveryRequest *fakerq =
      malloc(sizeof(LibnngioProtobuf__ServiceDiscoveryRequest));
  libnngio_protobuf__service_discovery_request__init(fakerq);
  LibnngioProtobuf__LibnngioMessage *temp_msg =
      nngio_create_nngio_message_with_service_discovery_request("uuid-101",
                                                                fakerq);
  size_t packed_size =
      libnngio_protobuf__libnngio_message__get_packed_size(temp_msg);
  uint8_t *buffer = malloc(packed_size);
  libnngio_protobuf__libnngio_message__pack(temp_msg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  free(buffer);
  nngio_free_nngio_message(temp_msg);
#endif

  // Prepare to receive service discovery request message
  LibnngioProtobuf__ServiceDiscoveryRequest *recv_service_request = NULL;
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
  LibnngioProtobuf__Service *service1 =
      nngio_create_service("Echo", echo_methods, 2);
  LibnngioProtobuf__Service *service2 =
      nngio_create_service("Math", math_methods, 3);
  LibnngioProtobuf__Service *services[2] = {service1, service2};
  LibnngioProtobuf__ServiceDiscoveryResponse *service_response =
      nngio_create_service_discovery_response(services, 2);

#ifdef NNGIO_MOCK_TRANSPORT
  // Mocking: set expected receive buffer for REQ context
  LibnngioProtobuf__Service *fakeservice1 =
      nngio_create_service("Echo", echo_methods, 2);
  LibnngioProtobuf__Service *fakeservice2 =
      nngio_create_service("Math", math_methods, 3);
  LibnngioProtobuf__Service *fakeservices[2] = {fakeservice1, fakeservice2};
  LibnngioProtobuf__ServiceDiscoveryResponse *fakeresp =
      nngio_create_service_discovery_response(fakeservices, 2);
  LibnngioProtobuf__LibnngioMessage *temp_resp_msg =
      nngio_create_nngio_message_with_service_discovery_response("uuid-202",
                                                                 fakeresp);
  packed_size =
      libnngio_protobuf__libnngio_message__get_packed_size(temp_resp_msg);
  buffer = malloc(packed_size);
  libnngio_protobuf__libnngio_message__pack(temp_resp_msg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  free(buffer);
  nngio_free_nngio_message(temp_resp_msg);
#endif

  // Prepare to receive service discovery response message
  LibnngioProtobuf__ServiceDiscoveryResponse *recv_service_response = NULL;
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
    LibnngioProtobuf__Service *sent_service = service_response->services[i];
    LibnngioProtobuf__Service *recv_service =
        recv_service_response->services[i];
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
  volatile int done;                       /**< Flag to indicate completion */
  int result;                              /**< Result of the async operation */
  LibnngioProtobuf__LibnngioMessage **msg; /**< Message pointer */
} async_test_sync;

/**
 * @brief Test async recv callback
 */
void async_recv_cb(libnngio_protobuf_context *ctx, int result,
                   LibnngioProtobuf__LibnngioMessage **msg, void *user_data) {
  libnngio_log("INF", "TEST_ASYNC_RECV_CB", __FILE__, __LINE__, -1,
               "Async recv callback called with result=%d", result);
  libnngio_log("INF", "TEST_ASYNC_RECV_CB", __FILE__, __LINE__, -1,
               "Message UUID: %s", msg && *msg ? (*msg)->uuid : "NULL");
  libnngio_log(
      "INF", "TEST_ASYNC_RECV_CB", __FILE__, __LINE__, -1, "Message case: %s",
      msg && *msg ? libnngio_protobuf_nngio_msg_case_str((*msg)->msg_case)
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
                   LibnngioProtobuf__LibnngioMessage *msg, void *user_data) {
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
  LibnngioProtobuf__Raw *raw = nngio_create_raw_message(raw_msg, raw_msg_len);
  libnngio_log("INF", "TEST_PROTOBUF_RAW_MESSAGE_ASYNC", __FILE__, __LINE__, -1,
               "Prepared raw message for sending: %s", raw_msg);

#ifdef NNGIO_MOCK_TRANSPORT
  // Mocking: set expected receive buffer for REP context
  LibnngioProtobuf__Raw *fakeraw =
      nngio_create_raw_message(raw_msg, raw_msg_len);
  LibnngioProtobuf__LibnngioMessage *fakenmsg =
      nngio_create_nngio_message_with_raw(
          "11aa5292-1e8d-4c4f-8d38-cb1d53e0e34b", fakeraw);
  size_t packed_size =
      libnngio_protobuf__libnngio_message__get_packed_size(fakenmsg);
  uint8_t *buffer = malloc(packed_size);
  libnngio_protobuf__libnngio_message__pack(fakenmsg, buffer);
  libnngio_mock_set_recv_async_result(0);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  free(buffer);
  nngio_free_nngio_message(fakenmsg);
#endif

  async_test_sync recv_sync = {0}, send_sync = {0};

  // Prepare to receive raw message
  LibnngioProtobuf__Raw *recv_raw_message = NULL;

  libnngio_log("INF", "TEST_PROTOBUF_RAW_MESSAGE_ASYNC", __FILE__, __LINE__, -1,
               "Prepared raw message for sending.");

  // Receive raw message asynchronously
  err = libnngio_protobuf_recv_raw_message_async(
      rep_proto_ctx, &recv_raw_message,
      (libnngio_protobuf_recv_cb_info){.user_cb = async_recv_cb,
                                       .user_data = &recv_sync});
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
  err = libnngio_protobuf_send_raw_message_async(
      req_proto_ctx, raw,
      (libnngio_protobuf_send_cb_info){.user_cb = async_send_cb,
                                       .user_data = &send_sync});
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
  LibnngioProtobuf__RpcRequest *rpc_request_msg = nngio_create_rpc_request(
      "TestService", "TestMethod", (const uint8_t *)"Hello", 5);

#ifdef NNGIO_MOCK_TRANSPORT
  // Mocking: set expected receive buffer for REP context
  LibnngioProtobuf__RpcRequest *fakerpc = nngio_create_rpc_request(
      "TestService", "TestMethod", (const uint8_t *)"Hello", 5);
  LibnngioProtobuf__LibnngioMessage *fakemsg =
      nngio_create_nngio_message_with_rpc_request("uuid-123", fakerpc);
  size_t packed_size =
      libnngio_protobuf__libnngio_message__get_packed_size(fakemsg);
  uint8_t *buffer = malloc(packed_size);
  libnngio_protobuf__libnngio_message__pack(fakemsg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  nngio_free_nngio_message(fakemsg);
  free(buffer);
#endif

  async_test_sync recv_sync = {0}, send_sync = {0};

  // Prepare to receive RPC request message
  LibnngioProtobuf__RpcRequest *recv_request_msg = NULL;

  libnngio_log("INF", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Prepared RPC request message for sending.");

  // Receive rpc request message asynchronously
  err = libnngio_protobuf_recv_rpc_request_async(
      rep_proto_ctx, &recv_request_msg,
      (libnngio_protobuf_recv_cb_info){.user_cb = async_recv_cb,
                                       .user_data = &recv_sync});
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
  err = libnngio_protobuf_send_rpc_request_async(
      req_proto_ctx, rpc_request_msg,
      (libnngio_protobuf_send_cb_info){.user_cb = async_send_cb,
                                       .user_data = &send_sync});
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
  LibnngioProtobuf__RpcResponse *rpc_response_msg = nngio_create_rpc_response(
      LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success,
      (const uint8_t *)"Goodbye", 7, NULL);

#ifdef NNGIO_MOCK_TRANSPORT
  // Mocking: set expected receive buffer for REP context
  LibnngioProtobuf__RpcResponse *fakerpc_response = nngio_create_rpc_response(
      LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success,
      (const uint8_t *)"Goodbye", 7, NULL);
  LibnngioProtobuf__LibnngioMessage *fake_response_msg =
      nngio_create_nngio_message_with_rpc_response("uuid-456",
                                                   fakerpc_response);
  packed_size =
      libnngio_protobuf__libnngio_message__get_packed_size(fake_response_msg);
  buffer = malloc(packed_size);
  libnngio_protobuf__libnngio_message__pack(fake_response_msg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  nngio_free_nngio_message(fake_response_msg);
  free(buffer);
#endif

  memset(&recv_sync, 0, sizeof(async_test_sync));
  memset(&send_sync, 0, sizeof(async_test_sync));

  // Prepare to receive RPC response message
  LibnngioProtobuf__RpcResponse *recv_response_msg = NULL;

  libnngio_log("INF", "TEST_PROTOBUF_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Prepared RPC response message for sending.");

  // Receive rpc request message asynchronously
  err = libnngio_protobuf_recv_rpc_response_async(
      rep_proto_ctx, &recv_response_msg,
      (libnngio_protobuf_recv_cb_info){.user_cb = async_recv_cb,
                                       .user_data = &recv_sync});
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
      req_proto_ctx, rpc_response_msg,
      (libnngio_protobuf_send_cb_info){.user_cb = async_send_cb,
                                       .user_data = &send_sync});
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
  // the libnngio_protobuf__rpc_response__free_unpacked could be used
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
  LibnngioProtobuf__ServiceDiscoveryRequest *service_request =
      malloc(sizeof(LibnngioProtobuf__ServiceDiscoveryRequest));
  libnngio_protobuf__service_discovery_request__init(service_request);
  // No fields to set for now

#ifdef NNGIO_MOCK_TRANSPORT
  // Mocking: set expected receive buffer for REP context
  LibnngioProtobuf__ServiceDiscoveryRequest *fakerq =
      malloc(sizeof(LibnngioProtobuf__ServiceDiscoveryRequest));
  libnngio_protobuf__service_discovery_request__init(fakerq);
  LibnngioProtobuf__LibnngioMessage *temp_msg =
      nngio_create_nngio_message_with_service_discovery_request("uuid-101",
                                                                fakerq);
  size_t packed_size =
      libnngio_protobuf__libnngio_message__get_packed_size(temp_msg);
  uint8_t *buffer = malloc(packed_size);
  libnngio_protobuf__libnngio_message__pack(temp_msg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  free(buffer);
  nngio_free_nngio_message(temp_msg);
#endif

  async_test_sync recv_sync = {0}, send_sync = {0};

  // Prepare to receive service discovery request message
  LibnngioProtobuf__ServiceDiscoveryRequest *recv_service_request = NULL;
  libnngio_log("INF", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__,
               __LINE__, -1,
               "Prepared service discovery request message for sending.");

  // Receive rpc request message asynchronously
  err = libnngio_protobuf_recv_service_discovery_request_async(
      rep_proto_ctx, &recv_service_request,
      (libnngio_protobuf_recv_cb_info){.user_cb = async_recv_cb,
                                       .user_data = &recv_sync});
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
      req_proto_ctx, service_request,
      (libnngio_protobuf_send_cb_info){.user_cb = async_send_cb,
                                       .user_data = &send_sync});
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
  LibnngioProtobuf__Service *service1 =
      nngio_create_service("Echo", echo_methods, 2);
  LibnngioProtobuf__Service *service2 =
      nngio_create_service("Math", math_methods, 3);
  LibnngioProtobuf__Service *services[2] = {service1, service2};
  LibnngioProtobuf__ServiceDiscoveryResponse *service_response =
      nngio_create_service_discovery_response(services, 2);

#ifdef NNGIO_MOCK_TRANSPORT
  // Mocking: set expected receive buffer for REQ context
  LibnngioProtobuf__Service *fakeservice1 =
      nngio_create_service("Echo", echo_methods, 2);
  LibnngioProtobuf__Service *fakeservice2 =
      nngio_create_service("Math", math_methods, 3);
  LibnngioProtobuf__Service *fakeservices[2] = {fakeservice1, fakeservice2};
  LibnngioProtobuf__ServiceDiscoveryResponse *fakeresp =
      nngio_create_service_discovery_response(fakeservices, 2);
  LibnngioProtobuf__LibnngioMessage *temp_resp_msg =
      nngio_create_nngio_message_with_service_discovery_response("uuid-202",
                                                                 fakeresp);
  packed_size =
      libnngio_protobuf__libnngio_message__get_packed_size(temp_resp_msg);
  buffer = malloc(packed_size);
  libnngio_protobuf__libnngio_message__pack(temp_resp_msg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  free(buffer);
  nngio_free_nngio_message(temp_resp_msg);
#endif

  memset(&recv_sync, 0, sizeof(async_test_sync));
  memset(&send_sync, 0, sizeof(async_test_sync));

  // Prepare to receive service discovery response message
  LibnngioProtobuf__ServiceDiscoveryResponse *recv_service_response = NULL;
  libnngio_log("INF", "TEST_PROTOBUF_SERVICE_DISCOVERY_ASYNC", __FILE__,
               __LINE__, -1,
               "Prepared service discovery response message for sending.");

  // Receive rpc request message asynchronously
  err = libnngio_protobuf_recv_service_discovery_response_async(
      rep_proto_ctx, &recv_service_response,
      (libnngio_protobuf_recv_cb_info){.user_cb = async_recv_cb,
                                       .user_data = &recv_sync});
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
      req_proto_ctx, service_response,
      (libnngio_protobuf_send_cb_info){.user_cb = async_send_cb,
                                       .user_data = &send_sync});
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
    LibnngioProtobuf__Service *sent_service = service_response->services[i];
    LibnngioProtobuf__Service *recv_service =
        recv_service_response->services[i];
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

  char *uuid = libnngio_protobuf_gen_uuid();
  libnngio_log("INF", "TEST_PROTOBUF_SEND_RECV", __FILE__, __LINE__, -1,
               "Generated UUID: %s", uuid);

  // Prepare to send a raw message
  LibnngioProtobuf__Raw *raw_msg =
      nngio_create_raw_message((const uint8_t *)"Hello, World!", 13);
  LibnngioProtobuf__LibnngioMessage *msg =
      nngio_create_nngio_message_with_raw(uuid, raw_msg);

#ifdef NNGIO_MOCK_TRANSPORT
  // Mocking: set expected receive buffer for REP context
  LibnngioProtobuf__Raw *fakeraw =
      nngio_create_raw_message((const uint8_t *)"Hello, World!", 13);
  LibnngioProtobuf__LibnngioMessage *fake_msg =
      nngio_create_nngio_message_with_raw(uuid, fakeraw);
  size_t packed_size =
      libnngio_protobuf__libnngio_message__get_packed_size(fake_msg);
  uint8_t *buffer = malloc(packed_size);
  libnngio_protobuf__libnngio_message__pack(fake_msg, buffer);
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
  LibnngioProtobuf__LibnngioMessage *recv_msg = NULL;

  // Receive raw message
  err = libnngio_protobuf_recv(rep_proto_ctx,
                               (LibnngioProtobuf__LibnngioMessage **)&recv_msg);
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
  if (recv_msg->raw->data.len != msg->raw->data.len ||
      memcmp(recv_msg->raw->data.data, msg->raw->data.data,
             msg->raw->data.len) != 0) {
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
               "data: %.*s", (int)recv_msg->raw->data.len,
               recv_msg->raw->data.data);

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

  char *uuid = libnngio_protobuf_gen_uuid();
  libnngio_log("INF", "TEST_PROTOBUF_SEND_RECV_ASYNC", __FILE__, __LINE__, -1,
               "Generated UUID: %s", uuid);

  // Prepare to send a raw message
  LibnngioProtobuf__Raw *raw_msg =
      nngio_create_raw_message((const uint8_t *)"Hello, World!", 13);
  LibnngioProtobuf__LibnngioMessage *msg =
      nngio_create_nngio_message_with_raw(uuid, raw_msg);

  libnngio_log(
      "INF", "TEST_PROTOBUF_SEND_RECV_ASYNC", __FILE__, __LINE__, -1,
      "Prepared raw message for sending with UUID: %s, msg: %p, raw: %p", uuid,
      (void *)msg, (void *)raw_msg);
  libnngio_log("INF", "TEST_PROTOBUF_SEND_RECV_ASYNC", __FILE__, __LINE__, -1,
               "Raw message data: %.*s", (int)raw_msg->data.len,
               raw_msg->data.data);

  libnngio_log("INF", "TEST_PROTOBUF_SEND_RECV_ASYNC", __FILE__, __LINE__, -1,
               "msg pointer: %p", (void *)msg);

#ifdef NNGIO_MOCK_TRANSPORT
  // Mocking: set expected receive buffer for REP context
  LibnngioProtobuf__Raw *fakeraw =
      nngio_create_raw_message((const uint8_t *)"Hello, World!", 13);
  LibnngioProtobuf__LibnngioMessage *fake_msg =
      nngio_create_nngio_message_with_raw(uuid, fakeraw);
  size_t packed_size =
      libnngio_protobuf__libnngio_message__get_packed_size(fake_msg);
  uint8_t *buffer = malloc(packed_size);
  libnngio_protobuf__libnngio_message__pack(fake_msg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  nngio_free_nngio_message(fake_msg);
  free(buffer);
#endif

  async_test_sync recv_sync = {0}, send_sync = {0};

  libnngio_log("INF", "TEST_PROTOBUF_SEND_RECV_ASYNC", __FILE__, __LINE__, -1,
               "Prepared raw message for sending.");

  // Prepare to receive raw message
  LibnngioProtobuf__LibnngioMessage **recv_msg = NULL;
  recv_msg = malloc(sizeof(LibnngioProtobuf__LibnngioMessage *));
  *recv_msg = NULL;

  // Receive raw message asynchronously
  err = libnngio_protobuf_recv_async(
      rep_proto_ctx, recv_msg,
      (libnngio_protobuf_recv_cb_info){.user_cb = async_recv_cb,
                                       .user_data = &recv_sync});
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
  err = libnngio_protobuf_send_async(
      req_proto_ctx, msg,
      (libnngio_protobuf_send_cb_info){.user_cb = async_send_cb,
                                       .user_data = &send_sync});
  if (err != LIBNNGIO_PROTOBUF_ERR_NONE) {
    libnngio_log("ERR", "TEST_PROTOBUF_SEND_RECV_ASYNC", __FILE__, __LINE__, -1,
                 "Failed to send raw message: %s",
                 libnngio_protobuf_strerror(err));
    if (err == LIBNNGIO_PROTOBUF_ERR_TRANSPORT_ERROR) {
      libnngio_log("ERR", "TEST_PROTOBUF_SEND_RECV_ASYNC", __FILE__, __LINE__,
                   -1, "Transport error occurred while sending raw message.");
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

  libnngio_log(
      "INF", "TEST_PROTOBUF_SEND_RECV_ASYNC", __FILE__, __LINE__, -1,
      "Async receive completed successfully, recv_msg: %p, *recv_msg: %p",
      (void *)recv_msg, (void *)(*recv_msg));

  // Validate received message
  if ((*recv_msg)->raw->data.len != msg->raw->data.len ||
      memcmp((*recv_msg)->raw->data.data, msg->raw->data.data,
             msg->raw->data.len) != 0) {
    libnngio_log("ERR", "TEST_PROTOBUF_SEND_RECV_ASYNC_ASYNC", __FILE__,
                 __LINE__, -1, "Payload mismatch");
    libnngio_log("ERR", "TEST_PROTOBUF_SEND_RECV_ASYNC_ASYNC", __FILE__,
                 __LINE__, -1, "Expected (%zu): %.*s", msg->raw->data.len,
                 (int)msg->raw->data.len, msg->raw->data.data);
    libnngio_log("ERR", "TEST_PROTOBUF_SEND_RECV_ASYNC_ASYNC", __FILE__,
                 __LINE__, -1, "Received (%zu): %.*s",
                 (*recv_msg)->raw->data.len, (int)(*recv_msg)->raw->data.len,
                 (*recv_msg)->raw->data.data);
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
               "data: %.*s", (int)(*recv_msg)->raw->data.len,
               (*recv_msg)->raw->data.data);

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

static LibnngioProtobuf__RpcResponse__Status echo_say_hello_handler(
    libnngio_server *server, const void *request_payload,
    size_t request_payload_len, void **response_payload,
    size_t *response_payload_len, void *user_data) {
  (void)user_data;

  // Simple echo: prepend "Hello, " to the input
  const char *prefix = "Hello, ";
  size_t prefix_len = strlen(prefix);

  *response_payload_len = prefix_len + request_payload_len;
  *response_payload = malloc(*response_payload_len);
  if (*response_payload == NULL) {
    *response_payload_len = 0;
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }

  memcpy(*response_payload, prefix, prefix_len);
  memcpy((char *)*response_payload + prefix_len, request_payload,
         request_payload_len);

  return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success;
}

static LibnngioProtobuf__RpcResponse__Status math_add_handler(
    libnngio_server *server, const void *request_payload,
    size_t request_payload_len, void **response_payload,
    size_t *response_payload_len, void *user_data) {
  (void)user_data;

  // Expect two 4-byte integers in request
  if (request_payload_len != 8) {
    *response_payload = NULL;
    *response_payload_len = 0;
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InvalidRequest;
  }

  const int *inputs = (const int *)request_payload;
  int result = inputs[0] + inputs[1];

  *response_payload_len = sizeof(int);
  *response_payload = malloc(*response_payload_len);
  if (*response_payload == NULL) {
    *response_payload_len = 0;
    return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__InternalError;
  }

  memcpy(*response_payload, &result, sizeof(int));
  return LIBNNGIO_PROTOBUF__RPC_RESPONSE__STATUS__Success;
}

void test_rpc_service_discovery() {
  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "Testing service registration and discovery...");

  // Initialize transport and contexts
  libnngio_config rep_cfg = {.mode = LIBNNGIO_MODE_LISTEN,
                             .proto = LIBNNGIO_PROTO_REP,
                             .url = "tcp://127.0.0.1:6666",
                             .tls_cert = NULL,
                             .tls_key = NULL,
                             .tls_ca_cert = NULL};

  libnngio_config req_cfg = {.mode = LIBNNGIO_MODE_DIAL,
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
  libnngio_protobuf_error_code proto_rv =
      libnngio_protobuf_context_init(&rep_proto_ctx, rep_ctx);
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
      {"SayGoodbye", echo_say_hello_handler, NULL}};
  proto_rv =
      libnngio_server_register_service(server, "Echo", echo_methods_reg, 2);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  // Register Math service
  libnngio_service_method math_methods_reg[] = {
      {"Add", math_add_handler, NULL},
      {"Subtract", math_add_handler, NULL},
      {"Multiply", math_add_handler, NULL}};
  proto_rv =
      libnngio_server_register_service(server, "Math", math_methods_reg, 3);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "Server initialized with Echo and Math services.");

  LibnngioProtobuf__ServiceDiscoveryResponse *service_response = NULL;
  proto_rv = libnngio_server_create_service_discovery_response(
      server, &service_response);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "Service discovery response created with %zu services.",
               service_response->n_services);
  for (size_t i = 0; i < service_response->n_services; i++) {
    LibnngioProtobuf__Service *service = service_response->services[i];
    libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
                 "Service %zu: %s with %d methods.", i, service->name,
                 service->n_methods);
    for (size_t j = 0; j < service->n_methods; j++) {
      libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
                   "  Method %zu: %s", j, service->methods[j]);
    }
  }

  // Initialize client
  libnngio_client *client = NULL;
  proto_rv = libnngio_client_init(&client, req_proto_ctx);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "Client initialized.");

  // Test service discovery
  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "Testing service discovery...");

  // Prepare service discovery request
  LibnngioProtobuf__ServiceDiscoveryRequest *service_request =
      malloc(sizeof(LibnngioProtobuf__ServiceDiscoveryRequest));
  libnngio_protobuf__service_discovery_request__init(service_request);

#ifdef NNGIO_MOCK_TRANSPORT
  // Mock service discover request
  LibnngioProtobuf__ServiceDiscoveryRequest *fakerq =
      malloc(sizeof(LibnngioProtobuf__ServiceDiscoveryRequest));
  LibnngioProtobuf__LibnngioMessage *mock_request_msg =
      nngio_create_nngio_message_with_service_discovery_request(
          "uuid-discovery-req", service_request);
  libnngio_protobuf__service_discovery_request__init(fakerq);
  size_t req_pack_size =
      libnngio_protobuf__libnngio_message__get_packed_size(mock_request_msg);
  uint8_t *req_buffer = malloc(req_pack_size);
  libnngio_protobuf__libnngio_message__pack(mock_request_msg, req_buffer);
  libnngio_mock_set_recv_buffer((const char *)req_buffer, req_pack_size);
  libnngio_protobuf__service_discovery_request__free_unpacked(fakerq, NULL);
  free(req_buffer);
  nngio_free_nngio_message(mock_request_msg);
#endif

  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "Client Service discovery request prepared.");
  libnngio_client_send_service_discovery_request(client, service_request);

  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "Client Service discovery request sent.");

  // Receive service discovery request and create response
  LibnngioProtobuf__ServiceDiscoveryRequest *actual_service_request = NULL;
  LibnngioProtobuf__ServiceDiscoveryResponse *actual_service_response = NULL;
  proto_rv = libnngio_server_handle_service_discovery(
      server, &actual_service_request, &actual_service_response);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
  assert(actual_service_response != NULL);
  assert(actual_service_response->n_services == 5);
  assert(strcmp(actual_service_response->services[0]->name,
                "LibnngioProtobuf.RpcService") == 0);
  assert(strcmp(actual_service_response->services[1]->name,
                "LibnngioProtobuf.ServiceDiscoveryService") == 0);
  assert(strcmp(actual_service_response->services[2]->name,
                "LibnngioProtobuf.TransportService") == 0);
  assert(strcmp(actual_service_response->services[3]->name, "Echo") == 0);
  assert(strcmp(actual_service_response->services[4]->name, "Math") == 0);
  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "Service discovery response created with %zu services.",
               actual_service_response->n_services);
  for (size_t i = 0; i < actual_service_response->n_services; i++) {
    LibnngioProtobuf__Service *actual_service =
        actual_service_response->services[i];
    libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
                 "Service %zu: %s with %d methods.", i, actual_service->name,
                 actual_service->n_methods);
    for (size_t j = 0; j < actual_service->n_methods; j++) {
      libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
                   "  Method %zu: %s", j, actual_service->methods[j]);
    }
  }

#ifdef NNGIO_MOCK_TRANSPORT
  // Mock service discovery response
  LibnngioProtobuf__ServiceDiscoveryResponse *mock_response =
      nngio_copy_service_discovery_response(service_response);
  LibnngioProtobuf__LibnngioMessage *mock_response_msg =
      nngio_create_nngio_message_with_service_discovery_response(
          "uuid-discovery", mock_response);

  size_t packed_size =
      libnngio_protobuf__libnngio_message__get_packed_size(mock_response_msg);
  uint8_t *buffer = malloc(packed_size);
  libnngio_protobuf__libnngio_message__pack(mock_response_msg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  free(buffer);
  nngio_free_nngio_message(mock_response_msg);
  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "Mock service discovery response set.");
#endif

  // send the response back to the client and make sure that the client
  // populates its local copy of services

  libnngio_server_send_service_discovery_response(server,
                                                  actual_service_response);

  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "Service discovery response sent from server.");
  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "Receiving service discovery response with client.");

  LibnngioProtobuf__ServiceDiscoveryResponse *client_recv_response = NULL;
  proto_rv = libnngio_client_recv_service_discovery_response(
      client, &client_recv_response);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
  assert(client_recv_response != NULL);
  assert(client_recv_response->n_services == 5);
  assert(strcmp(client_recv_response->services[0]->name,
                "LibnngioProtobuf.RpcService") == 0);
  assert(strcmp(client_recv_response->services[1]->name,
                "LibnngioProtobuf.ServiceDiscoveryService") == 0);
  assert(strcmp(client_recv_response->services[2]->name,
                "LibnngioProtobuf.TransportService") == 0);
  assert(strcmp(client_recv_response->services[3]->name, "Echo") == 0);
  assert(strcmp(client_recv_response->services[4]->name, "Math") == 0);
  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "Service discovery response received with %zu services.",
               client_recv_response->n_services);
  for (size_t i = 0; i < client_recv_response->n_services; i++) {
    LibnngioProtobuf__Service *actual_service =
        client_recv_response->services[i];
    libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
                 "Service %zu: %s with %d methods.", i, actual_service->name,
                 actual_service->n_methods);
    for (size_t j = 0; j < actual_service->n_methods; j++) {
      libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
                   "  Method %zu: %s", j, actual_service->methods[j]);
    }
  }

  // Populate client's discovered services
  proto_rv = libnngio_client_populate_services_from_response(
      client, client_recv_response);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
  assert(client->n_discovered_services == 5);
  assert(strcmp(client->discovered_services[0]->name,
                "LibnngioProtobuf.RpcService") == 0);
  assert(strcmp(client->discovered_services[1]->name,
                "LibnngioProtobuf.ServiceDiscoveryService") == 0);
  assert(strcmp(client->discovered_services[2]->name,
                "LibnngioProtobuf.TransportService") == 0);
  assert(strcmp(client->discovered_services[3]->name, "Echo") == 0);
  assert(strcmp(client->discovered_services[4]->name, "Math") == 0);
  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "Client populated services from response. Found %zu services.",
               client->n_discovered_services);
  for (size_t i = 0; i < client->n_discovered_services; i++) {
    LibnngioProtobuf__Service *service = client->discovered_services[i];
    libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
                 "Discovered Service %zu: %s with %zu methods.", i,
                 service->name, service->n_methods);
    for (size_t j = 0; j < service->n_methods; j++) {
      libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
                   "  Method %zu: %s", j, service->methods[j]);
    }
  }

  // Clean up
  libnngio_protobuf__service_discovery_request__free_unpacked(
      actual_service_request, NULL);
  nngio_free_service_discovery_response(client_recv_response);
  nngio_free_service_discovery_response(actual_service_response);
  nngio_free_service_discovery_response(service_response);
  libnngio_client_free(client);
  libnngio_server_free(server);
  libnngio_protobuf_context_free(rep_proto_ctx);
  libnngio_protobuf_context_free(req_proto_ctx);
  libnngio_context_free(rep_ctx);
  libnngio_context_free(req_ctx);
  libnngio_transport_free(rep);
  libnngio_transport_free(req);

  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY", __FILE__, __LINE__, -1,
               "RPC Service Discovery test completed successfully.");
}

typedef struct {
  volatile int done;
  int result;
} service_discovery_sync_t;  // the code is async, but the tests are not...

static void send_service_discovery_callback(
    libnngio_protobuf_context *ctx, int result,
    LibnngioProtobuf__LibnngioMessage *msg, void *user_data) {
  service_discovery_sync_t *sync = (service_discovery_sync_t *)user_data;
  sync->done = 1;
  sync->result = result;

  // An application could hook here with user data to add additional processing
  // of the message if desired.
  // For this test, we are concerned with the side effects on the client and
  // server objects, so we do not process the message here.
  // Typically though, an application would want to do something with it.
  // For example, logging, metrics, etc.

  // Note that differently from the recv callback, we do not free the message
  // here, as the send callback is called after the message has been sent,
  // and the library takes care of freeing it.
}

static void recv_service_discovery_callback(
    libnngio_protobuf_context *ctx, int result,
    LibnngioProtobuf__LibnngioMessage **msg, void *user_data) {
  service_discovery_sync_t *sync = (service_discovery_sync_t *)user_data;
  sync->done = 1;
  sync->result = result;

  // An application could hook here with user data to add additional processing
  // of the message if desired.
  // For this test, we are concerned with the side effects on the client and
  // server objects, so we do not process the message here.
  // Typically though, an application would want to do something with it.
  // For example, logging, metrics, etc.

  // Instad of doing anything with the message, we just free it.
  if (msg != NULL && *msg != NULL) {
    nngio_free_nngio_message(*msg);
  }
}

void test_rpc_service_discovery_async(void) {
  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
               -1, "Testing async service registration and discovery...");

  // Initialize transport and contexts
  libnngio_config rep_cfg = {.mode = LIBNNGIO_MODE_LISTEN,
                             .proto = LIBNNGIO_PROTO_REP,
                             .url = "tcp://127.0.0.1:6666",
                             .tls_cert = NULL,
                             .tls_key = NULL,
                             .tls_ca_cert = NULL};

  libnngio_config req_cfg = {.mode = LIBNNGIO_MODE_DIAL,
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
  libnngio_protobuf_error_code proto_rv =
      libnngio_protobuf_context_init(&rep_proto_ctx, rep_ctx);
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
      {"SayGoodbye", echo_say_hello_handler, NULL}};
  proto_rv =
      libnngio_server_register_service(server, "Echo", echo_methods_reg, 2);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  // Register Math service
  libnngio_service_method math_methods_reg[] = {
      {"Add", math_add_handler, NULL},
      {"Subtract", math_add_handler, NULL},
      {"Multiply", math_add_handler, NULL}};
  proto_rv =
      libnngio_server_register_service(server, "Math", math_methods_reg, 3);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
               -1, "Server initialized with Echo and Math services.");

  LibnngioProtobuf__ServiceDiscoveryResponse *service_response = NULL;
  proto_rv = libnngio_server_create_service_discovery_response(
      server, &service_response);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
               -1, "Service discovery response created with %zu services.",
               service_response->n_services);
  for (size_t i = 0; i < service_response->n_services; i++) {
    LibnngioProtobuf__Service *service = service_response->services[i];
    libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
                 -1, "Service %zu: %s with %d methods.", i, service->name,
                 service->n_methods);
    for (size_t j = 0; j < service->n_methods; j++) {
      libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__,
                   __LINE__, -1, "  Method %zu: %s", j, service->methods[j]);
    }
  }

  // Initialize client
  libnngio_client *client = NULL;
  proto_rv = libnngio_client_init(&client, req_proto_ctx);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
               -1, "Client initialized.");

  // Test service discovery
  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
               -1, "Testing service discovery...");

  // Prepare service discovery request
  LibnngioProtobuf__ServiceDiscoveryRequest *service_request =
      malloc(sizeof(LibnngioProtobuf__ServiceDiscoveryRequest));
  libnngio_protobuf__service_discovery_request__init(service_request);

#ifdef NNGIO_MOCK_TRANSPORT
  // Mock service discover request
  LibnngioProtobuf__ServiceDiscoveryRequest *fakerq =
      malloc(sizeof(LibnngioProtobuf__ServiceDiscoveryRequest));
  LibnngioProtobuf__LibnngioMessage *mock_request_msg =
      nngio_create_nngio_message_with_service_discovery_request(
          "uuid-discovery-req", service_request);
  libnngio_protobuf__service_discovery_request__init(fakerq);
  size_t req_pack_size =
      libnngio_protobuf__libnngio_message__get_packed_size(mock_request_msg);
  uint8_t *req_buffer = malloc(req_pack_size);
  libnngio_protobuf__libnngio_message__pack(mock_request_msg, req_buffer);
  libnngio_mock_set_recv_buffer((const char *)req_buffer, req_pack_size);
  libnngio_protobuf__service_discovery_request__free_unpacked(fakerq, NULL);
  free(req_buffer);
  nngio_free_nngio_message(mock_request_msg);
#endif

  // Prepare and call libnngio_server_handle_service_discovery_async
  // This requires setting up a callback and user data to capture the
  // response when ready. For simplicity, we'll do this synchronously here
  // but in a real async scenario, you'd set up the callback properly.

  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
               -1, "Setting up asynchronous service discovery handling...");

  LibnngioProtobuf__ServiceDiscoveryRequest *actual_service_request = NULL;
  LibnngioProtobuf__ServiceDiscoveryResponse *actual_service_response = NULL;
  service_discovery_sync_t send_sync = {0}, recv_sync = {0};

  proto_rv = libnngio_server_handle_service_discovery_async(
      server, &actual_service_request, &actual_service_response,
      (libnngio_protobuf_recv_cb_info){
          .user_cb = recv_service_discovery_callback,
          .user_data = &recv_sync,
      });
  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
               -1, "Asynchronous service discovery handling initiated.");
  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
               -1, "Sending an asynchronous service discovery request...");

  libnngio_client_send_service_discovery_request_async(
      client, service_request,
      (libnngio_protobuf_send_cb_info){
          .user_cb = send_service_discovery_callback,
          .user_data = &send_sync,
      });
  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
               -1, "Client Service discovery request sent.");

  // wait for async operation to complete
  while (!send_sync.done) {
    nng_msleep(10);
  }
  while (!recv_sync.done) {
    nng_msleep(10);
  }

  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
               -1, "Asynchronous service discovery handling completed.");
  if (send_sync.result != 0 || recv_sync.result != 0) {
    libnngio_log("ERR", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
                 -1, "Async service discovery send result: %d",
                 send_sync.result);
    libnngio_log("ERR", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
                 -1, "Async service discovery recv result: %d",
                 recv_sync.result);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_context_free(req_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(0);
  }

  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
               -1, "Async service discovery succeeded, validating response...");

  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
  assert(actual_service_response != NULL);
  assert(actual_service_response->n_services == 5);
  assert(strcmp(actual_service_response->services[0]->name,
                "LibnngioProtobuf.RpcService") == 0);
  assert(strcmp(actual_service_response->services[1]->name,
                "LibnngioProtobuf.ServiceDiscoveryService") == 0);
  assert(strcmp(actual_service_response->services[2]->name,
                "LibnngioProtobuf.TransportService") == 0);
  assert(strcmp(actual_service_response->services[3]->name, "Echo") == 0);
  assert(strcmp(actual_service_response->services[4]->name, "Math") == 0);
  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
               -1, "Service discovery response created with %zu services.",
               actual_service_response->n_services);
  for (size_t i = 0; i < actual_service_response->n_services; i++) {
    LibnngioProtobuf__Service *actual_service =
        actual_service_response->services[i];
    libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
                 -1, "Service %zu: %s with %d methods.", i,
                 actual_service->name, actual_service->n_methods);
    for (size_t j = 0; j < actual_service->n_methods; j++) {
      libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__,
                   __LINE__, -1, "  Method %zu: %s", j,
                   actual_service->methods[j]);
    }
  }

  // Setup mock response for client to receive if needed

#ifdef NNGIO_MOCK_TRANSPORT
  // Mock service discovery response
  LibnngioProtobuf__ServiceDiscoveryResponse *mock_response =
      nngio_copy_service_discovery_response(actual_service_response);
  LibnngioProtobuf__LibnngioMessage *mock_response_msg =
      nngio_create_nngio_message_with_service_discovery_response(
          "uuid-discovery", mock_response);

  size_t packed_size =
      libnngio_protobuf__libnngio_message__get_packed_size(mock_response_msg);
  uint8_t *buffer = malloc(packed_size);
  libnngio_protobuf__libnngio_message__pack(mock_response_msg, buffer);
  libnngio_mock_set_recv_buffer((const char *)buffer, packed_size);
  free(buffer);
  nngio_free_nngio_message(mock_response_msg);
  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
               -1, "Mock service discovery response set.");
#endif

  // prepare client to receive the response
  libnngio_log(
      "INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__, -1,
      "Preparing client to receive asynchronous service discovery response...");

  LibnngioProtobuf__ServiceDiscoveryResponse *client_recv_response = NULL;
  memset(&recv_sync, 0, sizeof(recv_sync));
  memset(&send_sync, 0, sizeof(send_sync));
  libnngio_client_recv_service_discovery_response_async(
      client, &client_recv_response,
      (libnngio_protobuf_recv_cb_info){
          .user_cb = recv_service_discovery_callback,
          .user_data = &recv_sync,
      });

  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
               -1,
               "Prepared to receiving service discovery response with client.");

  // send the response back to the client
  proto_rv = libnngio_server_send_service_discovery_response_async(
      server, actual_service_response,
      (libnngio_protobuf_send_cb_info){
          .user_cb = send_service_discovery_callback,
          .user_data = &send_sync,
      });
  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
               -1, "Service discovery response sent from server.");

  // wait for async operation to complete
  while (!send_sync.done) {
    nng_msleep(10);
  }
  while (!recv_sync.done) {
    nng_msleep(10);
  }

  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
               -1,
               "Asynchronous service discovery response handling completed.");
  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
               -1, "Validating client received response...");

  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
  assert(client_recv_response != NULL);
  assert(client_recv_response->n_services == 5);
  assert(strcmp(client_recv_response->services[0]->name,
                "LibnngioProtobuf.RpcService") == 0);
  assert(strcmp(client_recv_response->services[1]->name,
                "LibnngioProtobuf.ServiceDiscoveryService") == 0);
  assert(strcmp(client_recv_response->services[2]->name,
                "LibnngioProtobuf.TransportService") == 0);
  assert(strcmp(client_recv_response->services[3]->name, "Echo") == 0);
  assert(strcmp(client_recv_response->services[4]->name, "Math") == 0);
  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
               -1, "Service discovery response received with %zu services.",
               client_recv_response->n_services);
  for (size_t i = 0; i < client_recv_response->n_services; i++) {
    LibnngioProtobuf__Service *actual_service =
        client_recv_response->services[i];
    libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
                 -1, "Service %zu: %s with %d methods.", i,
                 actual_service->name, actual_service->n_methods);
    for (size_t j = 0; j < actual_service->n_methods; j++) {
      libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__,
                   __LINE__, -1, "  Method %zu: %s", j,
                   actual_service->methods[j]);
    }
  }
  assert(client->n_discovered_services == 5);
  assert(strcmp(client->discovered_services[0]->name,
                "LibnngioProtobuf.RpcService") == 0);
  assert(strcmp(client->discovered_services[1]->name,
                "LibnngioProtobuf.ServiceDiscoveryService") == 0);
  assert(strcmp(client->discovered_services[2]->name,
                "LibnngioProtobuf.TransportService") == 0);
  assert(strcmp(client->discovered_services[3]->name, "Echo") == 0);
  assert(strcmp(client->discovered_services[4]->name, "Math") == 0);
  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
               -1,
               "Client populated services from response. Found %zu services.",
               client->n_discovered_services);
  for (size_t i = 0; i < client->n_discovered_services; i++) {
    LibnngioProtobuf__Service *service = client->discovered_services[i];
    libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
                 -1, "Discovered Service %zu: %s with %zu methods.", i,
                 service->name, service->n_methods);
    for (size_t j = 0; j < service->n_methods; j++) {
      libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__,
                   __LINE__, -1, "  Method %zu: %s", j, service->methods[j]);
    }
  }

  // Clean up
  libnngio_protobuf__service_discovery_request__free_unpacked(
      actual_service_request, NULL);
  nngio_free_service_discovery_response(client_recv_response);
  nngio_free_service_discovery_response(actual_service_response);
  nngio_free_service_discovery_response(service_response);
  libnngio_client_free(client);
  libnngio_server_free(server);
  libnngio_protobuf_context_free(rep_proto_ctx);
  libnngio_protobuf_context_free(req_proto_ctx);
  libnngio_context_free(rep_ctx);
  libnngio_context_free(req_ctx);
  libnngio_transport_free(rep);
  libnngio_transport_free(req);

  libnngio_log("INF", "TEST_RPC_SERVICE_DISCOVERY_ASYNC", __FILE__, __LINE__,
               -1, "Async RPC Service Discovery test completed successfully.");
}

static void test_rpc(void) {
  libnngio_log("INF", "TEST_RPC", __FILE__, __LINE__, -1,
               "Testing rpc invocation...");

  // Initialize transport and contexts
  libnngio_config rep_cfg = {.mode = LIBNNGIO_MODE_LISTEN,
                             .proto = LIBNNGIO_PROTO_REP,
                             .url = "tcp://127.0.0.1:6666",
                             .tls_cert = NULL,
                             .tls_key = NULL,
                             .tls_ca_cert = NULL};

  libnngio_config req_cfg = {.mode = LIBNNGIO_MODE_DIAL,
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
  libnngio_protobuf_error_code proto_rv =
      libnngio_protobuf_context_init(&rep_proto_ctx, rep_ctx);
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
      {"SayGoodbye", echo_say_hello_handler, NULL}};
  proto_rv =
      libnngio_server_register_service(server, "Echo", echo_methods_reg, 2);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  // Register Math service
  libnngio_service_method math_methods_reg[] = {
      {"Add", math_add_handler, NULL},
      {"Subtract", math_add_handler, NULL},
      {"Multiply", math_add_handler, NULL}};
  proto_rv =
      libnngio_server_register_service(server, "Math", math_methods_reg, 3);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  libnngio_log("INF", "TEST_RPC", __FILE__, __LINE__, -1,
               "Server initialized with Echo and Math services.");

  // Initialize client
  libnngio_client *client = NULL;
  proto_rv = libnngio_client_init(&client, req_proto_ctx);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  libnngio_log("INF", "TEST_RPC", __FILE__, __LINE__, -1,
               "Client initialized.");

  // send rpc request from client and receive response on server
  libnngio_log("INF", "TEST_RPC", __FILE__, __LINE__, -1,
               "Testing rpc call to Echo.SayHello...");

  // create rpc request
  LibnngioProtobuf__RpcRequest *rpc_request =
      nngio_create_rpc_request("Echo", "SayHello", "World!", strlen("World!"));
  LibnngioProtobuf__RpcRequest *recv_rpc_request = NULL;

#ifdef NNGIO_MOCK_TRANSPORT
  // Mock rpc request
  LibnngioProtobuf__RpcRequest *fakerq = nngio_copy_rpc_request(rpc_request);
  LibnngioProtobuf__LibnngioMessage *mock_request_msg =
      nngio_create_nngio_message_with_rpc_request("uuid-req", fakerq);
  size_t req_pack_size =
      libnngio_protobuf__libnngio_message__get_packed_size(mock_request_msg);
  uint8_t *req_buffer = malloc(req_pack_size);
  libnngio_protobuf__libnngio_message__pack(mock_request_msg, req_buffer);
  libnngio_mock_set_recv_buffer((const char *)req_buffer, req_pack_size);
  free(req_buffer);
  nngio_free_nngio_message(mock_request_msg);
#endif

  libnngio_client_send_rpc_request(client, rpc_request);

  libnngio_log("INF", "TEST_RPC", __FILE__, __LINE__, -1,
               "Client RPC request sent.");
  libnngio_log("INF", "TEST_RPC", __FILE__, __LINE__, -1,
               "Server receiving RPC request...");

  libnngio_server_recv_rpc_request(server, &recv_rpc_request);

  libnngio_log(
      "INF", "TEST_RPC", __FILE__, __LINE__, -1,
      "Server received RPC request for service %s method %s with payload %.*s",
      recv_rpc_request->service_name, recv_rpc_request->method_name,
      (int)recv_rpc_request->payload.len,
      (char *)recv_rpc_request->payload.data);
  assert(strcmp(recv_rpc_request->service_name, "Echo") == 0);
  assert(strcmp(recv_rpc_request->method_name, "SayHello") == 0);
  assert(recv_rpc_request->payload.len == strlen("World!"));
  assert(memcmp(recv_rpc_request->payload.data, "World!", strlen("World!")) ==
         0);

  // handle the request
  libnngio_log("INF", "TEST_RPC", __FILE__, __LINE__, -1,
               "Handling the RPC request...");
  LibnngioProtobuf__RpcResponse *rpc_response = NULL;
  proto_rv = libnngio_server_create_rpc_response(server, recv_rpc_request,
                                                 &rpc_response);
#ifdef NNGIO_MOCK_TRANSPORT
  // Mock rpc response
  LibnngioProtobuf__RpcResponse *fakeresp =
      nngio_copy_rpc_response(rpc_response);
  LibnngioProtobuf__LibnngioMessage *mock_response_msg =
      nngio_create_nngio_message_with_rpc_response("uuid-resp", fakeresp);
  size_t resp_pack_size =
      libnngio_protobuf__libnngio_message__get_packed_size(mock_response_msg);
  uint8_t *resp_buffer = malloc(resp_pack_size);
  libnngio_protobuf__libnngio_message__pack(mock_response_msg, resp_buffer);
  libnngio_mock_set_recv_buffer((const char *)resp_buffer, resp_pack_size);
  free(resp_buffer);
  nngio_free_nngio_message(mock_response_msg);
#endif

  libnngio_log("INF", "TEST_RPC", __FILE__, __LINE__, -1,
               "Server Generating RPC response for request service %s method "
               "%s with payload %.*s",
               recv_rpc_request->service_name, recv_rpc_request->method_name,
               (int)recv_rpc_request->payload.len,
               (char *)recv_rpc_request->payload.data);

  libnngio_log(
      "INF", "TEST_RPC", __FILE__, __LINE__, -1,
      "Server Generated RPC response status %d with payload '%.*s' of len: %d",
      rpc_response->status, (int)rpc_response->payload.len,
      (char *)rpc_response->payload.data, (int)rpc_response->payload.len);

  size_t length = strlen("Hello, World!");
  assert(rpc_response->status == 0);
  assert(rpc_response->payload.len == length);
  assert(memcmp(rpc_response->payload.data, "Hello, World!", length) == 0);

  // send the response back to the client
  libnngio_log("INF", "TEST_RPC", __FILE__, __LINE__, -1,
               "Sending RPC response back to client...");
  proto_rv = libnngio_server_send_rpc_response(server, rpc_response);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
  libnngio_log("INF", "TEST_RPC", __FILE__, __LINE__, -1,
               "RPC response sent from server.");
  libnngio_log("INF", "TEST_RPC", __FILE__, __LINE__, -1,
               "Client receiving RPC response...");

  LibnngioProtobuf__RpcResponse *client_recv_response = NULL;
  proto_rv = libnngio_client_recv_rpc_response(client, &client_recv_response);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
  assert(client_recv_response != NULL);
  assert(client_recv_response->status == 0);
  assert(client_recv_response->payload.len == length);
  assert(memcmp(client_recv_response->payload.data, "Hello, World!", length) ==
         0);
  libnngio_log("INF", "TEST_RPC", __FILE__, __LINE__, -1,
               "Client received RPC response with status %d and payload '%.*s' "
               "of len: %d",
               client_recv_response->status,
               (int)client_recv_response->payload.len,
               (char *)client_recv_response->payload.data,
               (int)client_recv_response->payload.len);
  libnngio_log("INF", "TEST_RPC", __FILE__, __LINE__, -1,
               "RPC call to Echo.SayHello completed successfully.");

  nngio_free_rpc_response(client_recv_response);
  nngio_free_rpc_response(rpc_response);
  nngio_free_rpc_request(recv_rpc_request);
  nngio_free_rpc_request(rpc_request);
  libnngio_client_free(client);
  libnngio_server_free(server);
  libnngio_protobuf_context_free(rep_proto_ctx);
  libnngio_protobuf_context_free(req_proto_ctx);
  libnngio_context_free(rep_ctx);
  libnngio_context_free(req_ctx);
  libnngio_transport_free(rep);
  libnngio_transport_free(req);

  libnngio_log("INF", "TEST_RPC", __FILE__, __LINE__, -1,
               "RPC test completed successfully.");
};

typedef struct {
  volatile int done;
  int result;
} rpc_sync_t;  // the code is async, but the tests are not...

static void send_rpc_callback(libnngio_protobuf_context *ctx, int result,
                              LibnngioProtobuf__LibnngioMessage *msg,
                              void *user_data) {
  rpc_sync_t *sync = (rpc_sync_t *)user_data;
  sync->done = 1;
  sync->result = result;

  // An application could hook here with user data to add additional processing
  // of the message if desired.
  // For this test, we are concerned with the side effects on the client and
  // server objects, so we do not process the message here.
  // Typically though, an application would want to do something with it.
  // For example, logging, metrics, etc.

  // Note that differently from the recv callback, we do not free the message
  // here, as the send callback is called after the message has been sent,
  // and the library takes care of freeing it.
}

static void recv_rpc_callback(libnngio_protobuf_context *ctx, int result,
                              LibnngioProtobuf__LibnngioMessage **msg,
                              void *user_data) {
  rpc_sync_t *sync = (rpc_sync_t *)user_data;
  sync->done = 1;
  sync->result = result;

  // An application could hook here with user data to add additional processing
  // of the message if desired.
  // For this test, we are concerned with the side effects on the client and
  // server objects, so we do not process the message here.
  // Typically though, an application would want to do something with it.
  // For example, logging, metrics, etc.

  // Instad of doing anything with the message, we just free it.
  if (msg != NULL && *msg != NULL) {
    nngio_free_nngio_message(*msg);
  }
}

static void test_rpc_asyc(void) {
  libnngio_log("INF", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Testing async rpc invocation...");

  // Initialize transport and contexts
  libnngio_config rep_cfg = {.mode = LIBNNGIO_MODE_LISTEN,
                             .proto = LIBNNGIO_PROTO_REP,
                             .url = "tcp://127.0.0.1:6666",
                             .tls_cert = NULL,
                             .tls_key = NULL,
                             .tls_ca_cert = NULL};

  libnngio_config req_cfg = {.mode = LIBNNGIO_MODE_DIAL,
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
  libnngio_protobuf_error_code proto_rv =
      libnngio_protobuf_context_init(&rep_proto_ctx, rep_ctx);
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
      {"SayGoodbye", echo_say_hello_handler, NULL}};
  proto_rv =
      libnngio_server_register_service(server, "Echo", echo_methods_reg, 2);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  // Register Math service
  libnngio_service_method math_methods_reg[] = {
      {"Add", math_add_handler, NULL},
      {"Subtract", math_add_handler, NULL},
      {"Multiply", math_add_handler, NULL}};
  proto_rv =
      libnngio_server_register_service(server, "Math", math_methods_reg, 3);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  libnngio_log("INF", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Server initialized with Echo and Math services.");

  // Initialize client
  libnngio_client *client = NULL;
  proto_rv = libnngio_client_init(&client, req_proto_ctx);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  libnngio_log("INF", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Client initialized.");

  // send rpc request from client and receive response on server
  libnngio_log("INF", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Testing rpc call to Echo.SayHello...");

  // create rpc request
  LibnngioProtobuf__RpcRequest *rpc_request =
      nngio_create_rpc_request("Echo", "SayHello", "World!", strlen("World!"));
  LibnngioProtobuf__RpcRequest *recv_rpc_request = NULL;

#ifdef NNGIO_MOCK_TRANSPORT
  // Mock rpc request
  LibnngioProtobuf__RpcRequest *fakerq = nngio_copy_rpc_request(rpc_request);
  LibnngioProtobuf__LibnngioMessage *mock_request_msg =
      nngio_create_nngio_message_with_rpc_request("uuid-req", fakerq);
  size_t req_pack_size =
      libnngio_protobuf__libnngio_message__get_packed_size(mock_request_msg);
  uint8_t *req_buffer = malloc(req_pack_size);
  libnngio_protobuf__libnngio_message__pack(mock_request_msg, req_buffer);
  libnngio_mock_set_recv_buffer((const char *)req_buffer, req_pack_size);
  free(req_buffer);
  nngio_free_nngio_message(mock_request_msg);
#endif

  libnngio_log("INF", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Sending an asynchronous RPC request...");

  LibnngioProtobuf__RpcRequest *actual_rpc_request = NULL;
  LibnngioProtobuf__RpcResponse *actual_rpc_response = NULL;
  rpc_sync_t send_sync = {0}, recv_sync = {0};

  proto_rv = libnngio_server_handle_rpc_request_async(
      server, &actual_rpc_request, &actual_rpc_response,
      (libnngio_protobuf_recv_cb_info){
          .user_cb = recv_rpc_callback,
          .user_data = &recv_sync,
      });
  libnngio_log("INF", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Asynchronous RPC handling initiated.");
  libnngio_log("INF", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Sending an asynchronous RPC request...");

  proto_rv =
      libnngio_client_send_rpc_request_async(client, rpc_request,
                                             (libnngio_protobuf_send_cb_info){
                                                 .user_cb = send_rpc_callback,
                                                 .user_data = &send_sync,
                                             });
  libnngio_log("INF", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Client RPC request sent.");

  // wait for async operation to complete
  while (!send_sync.done) {
    nng_msleep(10);
  }
  while (!recv_sync.done) {
    nng_msleep(10);
  }

  libnngio_log("INF", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Asynchronous RPC handling completed.");
  if (send_sync.result != 0 || recv_sync.result != 0) {
    libnngio_log("ERR", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
                 "Async RPC send result: %d", send_sync.result);
    libnngio_log("ERR", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
                 "Async RPC recv result: %d", recv_sync.result);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_context_free(req_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(0);
  }

  libnngio_log("INF", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Async RPC succeeded, validating request...");
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
  assert(actual_rpc_request != NULL);
  assert(strcmp(actual_rpc_request->service_name, "Echo") == 0);
  assert(strcmp(actual_rpc_request->method_name, "SayHello") == 0);
  assert(actual_rpc_request->payload.len == strlen("World!"));
  assert(memcmp(actual_rpc_request->payload.data, "World!", strlen("World!")) ==
         0);
  libnngio_log(
      "INF", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
      "Server received RPC request for service %s method %s with payload %.*s",
      actual_rpc_request->service_name, actual_rpc_request->method_name,
      (int)actual_rpc_request->payload.len,
      (char *)actual_rpc_request->payload.data);

  // validate the generated response
  libnngio_log("INF", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Validating generated RPC response...");
  assert(actual_rpc_response != NULL);
  size_t length = strlen("Hello, World!");
  assert(actual_rpc_response->status == 0);
  assert(actual_rpc_response->payload.len == length);
  assert(memcmp(actual_rpc_response->payload.data, "Hello, World!", length) ==
         0);
  libnngio_log(
      "INF", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
      "Server Generated RPC response status %d with payload '%.*s' of len: %d",
      actual_rpc_response->status, (int)actual_rpc_response->payload.len,
      (char *)actual_rpc_response->payload.data,
      (int)actual_rpc_response->payload.len);

  // prepare client to receive the response
#ifdef NNGIO_MOCK_TRANSPORT
  // Mock rpc response
  LibnngioProtobuf__RpcResponse *fakeresp =
      nngio_copy_rpc_response(actual_rpc_response);
  LibnngioProtobuf__LibnngioMessage *mock_response_msg =
      nngio_create_nngio_message_with_rpc_response("uuid-resp", fakeresp);
  size_t resp_pack_size =
      libnngio_protobuf__libnngio_message__get_packed_size(mock_response_msg);
  uint8_t *resp_buffer = malloc(resp_pack_size);
  libnngio_protobuf__libnngio_message__pack(mock_response_msg, resp_buffer);
  libnngio_mock_set_recv_buffer((const char *)resp_buffer, resp_pack_size);
  free(resp_buffer);
  nngio_free_nngio_message(mock_response_msg);
#endif

  libnngio_log("INF", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Preparing client to receive asynchronous RPC response...");
  LibnngioProtobuf__RpcResponse *client_recv_response = NULL;
  memset(&recv_sync, 0, sizeof(recv_sync));
  memset(&send_sync, 0, sizeof(send_sync));
  proto_rv =
      libnngio_client_recv_rpc_response_async(client, &client_recv_response,
                                              (libnngio_protobuf_recv_cb_info){
                                                  .user_cb = recv_rpc_callback,
                                                  .user_data = &recv_sync,
                                              });
  libnngio_log("INF", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Prepared to receiving RPC response with client.");

  libnngio_log("INF", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Server sending asynchronous RPC response...");
  proto_rv =
      libnngio_server_send_rpc_response_async(server, actual_rpc_response,
                                              (libnngio_protobuf_send_cb_info){
                                                  .user_cb = send_rpc_callback,
                                                  .user_data = &send_sync,
                                              });
  libnngio_log("INF", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
               "RPC response sent from server.");

  // wait for async operation to complete
  while (!send_sync.done) {
    nng_msleep(10);
  }
  while (!recv_sync.done) {
    nng_msleep(10);
  }

  libnngio_log("INF", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Asynchronous RPC response handling completed.");
  if (send_sync.result != 0 || recv_sync.result != 0) {
    libnngio_log("ERR", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
                 "Async RPC send result: %d", send_sync.result);
    libnngio_log("ERR", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
                 "Async RPC recv result: %d", recv_sync.result);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_context_free(req_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(0);
  }

  libnngio_log("INF", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Validating client received response...");
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
  assert(client_recv_response != NULL);
  assert(client_recv_response->status == 0);
  assert(client_recv_response->payload.len == length);
  assert(memcmp(client_recv_response->payload.data, "Hello, World!", length) ==
         0);
  libnngio_log("INF", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Client received RPC response with status %d and payload '%.*s' "
               "of len: %d",
               client_recv_response->status,
               (int)client_recv_response->payload.len,
               (char *)client_recv_response->payload.data,
               (int)client_recv_response->payload.len);
  libnngio_log("INF", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
               "RPC call to Echo.SayHello completed successfully.");

  libnngio_log("INF", "TEST_RPC_ASYNC", __FILE__, __LINE__, -1,
               "Async RPC test completed successfully.");

  // cleanup
  nngio_free_rpc_response(client_recv_response);
  nngio_free_rpc_request(actual_rpc_request);
  nngio_free_rpc_response(actual_rpc_response);
  nngio_free_rpc_request(rpc_request);
  libnngio_client_free(client);
  libnngio_server_free(server);
  libnngio_protobuf_context_free(rep_proto_ctx);
  libnngio_protobuf_context_free(req_proto_ctx);
  libnngio_context_free(rep_ctx);
  libnngio_context_free(req_ctx);
  libnngio_transport_free(rep);
  libnngio_transport_free(req);
}

void test_service_discovery_via_rpc(void) {
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC", __FILE__, __LINE__, -1,
               "Testing service discovery via rpc invocation...");

  // Initialize transport and contexts
  libnngio_config rep_cfg = {.mode = LIBNNGIO_MODE_LISTEN,
                             .proto = LIBNNGIO_PROTO_REP,
                             .url = "tcp://127.0.0.1:6666",
                             .tls_cert = NULL,
                             .tls_key = NULL,
                             .tls_ca_cert = NULL};

  libnngio_config req_cfg = {.mode = LIBNNGIO_MODE_DIAL,
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
  libnngio_protobuf_error_code proto_rv =
      libnngio_protobuf_context_init(&rep_proto_ctx, rep_ctx);
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
      {"SayGoodbye", echo_say_hello_handler, NULL}};
  proto_rv =
      libnngio_server_register_service(server, "Echo", echo_methods_reg, 2);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  // Register Math service
  libnngio_service_method math_methods_reg[] = {
      {"Add", math_add_handler, NULL},
      {"Subtract", math_add_handler, NULL},
      {"Multiply", math_add_handler, NULL}};
  proto_rv =
      libnngio_server_register_service(server, "Math", math_methods_reg, 3);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC", __FILE__, __LINE__, -1,
               "Server initialized with Echo and Math services.");

  // Initialize client
  libnngio_client *client = NULL;
  proto_rv = libnngio_client_init(&client, req_proto_ctx);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC", __FILE__, __LINE__, -1,
               "Client initialized.");

  // send rpc request from client and receive response on server
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC", __FILE__, __LINE__, -1,
               "Testing rpc call to Echo.SayHello...");

  // create service discovery
  LibnngioProtobuf__ServiceDiscoveryRequest *rq =
      malloc(sizeof(LibnngioProtobuf__ServiceDiscoveryRequest));
  libnngio_protobuf__service_discovery_request__init(rq);
  size_t rq_pack_size =
      libnngio_protobuf__service_discovery_request__get_packed_size(rq);
  uint8_t *rq_buffer = malloc(rq_pack_size);
  free(rq);

  // create rpc request
  LibnngioProtobuf__RpcRequest *rpc_request = nngio_create_rpc_request(
      "LibnngioProtobuf.ServiceDiscoveryService", "GetServices",
      (const char *)rq_buffer, rq_pack_size);
  free(rq_buffer);
  LibnngioProtobuf__RpcRequest *recv_rpc_request = NULL;

#ifdef NNGIO_MOCK_TRANSPORT
  // Mock rpc request
  LibnngioProtobuf__RpcRequest *fakerq = nngio_copy_rpc_request(rpc_request);
  LibnngioProtobuf__LibnngioMessage *mock_request_msg =
      nngio_create_nngio_message_with_rpc_request("uuid-req", fakerq);
  size_t req_pack_size =
      libnngio_protobuf__libnngio_message__get_packed_size(mock_request_msg);
  uint8_t *req_buffer = malloc(req_pack_size);
  libnngio_protobuf__libnngio_message__pack(mock_request_msg, req_buffer);
  libnngio_mock_set_recv_buffer((const char *)req_buffer, req_pack_size);
  free(req_buffer);
  nngio_free_nngio_message(mock_request_msg);
#endif

  libnngio_client_send_rpc_request(client, rpc_request);

  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC", __FILE__, __LINE__, -1,
               "Client RPC request sent.");
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC", __FILE__, __LINE__, -1,
               "Server receiving RPC request...");

  libnngio_server_recv_rpc_request(server, &recv_rpc_request);

  libnngio_log(
      "INF", "TEST_SERVICE_DISCOVERY_VIA_RPC", __FILE__, __LINE__, -1,
      "Server received RPC request for service %s method %s with payload %.*s",
      recv_rpc_request->service_name, recv_rpc_request->method_name,
      (int)recv_rpc_request->payload.len,
      (char *)recv_rpc_request->payload.data);
  assert(strcmp(recv_rpc_request->service_name,
                "LibnngioProtobuf.ServiceDiscoveryService") == 0);
  assert(strcmp(recv_rpc_request->method_name, "GetServices") == 0);
  assert(recv_rpc_request->payload.len == 0);
  assert(recv_rpc_request->payload.data == NULL);

  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC", __FILE__, __LINE__, -1,
               "Server Generating RPC response for request service %s method "
               "%s with payload of size %d",
               recv_rpc_request->service_name, recv_rpc_request->method_name,
               (int)recv_rpc_request->payload.len);

  // handle the request
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC", __FILE__, __LINE__, -1,
               "Handling the RPC request...");
  LibnngioProtobuf__RpcResponse *rpc_response = NULL;
  proto_rv = libnngio_server_create_rpc_response(server, recv_rpc_request,
                                                 &rpc_response);
#ifdef NNGIO_MOCK_TRANSPORT
  // Mock rpc response
  LibnngioProtobuf__RpcResponse *fakeresp =
      nngio_copy_rpc_response(rpc_response);
  LibnngioProtobuf__LibnngioMessage *mock_response_msg =
      nngio_create_nngio_message_with_rpc_response("uuid-resp", fakeresp);
  size_t resp_pack_size =
      libnngio_protobuf__libnngio_message__get_packed_size(mock_response_msg);
  uint8_t *resp_buffer = malloc(resp_pack_size);
  libnngio_protobuf__libnngio_message__pack(mock_response_msg, resp_buffer);
  libnngio_mock_set_recv_buffer((const char *)resp_buffer, resp_pack_size);
  free(resp_buffer);
  nngio_free_nngio_message(mock_response_msg);
#endif

  libnngio_log(
      "INF", "TEST_SERVICE_DISCOVERY_VIA_RPC", __FILE__, __LINE__, -1,
      "Server Generated RPC response status %d with payload of len: %d",
      rpc_response->status, (int)rpc_response->payload.len);
  // extract generated service discovery response from rpc response payload
  LibnngioProtobuf__ServiceDiscoveryResponse *service_discovery_response =
      libnngio_protobuf__service_discovery_response__unpack(
          NULL, rpc_response->payload.len, rpc_response->payload.data);

  assert(service_discovery_response != NULL);
  assert(service_discovery_response->n_services == 5);
  assert(strcmp(service_discovery_response->services[0]->name,
                "LibnngioProtobuf.RpcService") == 0);
  assert(strcmp(service_discovery_response->services[1]->name,
                "LibnngioProtobuf.ServiceDiscoveryService") == 0);
  assert(strcmp(service_discovery_response->services[2]->name,
                "LibnngioProtobuf.TransportService") == 0);
  assert(strcmp(service_discovery_response->services[3]->name, "Echo") == 0);
  assert(strcmp(service_discovery_response->services[4]->name, "Math") == 0);

  libnngio_log(
      "INF", "TEST_SERVICE_DISCOVERY_VIA_RPC", __FILE__, __LINE__, -1,
      "Service Discovery Response within RPC Response has %d services:",
      service_discovery_response->n_services);
  for (size_t i = 0; i < service_discovery_response->n_services; i++) {
    LibnngioProtobuf__Service *service =
        service_discovery_response->services[i];
    libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC", __FILE__, __LINE__,
                 -1, "Service %d: %s with %d methods", (int)i, service->name,
                 (int)service->n_methods);
    for (size_t j = 0; j < service->n_methods; j++) {
      char *method = service->methods[j];
      libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC", __FILE__, __LINE__,
                   -1, "  Method %d: %s", (int)j, method);
    }
  }
  libnngio_protobuf__service_discovery_response__free_unpacked(
      service_discovery_response, NULL);

  // send the response back to the client
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC", __FILE__, __LINE__, -1,
               "Sending RPC response back to client...");
  proto_rv = libnngio_server_send_rpc_response(server, rpc_response);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC", __FILE__, __LINE__, -1,
               "RPC response sent from server.");
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC", __FILE__, __LINE__, -1,
               "Client receiving RPC response...");

  LibnngioProtobuf__RpcResponse *client_recv_response = NULL;
  proto_rv = libnngio_client_recv_rpc_response(client, &client_recv_response);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
  assert(client_recv_response != NULL);
  assert(client_recv_response->status == 0);
  assert(client_recv_response->payload.len == rpc_response->payload.len);
  assert(memcmp(client_recv_response->payload.data, rpc_response->payload.data,
                rpc_response->payload.len) == 0);
  libnngio_log(
      "INF", "TEST_SERVICE_DISCOVERY_VIA_RPC", __FILE__, __LINE__, -1,
      "Client received RPC response with status %d and payload of len: %d",
      client_recv_response->status, (int)client_recv_response->payload.len);
  libnngio_log(
      "INF", "TEST_SERVICE_DISCOVERY_VIA_RPC", __FILE__, __LINE__, -1,
      "RPC call to LibnngioProtobuf.ServiceDiscoveryService.GetServices "
      "completed successfully.");

  nngio_free_rpc_response(client_recv_response);
  nngio_free_rpc_response(rpc_response);
  nngio_free_rpc_request(recv_rpc_request);
  nngio_free_rpc_request(rpc_request);
  libnngio_client_free(client);
  libnngio_server_free(server);
  libnngio_protobuf_context_free(rep_proto_ctx);
  libnngio_protobuf_context_free(req_proto_ctx);
  libnngio_context_free(rep_ctx);
  libnngio_context_free(req_ctx);
  libnngio_transport_free(rep);
  libnngio_transport_free(req);

  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC", __FILE__, __LINE__, -1,
               "Service Discovery via RPC test completed successfully.");
}

void test_service_discovery_via_rpc_async(void) {
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__,
               __LINE__, -1, "Testing async rpc invocation...");

  // Initialize transport and contexts
  libnngio_config rep_cfg = {.mode = LIBNNGIO_MODE_LISTEN,
                             .proto = LIBNNGIO_PROTO_REP,
                             .url = "tcp://127.0.0.1:6666",
                             .tls_cert = NULL,
                             .tls_key = NULL,
                             .tls_ca_cert = NULL};

  libnngio_config req_cfg = {.mode = LIBNNGIO_MODE_DIAL,
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
  libnngio_protobuf_error_code proto_rv =
      libnngio_protobuf_context_init(&rep_proto_ctx, rep_ctx);
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
      {"SayGoodbye", echo_say_hello_handler, NULL}};
  proto_rv =
      libnngio_server_register_service(server, "Echo", echo_methods_reg, 2);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  // Register Math service
  libnngio_service_method math_methods_reg[] = {
      {"Add", math_add_handler, NULL},
      {"Subtract", math_add_handler, NULL},
      {"Multiply", math_add_handler, NULL}};
  proto_rv =
      libnngio_server_register_service(server, "Math", math_methods_reg, 3);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__,
               __LINE__, -1, "Server initialized with Echo and Math services.");

  // Initialize client
  libnngio_client *client = NULL;
  proto_rv = libnngio_client_init(&client, req_proto_ctx);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__,
               __LINE__, -1, "Client initialized.");

  // send rpc request from client and receive response on server
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__,
               __LINE__, -1, "Testing rpc call to Echo.SayHello...");

  // create service discovery
  LibnngioProtobuf__ServiceDiscoveryRequest *rq =
      malloc(sizeof(LibnngioProtobuf__ServiceDiscoveryRequest));
  libnngio_protobuf__service_discovery_request__init(rq);
  size_t rq_pack_size =
      libnngio_protobuf__service_discovery_request__get_packed_size(rq);
  uint8_t *rq_buffer = malloc(rq_pack_size);
  free(rq);

  // create rpc request
  LibnngioProtobuf__RpcRequest *rpc_request = nngio_create_rpc_request(
      "LibnngioProtobuf.ServiceDiscoveryService", "GetServices",
      (const char *)rq_buffer, rq_pack_size);
  free(rq_buffer);
  LibnngioProtobuf__RpcRequest *recv_rpc_request = NULL;

#ifdef NNGIO_MOCK_TRANSPORT
  // Mock rpc request
  LibnngioProtobuf__RpcRequest *fakerq = nngio_copy_rpc_request(rpc_request);
  LibnngioProtobuf__LibnngioMessage *mock_request_msg =
      nngio_create_nngio_message_with_rpc_request("uuid-req", fakerq);
  size_t req_pack_size =
      libnngio_protobuf__libnngio_message__get_packed_size(mock_request_msg);
  uint8_t *req_buffer = malloc(req_pack_size);
  libnngio_protobuf__libnngio_message__pack(mock_request_msg, req_buffer);
  libnngio_mock_set_recv_buffer((const char *)req_buffer, req_pack_size);
  free(req_buffer);
  nngio_free_nngio_message(mock_request_msg);
#endif

  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__,
               __LINE__, -1, "Sending an asynchronous RPC request...");

  LibnngioProtobuf__RpcRequest *actual_rpc_request = NULL;
  LibnngioProtobuf__RpcResponse *actual_rpc_response = NULL;
  rpc_sync_t send_sync = {0}, recv_sync = {0};

  proto_rv = libnngio_server_handle_rpc_request_async(
      server, &actual_rpc_request, &actual_rpc_response,
      (libnngio_protobuf_recv_cb_info){
          .user_cb = recv_rpc_callback,
          .user_data = &recv_sync,
      });
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__,
               __LINE__, -1, "Asynchronous RPC handling initiated.");
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__,
               __LINE__, -1, "Sending an asynchronous RPC request...");

  proto_rv =
      libnngio_client_send_rpc_request_async(client, rpc_request,
                                             (libnngio_protobuf_send_cb_info){
                                                 .user_cb = send_rpc_callback,
                                                 .user_data = &send_sync,
                                             });
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__,
               __LINE__, -1, "Client RPC request sent.");

  // wait for async operation to complete
  while (!send_sync.done) {
    nng_msleep(10);
  }
  while (!recv_sync.done) {
    nng_msleep(10);
  }

  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__,
               __LINE__, -1, "Asynchronous RPC handling completed.");
  if (send_sync.result != 0 || recv_sync.result != 0) {
    libnngio_log("ERR", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__,
                 __LINE__, -1, "Async RPC send result: %d", send_sync.result);
    libnngio_log("ERR", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__,
                 __LINE__, -1, "Async RPC recv result: %d", recv_sync.result);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_context_free(req_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(0);
  }

  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__,
               __LINE__, -1, "Async RPC succeeded, validating request...");
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
  assert(actual_rpc_request != NULL);
  assert(strcmp(actual_rpc_request->service_name,
                "LibnngioProtobuf.ServiceDiscoveryService") == 0);
  assert(strcmp(actual_rpc_request->method_name, "GetServices") == 0);
  assert(actual_rpc_request->payload.len == 0);
  assert(actual_rpc_request->payload.data == NULL);
  libnngio_log(
      "INF", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__, __LINE__, -1,
      "Server received RPC request for service %s method %s with payload %.*s",
      actual_rpc_request->service_name, actual_rpc_request->method_name,
      (int)actual_rpc_request->payload.len,
      (char *)actual_rpc_request->payload.data);

  // validate the generated response
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__,
               __LINE__, -1, "Validating generated RPC response...");
  libnngio_log(
      "INF", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__, __LINE__, -1,
      "Server Generated RPC response status %d with payload of len: %d",
      actual_rpc_response->status, (int)actual_rpc_response->payload.len);
  assert(actual_rpc_response != NULL);
  assert(actual_rpc_response->status == 0);
  LibnngioProtobuf__ServiceDiscoveryResponse *service_discovery_response =
      libnngio_protobuf__service_discovery_response__unpack(
          NULL, actual_rpc_response->payload.len,
          actual_rpc_response->payload.data);
  assert(service_discovery_response != NULL);
  assert(service_discovery_response->n_services == 5);
  assert(strcmp(service_discovery_response->services[0]->name,
                "LibnngioProtobuf.RpcService") == 0);
  assert(strcmp(service_discovery_response->services[1]->name,
                "LibnngioProtobuf.ServiceDiscoveryService") == 0);
  assert(strcmp(service_discovery_response->services[2]->name,
                "LibnngioProtobuf.TransportService") == 0);
  assert(strcmp(service_discovery_response->services[3]->name, "Echo") == 0);
  assert(strcmp(service_discovery_response->services[4]->name, "Math") == 0);

  // prepare client to receive the response
#ifdef NNGIO_MOCK_TRANSPORT
  // Mock rpc response
  LibnngioProtobuf__RpcResponse *fakeresp =
      nngio_copy_rpc_response(actual_rpc_response);
  LibnngioProtobuf__LibnngioMessage *mock_response_msg =
      nngio_create_nngio_message_with_rpc_response("uuid-resp", fakeresp);
  size_t resp_pack_size =
      libnngio_protobuf__libnngio_message__get_packed_size(mock_response_msg);
  uint8_t *resp_buffer = malloc(resp_pack_size);
  libnngio_protobuf__libnngio_message__pack(mock_response_msg, resp_buffer);
  libnngio_mock_set_recv_buffer((const char *)resp_buffer, resp_pack_size);
  free(resp_buffer);
  nngio_free_nngio_message(mock_response_msg);
#endif

  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__,
               __LINE__, -1,
               "Preparing client to receive asynchronous RPC response...");
  LibnngioProtobuf__RpcResponse *client_recv_response = NULL;
  memset(&recv_sync, 0, sizeof(recv_sync));
  memset(&send_sync, 0, sizeof(send_sync));
  proto_rv =
      libnngio_client_recv_rpc_response_async(client, &client_recv_response,
                                              (libnngio_protobuf_recv_cb_info){
                                                  .user_cb = recv_rpc_callback,
                                                  .user_data = &recv_sync,
                                              });
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__,
               __LINE__, -1, "Prepared to receiving RPC response with client.");

  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__,
               __LINE__, -1, "Server sending asynchronous RPC response...");
  proto_rv =
      libnngio_server_send_rpc_response_async(server, actual_rpc_response,
                                              (libnngio_protobuf_send_cb_info){
                                                  .user_cb = send_rpc_callback,
                                                  .user_data = &send_sync,
                                              });
  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__,
               __LINE__, -1, "RPC response sent from server.");

  // wait for async operation to complete
  while (!send_sync.done) {
    nng_msleep(10);
  }
  while (!recv_sync.done) {
    nng_msleep(10);
  }

  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__,
               __LINE__, -1, "Asynchronous RPC response handling completed.");
  if (send_sync.result != 0 || recv_sync.result != 0) {
    libnngio_log("ERR", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__,
                 __LINE__, -1, "Async RPC send result: %d", send_sync.result);
    libnngio_log("ERR", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__,
                 __LINE__, -1, "Async RPC recv result: %d", recv_sync.result);
    libnngio_protobuf_context_free(rep_proto_ctx);
    libnngio_protobuf_context_free(req_proto_ctx);
    libnngio_context_free(rep_ctx);
    libnngio_context_free(req_ctx);
    libnngio_transport_free(rep);
    libnngio_transport_free(req);
    assert(0);
  }

  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__,
               __LINE__, -1, "Validating client received response...");
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
  assert(client_recv_response != NULL);
  assert(client_recv_response->status == 0);
  assert(client_recv_response->payload.len == actual_rpc_response->payload.len);
  assert(memcmp(client_recv_response->payload.data,
                actual_rpc_response->payload.data,
                actual_rpc_response->payload.len) == 0);
  libnngio_log(
      "INF", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__, __LINE__, -1,
      "Client received RPC response with status %d and payload of len: %d",
      client_recv_response->status, (int)client_recv_response->payload.len);
  libnngio_log(
      "INF", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__, __LINE__, -1,
      "RPC call to LibnngioProtobuf.ServiceDiscoveryService.GetServices "
      "completed successfully.");

  libnngio_log("INF", "TEST_SERVICE_DISCOVERY_VIA_RPC_ASYNC", __FILE__,
               __LINE__, -1, "Async RPC test completed successfully.");

  // cleanup
  libnngio_protobuf__service_discovery_response__free_unpacked(
      service_discovery_response, NULL);
  nngio_free_rpc_response(client_recv_response);
  nngio_free_rpc_request(actual_rpc_request);
  nngio_free_rpc_response(actual_rpc_response);
  nngio_free_rpc_request(rpc_request);
  libnngio_client_free(client);
  libnngio_server_free(server);
  libnngio_protobuf_context_free(rep_proto_ctx);
  libnngio_protobuf_context_free(req_proto_ctx);
  libnngio_context_free(rep_ctx);
  libnngio_context_free(req_ctx);
  libnngio_transport_free(rep);
  libnngio_transport_free(req);
}

void test_transport_operations(void) {
  libnngio_log("INF", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
               "Testing transport operations...");

  // Initialize transport and contexts
  libnngio_config rep_cfg = {.mode = LIBNNGIO_MODE_LISTEN,
                             .proto = LIBNNGIO_PROTO_REP,
                             .url = "tcp://127.0.0.1:7777",
                             .tls_cert = NULL,
                             .tls_key = NULL,
                             .tls_ca_cert = NULL};
  libnngio_config req_cfg = {.mode = LIBNNGIO_MODE_DIAL,
                             .proto = LIBNNGIO_PROTO_REQ,
                             .url = "tcp://127.0.0.1:7777",
                             .tls_cert = NULL,
                             .tls_key = NULL,
                             .tls_ca_cert = NULL};

  libnngio_transport *rep = NULL, *req = NULL;
  libnngio_context *rep_ctx = NULL, *req_ctx = NULL;
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

  // create server and client
  libnngio_protobuf_context *rep_proto_ctx = NULL, *req_proto_ctx = NULL;
  libnngio_protobuf_error_code proto_rv =
      libnngio_protobuf_context_init(&rep_proto_ctx, rep_ctx);
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

  libnngio_server *server = NULL;
  proto_rv = libnngio_server_init(&server, rep_proto_ctx);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
  libnngio_client *client = NULL;
  proto_rv = libnngio_client_init(&client, req_proto_ctx);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  libnngio_log("INF", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
               "Transport, contexts, server, and client initialized.");

  // create a Transport for our client to add to the server's known transports
  size_t num_transports = 10;
  for (size_t i = 0; i < num_transports; i++) {
    char name[50];
    snprintf(name, 50, "Transport-%zu", i);
    char url[100];
    snprintf(url, 100, "tcp://127.0.0.1:%zu", 5000 + i);
    libnngio_config cfg = {0};
    cfg.name = name;
    cfg.mode = LIBNNGIO_MODE_LISTEN;
    cfg.proto = LIBNNGIO_PROTO_REP;
    cfg.url = url;
    cfg.tls_cert = NULL;
    cfg.tls_key = NULL;
    cfg.tls_ca_cert = NULL;
    LibnngioProtobuf__AddTransportRequest *atreq =
        nngio_create_add_transport_request(&cfg);
    assert(atreq != NULL);
    assert(atreq->transport != NULL);
    assert(strcmp(atreq->transport->name, cfg.name) == 0);
    assert(strcmp(atreq->transport->url, cfg.url) == 0);
    assert(atreq->transport->mode == LIBNNGIO_PROTOBUF__TRANSPORT_MODE__Listen);
    assert(atreq->transport->proto ==
           LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Rep);
    if (!atreq) {
      libnngio_log("ERR", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
                   "Failed to create AddTransport message.");
      libnngio_protobuf__add_transport_request__free_unpacked(atreq, NULL);
      assert(0);
    }

    // create rpc request to add transport
    size_t atreq_pack_size =
        libnngio_protobuf__add_transport_request__get_packed_size(atreq);
    uint8_t *atreq_buffer = malloc(atreq_pack_size);
    libnngio_protobuf__add_transport_request__pack(atreq, atreq_buffer);
    LibnngioProtobuf__RpcRequest *rpc_request = nngio_create_rpc_request(
        "LibnngioProtobuf.TransportService", "AddTransport",
        (const char *)atreq_buffer, atreq_pack_size);
    free(atreq_buffer);
    if (!rpc_request) {
      libnngio_log("ERR", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
                   "Failed to create RPC request for AddTransport.");
      libnngio_protobuf__add_transport_request__free_unpacked(atreq, NULL);
      assert(0);
    }

    libnngio_log("INF", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
                 "Packed add transport request into RPC request for service %s "
                 "method %s with payload of size %d",
                 rpc_request->service_name, rpc_request->method_name,
                 (int)rpc_request->payload.len);

#ifdef NNGIO_MOCK_TRANSPORT
    // Mock rpc request
    LibnngioProtobuf__RpcRequest *fakerq = nngio_copy_rpc_request(rpc_request);
    LibnngioProtobuf__LibnngioMessage *mock_request_msg =
        nngio_create_nngio_message_with_rpc_request(
            "84a9f303-0f3e-43e2-a86a-9e136eaca57c", fakerq);
    size_t req_pack_size =
        libnngio_protobuf__libnngio_message__get_packed_size(mock_request_msg);
    uint8_t *req_buffer = malloc(req_pack_size);
    libnngio_protobuf__libnngio_message__pack(mock_request_msg, req_buffer);
    libnngio_mock_set_recv_buffer((const char *)req_buffer, req_pack_size);
    free(req_buffer);
    nngio_free_nngio_message(mock_request_msg);
#endif

    LibnngioProtobuf__RpcRequest *recv_rpc_request = NULL;
    libnngio_log("INF", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
                 "Sending AddTransport RPC request...");
    proto_rv = libnngio_client_send_rpc_request(client, rpc_request);
    assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
    proto_rv = libnngio_server_recv_rpc_request(server, &recv_rpc_request);
    assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

    // validate received rpc request
    libnngio_log("INF", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
                 "Server received RPC request for service %s method %s with "
                 "payload of size %d",
                 recv_rpc_request->service_name, recv_rpc_request->method_name,
                 (int)recv_rpc_request->payload.len);
    assert(strcmp(recv_rpc_request->service_name,
                  "LibnngioProtobuf.TransportService") == 0);
    assert(strcmp(recv_rpc_request->method_name, "AddTransport") == 0);
    assert(recv_rpc_request->payload.len ==
           libnngio_protobuf__add_transport_request__get_packed_size(atreq));
    LibnngioProtobuf__AddTransportRequest *atreq_recv =
        libnngio_protobuf__add_transport_request__unpack(
            NULL, recv_rpc_request->payload.len,
            recv_rpc_request->payload.data);
    assert(atreq_recv != NULL);
    assert(strcmp(atreq_recv->transport->name, cfg.name) == 0);
    assert(strcmp(atreq_recv->transport->url, cfg.url) == 0);
    assert(atreq_recv->transport->mode ==
           LIBNNGIO_PROTOBUF__TRANSPORT_MODE__Listen);
    assert(atreq_recv->transport->proto ==
           LIBNNGIO_PROTOBUF__TRANSPORT_PROTOCOL__Rep);
    libnngio_protobuf__add_transport_request__free_unpacked(atreq_recv, NULL);

    LibnngioProtobuf__RpcResponse *rpc_response = NULL;
    libnngio_log("INF", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
                 "Handling AddTransport RPC request...");
    proto_rv = libnngio_server_create_rpc_response(server, recv_rpc_request,
                                                   &rpc_response);
    if (proto_rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
      libnngio_log("ERR", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
                   "Failed to create RPC response for AddTransport.");
      libnngio_log("ERR", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
                   "Return code: %d", proto_rv);
      libnngio_log("ERR", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
                   "RPC response message: %s", rpc_response->error_message);
      assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
    }
    libnngio_log(
        "INF", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
        "Server Generated RPC response status %d with payload of len: %d",
        rpc_response->status, (int)rpc_response->payload.len);

#ifdef NNGIO_MOCK_TRANSPORT
    // Mock rpc response
    LibnngioProtobuf__RpcResponse *fakeresp =
        nngio_copy_rpc_response(rpc_response);
    LibnngioProtobuf__LibnngioMessage *mock_response_msg =
        nngio_create_nngio_message_with_rpc_response("uuid-resp", fakeresp);
    size_t resp_pack_size =
        libnngio_protobuf__libnngio_message__get_packed_size(mock_response_msg);
    uint8_t *resp_buffer = malloc(resp_pack_size);
    libnngio_protobuf__libnngio_message__pack(mock_response_msg, resp_buffer);
    libnngio_mock_set_recv_buffer((const char *)resp_buffer, resp_pack_size);
    free(resp_buffer);
    nngio_free_nngio_message(mock_response_msg);
#endif

    assert(server->n_transports == i + 1);

    LibnngioProtobuf__RpcResponse *recv_rpc_response = NULL;
    proto_rv = libnngio_server_send_rpc_response(server, rpc_response);
    assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
    libnngio_log("INF", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
                 "AddTransport RPC response sent.");
    proto_rv = libnngio_client_recv_rpc_response(client, &recv_rpc_response);
    assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
    libnngio_log("INF", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
                 "AddTransport RPC response received.");

    nngio_free_rpc_response(recv_rpc_response);
    nngio_free_rpc_response(rpc_response);
    nngio_free_rpc_request(recv_rpc_request);
    nngio_free_rpc_request(rpc_request);
    nngio_free_add_transport_request(atreq);
  }

  size_t half_n_transports = num_transports / 2;
  for (size_t i = 0; i < half_n_transports; i++) {
    char name[50];
    snprintf(name, 50, "Transport-%zu", i);
    char url[100];
    snprintf(url, 100, "tcp://127.0.0.1:%zu", 5000 + i);
    LibnngioProtobuf__RemoveTransportRequest *rtreq =
        nngio_create_remove_transport_request(name, LIBNNGIO_MODE_LISTEN,
                                              LIBNNGIO_PROTO_REP, url);
    assert(rtreq != NULL);
    if (!rtreq) {
      libnngio_log("ERR", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
                   "Failed to create RemoveTransport message.");
      libnngio_protobuf__remove_transport_request__free_unpacked(rtreq, NULL);
      assert(0);
    }

    // create rpc request to remove transport
    size_t rtreq_pack_size =
        libnngio_protobuf__remove_transport_request__get_packed_size(rtreq);
    uint8_t *rtreq_buffer = malloc(rtreq_pack_size);
    libnngio_protobuf__remove_transport_request__pack(rtreq, rtreq_buffer);
    LibnngioProtobuf__RpcRequest *rpc_request = nngio_create_rpc_request(
        "LibnngioProtobuf.TransportService", "RemoveTransport",
        (const char *)rtreq_buffer, rtreq_pack_size);
    free(rtreq_buffer);
    if (!rpc_request) {
      libnngio_log("ERR", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
                   "Failed to create RPC request for RemoveTransport.");
      libnngio_protobuf__remove_transport_request__free_unpacked(rtreq, NULL);
      assert(0);
    }

    libnngio_log("INF", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
                 "Packed remove transport request into RPC request for service "
                 "%s method %s with payload of size %d",
                 rpc_request->service_name, rpc_request->method_name,
                 (int)rpc_request->payload.len);

#ifdef NNGIO_MOCK_TRANSPORT
    // Mock rpc request
    LibnngioProtobuf__RpcRequest *fakerq = nngio_copy_rpc_request(rpc_request);
    LibnngioProtobuf__LibnngioMessage *mock_request_msg =
        nngio_create_nngio_message_with_rpc_request(
            "84a9f303-0f3e-43e2-a86a-9e136eaca57c", fakerq);
    size_t req_pack_size =
        libnngio_protobuf__libnngio_message__get_packed_size(mock_request_msg);
    uint8_t *req_buffer = malloc(req_pack_size);
    libnngio_protobuf__libnngio_message__pack(mock_request_msg, req_buffer);
    libnngio_mock_set_recv_buffer((const char *)req_buffer, req_pack_size);
    free(req_buffer);
    nngio_free_nngio_message(mock_request_msg);
#endif

    LibnngioProtobuf__RpcRequest *recv_rpc_request = NULL;
    libnngio_log("INF", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
                 "Sending RemoveTransport RPC request...");
    proto_rv = libnngio_client_send_rpc_request(client, rpc_request);
    assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
    proto_rv = libnngio_server_recv_rpc_request(server, &recv_rpc_request);
    assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

    // validate received rpc request
    libnngio_log("INF", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
                 "Server received RPC request for service %s method %s with "
                 "payload of size %d",
                 recv_rpc_request->service_name, recv_rpc_request->method_name,
                 (int)recv_rpc_request->payload.len);
    assert(strcmp(recv_rpc_request->service_name,
                  "LibnngioProtobuf.TransportService") == 0);
    assert(strcmp(recv_rpc_request->method_name, "RemoveTransport") == 0);
    assert(recv_rpc_request->payload.len ==
           libnngio_protobuf__remove_transport_request__get_packed_size(rtreq));
    LibnngioProtobuf__RemoveTransportRequest *rtreq_recv =
        libnngio_protobuf__remove_transport_request__unpack(
            NULL, recv_rpc_request->payload.len,
            recv_rpc_request->payload.data);
    assert(rtreq_recv != NULL);
    assert(strcmp(rtreq_recv->name, name) == 0);
    libnngio_protobuf__remove_transport_request__free_unpacked(rtreq_recv,
                                                               NULL);

    LibnngioProtobuf__RpcResponse *rpc_response = NULL;
    libnngio_log("INF", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
                 "Handling RemoveTransport RPC request...");
    proto_rv = libnngio_server_create_rpc_response(server, recv_rpc_request,
                                                   &rpc_response);
    if (proto_rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
      libnngio_log("ERR", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
                   "Failed to create RPC response for RemoveTransport.");
      libnngio_log("ERR", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
                   "Return code: %d", proto_rv);
      libnngio_log("ERR", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
                   "RPC response message: %s", rpc_response->error_message);
      assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
    }
    libnngio_log(
        "INF", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
        "Server Generated RPC response status %d with payload of len: %d",
        rpc_response->status, (int)rpc_response->payload.len);

#ifdef NNGIO_MOCK_TRANSPORT
    // Mock rpc response
    LibnngioProtobuf__RpcResponse *fakeresp =
        nngio_copy_rpc_response(rpc_response);
    LibnngioProtobuf__LibnngioMessage *mock_response_msg =
        nngio_create_nngio_message_with_rpc_response("uuid-resp", fakeresp);
    size_t resp_pack_size =
        libnngio_protobuf__libnngio_message__get_packed_size(mock_response_msg);
    uint8_t *resp_buffer = malloc(resp_pack_size);
    libnngio_protobuf__libnngio_message__pack(mock_response_msg, resp_buffer);
    libnngio_mock_set_recv_buffer((const char *)resp_buffer, resp_pack_size);
    free(resp_buffer);
    nngio_free_nngio_message(mock_response_msg);
#endif

    assert(server->n_transports == (num_transports - (i + 1)));

    LibnngioProtobuf__RpcResponse *recv_rpc_response = NULL;
    proto_rv = libnngio_server_send_rpc_response(server, rpc_response);
    assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
    libnngio_log("INF", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
                 "RemoveTransport RPC response sent.");
    proto_rv = libnngio_client_recv_rpc_response(client, &recv_rpc_response);
    assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
    libnngio_log("INF", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
                 "RemoveTransport RPC response received.");

    nngio_free_rpc_response(recv_rpc_response);
    nngio_free_rpc_response(rpc_response);
    nngio_free_rpc_request(recv_rpc_request);
    nngio_free_rpc_request(rpc_request);
    nngio_free_remove_transport_request(rtreq);
  }

  // cleanup
  libnngio_client_free(client);
  libnngio_server_free(server);
  libnngio_protobuf_context_free(rep_proto_ctx);
  libnngio_protobuf_context_free(req_proto_ctx);
  libnngio_context_free(rep_ctx);
  libnngio_context_free(req_ctx);
  libnngio_transport_free(rep);
  libnngio_transport_free(req);

  libnngio_log("INF", "TEST_TRANSPORT_OPERATIONS", __FILE__, __LINE__, -1,
               "Transport operations test completed successfully.");
}

void test_forwarders(void) {
  libnngio_log("INF", "TEST_FORWARDERS", __FILE__, __LINE__, -1,
               "Testing forwarders...");

  // Initialize transport and contexts
  libnngio_config rep_cfg = {.mode = LIBNNGIO_MODE_LISTEN,
                             .proto = LIBNNGIO_PROTO_REP,
                             .url = "tcp://127.0.0.1:7777",
                             .tls_cert = NULL,
                             .tls_key = NULL,
                             .tls_ca_cert = NULL};
  libnngio_config req_cfg = {.mode = LIBNNGIO_MODE_DIAL,
                             .proto = LIBNNGIO_PROTO_REQ,
                             .url = "tcp://127.0.0.1:7777",
                             .tls_cert = NULL,
                             .tls_key = NULL,
                             .tls_ca_cert = NULL};

  libnngio_transport *rep = NULL, *req = NULL;
  libnngio_context *rep_ctx = NULL, *req_ctx = NULL;
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

  // create server and client
  libnngio_protobuf_context *rep_proto_ctx = NULL, *req_proto_ctx = NULL;
  libnngio_protobuf_error_code proto_rv =
      libnngio_protobuf_context_init(&rep_proto_ctx, rep_ctx);
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

  libnngio_server *server = NULL;
  proto_rv = libnngio_server_init(&server, rep_proto_ctx);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);
  libnngio_client *client = NULL;
  proto_rv = libnngio_client_init(&client, req_proto_ctx);
  assert(proto_rv == LIBNNGIO_PROTOBUF_ERR_NONE);

  libnngio_log("INF", "TEST_FORWARDERS", __FILE__, __LINE__, -1,
               "Transport, contexts, server, and client initialized.");

  // Test scenario: Add a couple transports, create forwarder between them,
  // verify messages forwarded
  // create configured transports and add to server
  LibnngioProtobuf__AddTransportRequest *t1 =
      nngio_create_add_transport_request(&(libnngio_config){
          .name = "ForwarderTransport1",
          .mode = LIBNNGIO_MODE_LISTEN,
          .proto = LIBNNGIO_PROTO_PAIR,
          .url = "tcp://127.0.0.1:8001",
          .tls_cert = NULL,
          .tls_key = NULL,
          .tls_ca_cert = NULL,
      });
  LibnngioProtobuf__AddTransportRequest *t2 =
      nngio_create_add_transport_request(&(libnngio_config){
          .name = "ForwarderTransport2",
          .mode = LIBNNGIO_MODE_DIAL,
          .proto = LIBNNGIO_PROTO_PAIR,
          .url = "tcp://127.0.0.1:8002",
          .tls_cert = NULL,
          .tls_key = NULL,
          .tls_ca_cert = NULL,
      });

  // Here we would create a forwarder between transport1 and transport2
  libnngio_log("INF", "TEST_FORWARDERS", __FILE__, __LINE__, -1,
               "Creating forwarder between %s and %s", t1->transport->name,
               t2->transport->name);

  // You could create create forwarder manually like this
  // libnngio_protobuf_forwarder *forwarder = (libnngio_protobuf_forwarder
  // *)malloc(sizeof(libnngio_protobuf_forwarder)); forwarder->name =
  // strdup("TestForwarder"); forwarder->input = strdup(transport1->name);
  // forwarder->outputs = (char **)malloc(1 * sizeof(char *));
  // forwarder->outputs[0] = strdup(transport2->name);
  // forwarder->n_outputs = 1;
  // forwarder->running = true;
  // forwarder->fwd_func = libnngio_protobuf_default_forward_func;
  // forwarder->fwd_storage = NULL;

  // alternatively, create a fowarder with the create function
  libnngio_protobuf_forwarder *forwarder = NULL;
  proto_rv = libnngio_protobuf_create_forwarder(
      &forwarder, "TestForwarder", t1->transport->name,
      (const char **)t1->transport->name, 1,
      libnngio_protobuf_default_forward_func, NULL);

  // cleanup
  nngio_free_add_transport_request(t1);
  nngio_free_add_transport_request(t2);
  libnngio_server_free(server);
  libnngio_client_free(client);
  libnngio_protobuf_context_free(rep_proto_ctx);
  libnngio_protobuf_context_free(req_proto_ctx);
  libnngio_context_free(rep_ctx);
  libnngio_context_free(req_ctx);
  libnngio_transport_free(rep);
  libnngio_transport_free(req);

  libnngio_log("INF", "TEST_FORWARDERS", __FILE__, __LINE__, -1,
               "Forwarders test completed successfully.");
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
  test_rpc_service_discovery();
  test_rpc_service_discovery_async();
  test_rpc();
  test_rpc_asyc();
  test_service_discovery_via_rpc();
  test_service_discovery_via_rpc_async();
  test_transport_operations();
  test_forwarders();
  return 0;
}
