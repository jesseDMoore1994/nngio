# libnngio

This is a C library that provides an interface to [NNG](https://nng.nanomsg.org/), a modern networking library.

Mostly, it provides a facade to the NNG library, similar to the nngcat command line tool,
provided upstream by the NNG project. Rather than using the command line to provide the
options, tls credentials, etc. it provides a C API to do the same thing programmatically.

# Features

- Initialization and cleanup of NNG library
- Support for NNG sockets, addresses, and transports
- Support for various NNG protocols (e.g., PUB/SUB, REQ/REP, etc.)
- Support for Synchronous and Asynchronous operations
  - Synchronous send and receive functions over transport
  - Asynchronous send and receive functions over context
- Support for TLS credentials and options

# Usage

To use this library, you need to include the header file and link against the library.

```c
#include <nngio/main/libnngio_main.h>

typedef struct {
  volatile int done;
  int result;
  char buf[256];
  size_t len;
} async_test_sync;

void async_recv_cb(libnngio_context *ctx, int result, void *data, size_t len,
                   void *user_data) {
  libnngio_log("INF", "TEST_ASYNC_RECV_CB", __FILE__, __LINE__, -1,
               "Async recv callback called with result=%d, len=%zu", result,
               len);
  async_test_sync *sync = (async_test_sync *)user_data;
  if (result == 0 && data && len <= sizeof(sync->buf)) {
    memcpy(sync->buf, data, len);
    sync->len = len;
  } else {
    sync->len = 0;
  }
  sync->result = result;
  sync->done = 1;
}

void async_send_cb(libnngio_context *ctx, int result, void *data, size_t len,
                   void *user_data) {
  libnngio_log("INF", "TEST_ASYNC_SEND_CB", __FILE__, __LINE__, -1,
               "Async send callback called with result=%d, len=%zu", result,
               len);
  async_test_sync *sync = (async_test_sync *)user_data;
  sync->result = result;
  sync->done = 1;
}

int main() {
  libnngio_log_init("DBG")
  libnngio_transport *server = NULL, *client = NULL;
  libnngio_config server_cfg = {0}, client_cfg = {0};
  libnngio_context *server_ctx = NULL, *client_ctx = NULL;
  const char *url = "tls+tcp://127.0.0.1:5558";
  int rv;

  // Paths to server PEM files (update as appropriate)
  const char *ca_cert = "test_certs/dev-ca.pem";
  const char *s_cert = "test_certs/server.crt";
  const char *s_key = "test_certs/server.key";
  const char *c_cert = "test_certs/client.crt";
  const char *c_key = "test_certs/client.key";

  server_cfg.mode = LIBNNGIO_MODE_LISTEN;
  server_cfg.proto = LIBNNGIO_PROTO_REP;
  server_cfg.url = url;
  server_cfg.tls_cert = s_cert;
  server_cfg.tls_key = s_key;
  server_cfg.tls_ca_cert = ca_cert;

  client_cfg.mode = LIBNNGIO_MODE_DIAL;
  client_cfg.proto = LIBNNGIO_PROTO_REQ;
  client_cfg.url = url;
  client_cfg.tls_cert = c_cert;
  client_cfg.tls_key = c_key;
  client_cfg.tls_ca_cert = ca_cert;

  rv = libnngio_transport_init(&server, &server_cfg);
  assert(rv == 0);

  rv = libnngio_transport_init(&client, &client_cfg);
  assert(rv == 0);

  rv = libnngio_context_init(&server_ctx, server, &server_cfg, NULL, NULL);
  assert(rv == 0);

  rv = libnngio_context_init(&client_ctx, client, &client_cfg, NULL, NULL);
  assert(rv == 0);

  sleep_ms(100);

  const char *hello = "hello-tls-async";
  async_test_sync send_sync = {0}, recv_sync = {0};

  recv_sync.len = sizeof(recv_sync.buf);
  rv = libnngio_context_recv_async(server_ctx, recv_sync.buf, &recv_sync.len,
                                     async_recv_cb, &recv_sync);
  assert(rv == 0);


  rv = libnngio_context_send_async(client_ctx, hello, strlen(hello) + 1,
                                     async_send_cb, &send_sync);
  assert(rv == 0);

  while (!send_sync.done) {
    sleep_ms(1);
  }
  assert(send_sync.result == 0);

  while (!recv_sync.done) {
    sleep_ms(1);
  }
  assert(recv_sync.result == 0);
  assert(strcmp(recv_sync.buf, hello) == 0);

  libnngio_context_free(client_ctx);
  libnngio_context_free(server_ctx);
  libnngio_transport_free(client);
  libnngio_transport_free(server);
}
```

# Building

I strongly recommend using [Nix](https://nixos.org/). I try to keep my code as
generic as possible, so you can also try to build without Nix, but I cannot
guarantee that it will work on your system without some manual adjustments.

If you use Nix, you can also use `direnv` to automatically load the Nix
environment when you enter the directory. I use this direnv to drive the
makefile from the Nix environment, so you can use the Makefile without having
to worry about the dependencies.

To that end, if you elect to not use Nix, you will need to install the
dependencies manually. The library depends on the following libraries:

- [clang](https://clang.llvm.org/) - For building the library
- [NNG](https://nng.nanomsg.org/) - The core networking library
- [mbedtls](https://tls.mbed.org/) - For TLS support
- [doxygen](https://www.doxygen.nl/) - For generating documentation

Additional optional dependencies for testing and development:

- [inotify-tools](https://github.com/inotify-tools/inotify-tools) - For file system monitoring
- [valgrind](http://valgrind.org/) - For memory leak detection
- [gdb](https://www.gnu.org/software/gdb/) - For debugging

# Generating test certificates

I have provided a generated set of test certificates for TLS support. If they
go stale, or you would like certificates with different parameters, you can
check out my other repository [gen-dev-tls](https://github.com/jesseDMoore1994/gen-dev-tls).

# Testing

To run the tests, you have multiple options:

1. **Using Nix**: If you are using the Nix flake, you can run the tests with:
   ```bash
   # The build command will automatically run the tests
   nix build
   ```
   This is useful if you just want to do a spot check of the library.
2. **Using Makefile**: If you prefer to use the Makefile, you can run:
   ```bash
   # Optionally, provide NNGIO_DEBUG=1 or NNGIO_MOCK_MAIN=1 to enable debug 
   # builds or mock testing. You can also set NNGIO_LOGLEVEL=DBG to enable
   # debug level logging.
    make test
    ```
3. **Using test-loop.sh**: You can also run the tests using the provided script:
   ```bash
   ./test-loop.sh
   ```
   This will run the tests in a loop, which is useful for development and debugging.

# Debugging

To enable debugging, you can set the `NNGIO_DEBUG` environment variable to `1`
and recompile the library. This will disable optimizations, enable debug symbols,
and set a define a preprocessor definition called `NNGIO_DEBUG`. The defintion
is currently unused, but it is there for future use if needed. If you build
with `NNGIO_DEBUG=1`, you can also use the `NNGIO_MOCK_MAIN=1` to enable mock
testing, which is useful for testing the library without requiring running the
actual NNG library itself. The mock library is also published by this project,
so it can be used independently of the main library downstream for your own
testing. I found this useful for doing valgrind testing without having to worry
about the NNG library itself. I would encounter deadlocks in the NNG library
when running under valgrind, so I created the mock library to avoid that issue.

# Logging

To adust from the default logging level of `ERR`, you can set the
`NNGIO_LOGLEVEL` environment variable to one of the following values:
- `DBG` - Debug level logging
- `INF` - Info level logging
- `NTC` - Notice level logging
- `WRN` - Warning level logging
- `ERR` - Error level logging (default)

This also sets the logging in the NNG library, so you can use see the NNG logs
as well.

# License

This library is licensed under the MIT License. See the [LICENSE](LICENSE.txt) file for details.

Please refer to the NNG and mbedtls for their respective licenses and terms of use.

# Contributing

Contributions are welcome! Please feel free to submit issues, pull requests, or suggestions.

# Contact

For any questions or issues, please open an issue on the GitHub.
