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
- Support for TLS credentials and options

# Usage

To use this library, you need to include the header file and link against the library.

```c
#include <nngio/main/libnngio_main.h>

// Example usage
int main() {
    // Initialize NNG library
    libnngio_ctx *ctx = NULL;
    libnngio_config_t config = {0};

    config.tls_cert = "path/to/cert.pem";
    config.tls_key = "path/to/key.pem";
    config.tls_ca = "path/to/ca.pem";
    config.mode = LIBNNGIO_MODE_DIAL;
    config.proto = LIBNNGIO_PROTO_PAIR;
    config.url = "tcp://localhost:5555";

    if (libnngio_init(&ctx, &config) != 0) {
        fprintf(stderr, "Failed to initialize libnngio\n");
        return -1;
    }

    const char *message = "Hello, NNG!";
    if (libnngio_send(ctx, message, strlen(message)) != 0) {
        fprintf(stderr, "Failed to send message\n");
        libnngio_free(ctx);
        return -1;
    }

    libnngio_free(ctx);
}
```

# Building

I strongly recommend using [Nix](https://nixos.org/). You can also build this
library using the Makefile provided in the repository, but you will need to
install the NNG library and its dependencies manually. The nix flake provides
a development environment with all the dependencies needed to build and run
the library tests, publish the library, etc.

# License

This library is licensed under the MIT License. See the [LICENSE](LICENSE.txt) file for details.

Please refer to the NNG and mbedtls for their respective licenses and terms of use.

# Contributing

Contributions are welcome! Please feel free to submit issues, pull requests, or suggestions.

# Contact

For any questions or issues, please open an issue on the GitHub.
