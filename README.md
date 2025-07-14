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

Additional optional dependencies for testing and development:

- [inotify-tools](https://github.com/inotify-tools/inotify-tools) - For file system monitoring
- [valgrind](http://valgrind.org/) - For memory leak detection

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
   # Optionally, provide DEBUG=1 or TEST_MOCK=1 to enable debug builds or mock testing
    make test
    ```
3. **Using test-loop.sh**: You can also run the tests using the provided script:
   ```bash
   ./test-loop.sh
   ```
   This will run the tests in a loop, which is useful for development and debugging.


# License

This library is licensed under the MIT License. See the [LICENSE](LICENSE.txt) file for details.

Please refer to the NNG and mbedtls for their respective licenses and terms of use.

# Contributing

Contributions are welcome! Please feel free to submit issues, pull requests, or suggestions.

# Contact

For any questions or issues, please open an issue on the GitHub.
