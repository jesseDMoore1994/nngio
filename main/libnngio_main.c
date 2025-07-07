#include "main/libnngio_main.h"
#include <nng/nng.h>
#include <nng/protocol/pair0/pair.h>
#include <nng/supplemental/tls/tls.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// Context data structure
struct libnngio_ctx {
    nng_socket sock;
    nng_dialer dialer;
    nng_listener listener;
    int is_open;
    int is_dial;
    // Store allocated PEM buffers to free on ctx free
    char *tls_cert_mem;
    char *tls_key_mem;
    char *tls_ca_mem;
};

// Helper: Read a file into a NUL-terminated string buffer
static char *libnngio_read_file(const char *filename) {
    FILE *f = fopen(filename, "rb");
    char *buf = NULL;
    long sz;
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    rewind(f);
    buf = (char *)malloc(sz + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, sz, f) != (size_t)sz) { free(buf); fclose(f); return NULL; }
    buf[sz] = 0;
    fclose(f);
    return buf;
}

static int libnngio_proto_open(nng_socket *sock, libnngio_proto proto) {
    switch (proto) {
        case LIBNNGIO_PROTO_PAIR:
            return nng_pair0_open(sock);
        default:
            return NNG_ENOTSUP;
    }
}

// Configure the TLS config object on dialer/listener
static int libnngio_configure_tls(libnngio_ctx *ctx,
                                  nng_dialer dialer, nng_listener listener, int is_dial,
                                  const char *certfile, const char *keyfile, const char *cacert) {
    nng_tls_config *tls = NULL;
    int rv = 0;
    char *certbuf = NULL, *keybuf = NULL, *cabuf = NULL;

    if (is_dial) {
        rv = nng_dialer_get_ptr(dialer, NNG_OPT_TLS_CONFIG, (void **)&tls);
    } else {
        rv = nng_listener_get_ptr(listener, NNG_OPT_TLS_CONFIG, (void **)&tls);
    }
    if (rv != 0 || tls == NULL) {
        return 0; // No TLS config; not an error unless TLS is required
    }

    // Read cert and key if supplied
    if (certfile != NULL) {
        certbuf = libnngio_read_file(certfile);
        if (!certbuf) return NNG_EINVAL;
        ctx->tls_cert_mem = certbuf;
        // Use keyfile if supplied, else certfile (for combined file)
        if (keyfile && strcmp(certfile, keyfile) != 0) {
            keybuf = libnngio_read_file(keyfile);
            if (!keybuf) return NNG_EINVAL;
            ctx->tls_key_mem = keybuf;
        } else {
            keybuf = certbuf;
        }
        rv = nng_tls_config_own_cert(tls, certbuf, keybuf, NULL);
        if (rv != 0) return rv;
    }
    if (cacert != NULL) {
        cabuf = libnngio_read_file(cacert);
        if (!cabuf) return NNG_EINVAL;
        ctx->tls_ca_mem = cabuf;
        rv = nng_tls_config_ca_chain(tls, cabuf, NULL);
        if (rv != 0) return rv;
    }
    return 0;
}

static int libnngio_apply_options(nng_socket sock, const libnngio_option *opts, size_t nopts) {
    int rv = 0;
    for (size_t i = 0; i < nopts; ++i) {
        rv = nng_socket_set(sock, opts[i].key, (void *)opts[i].value, strlen(opts[i].value));
        if (rv != 0) return rv;
    }
    return 0;
}

int libnngio_init(libnngio_ctx **ctxp, const libnngio_config *config) {
    if (!ctxp || !config) return NNG_EINVAL;
    int rv;
    libnngio_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NNG_ENOMEM;

    ctx->is_dial = (config->mode == LIBNNGIO_MODE_DIAL);

    rv = libnngio_proto_open(&ctx->sock, config->proto);
    if (rv != 0) { free(ctx); return rv; }

    if (ctx->is_dial) {
        rv = nng_dialer_create(&ctx->dialer, ctx->sock, config->url);
        if (rv != 0) { nng_close(ctx->sock); free(ctx); return rv; }
    } else {
        rv = nng_listener_create(&ctx->listener, ctx->sock, config->url);
        if (rv != 0) { nng_close(ctx->sock); free(ctx); return rv; }
    }

    rv = libnngio_configure_tls(
        ctx,
        ctx->dialer, ctx->listener, ctx->is_dial,
        config->tls_cert,
        config->tls_key,
        config->tls_ca_cert
    );
    if (rv != 0) {
        if (ctx->is_dial)
            nng_dialer_close(ctx->dialer);
        else
            nng_listener_close(ctx->listener);
        nng_close(ctx->sock); free(ctx); return rv;
    }

    if (config->options && config->option_count > 0) {
        rv = libnngio_apply_options(ctx->sock, config->options, config->option_count);
        if (rv != 0) {
            if (ctx->is_dial)
                nng_dialer_close(ctx->dialer);
            else
                nng_listener_close(ctx->listener);
            nng_close(ctx->sock); free(ctx); return rv;
        }
    }

    if (config->recv_timeout_ms > 0)
        nng_socket_set_ms(ctx->sock, NNG_OPT_RECVTIMEO, config->recv_timeout_ms);
    if (config->send_timeout_ms > 0)
        nng_socket_set_ms(ctx->sock, NNG_OPT_SENDTIMEO, config->send_timeout_ms);
    if (config->max_msg_size > 0)
        nng_socket_set_size(ctx->sock, NNG_OPT_RECVMAXSZ, config->max_msg_size);

    if (ctx->is_dial)
        rv = nng_dialer_start(ctx->dialer, 0);
    else
        rv = nng_listener_start(ctx->listener, 0);

    if (rv != 0) {
        if (ctx->is_dial)
            nng_dialer_close(ctx->dialer);
        else
            nng_listener_close(ctx->listener);
        nng_close(ctx->sock); free(ctx); return rv;
    }

    ctx->is_open = 1;
    *ctxp = ctx;

    return 0;
}

int libnngio_send(libnngio_ctx *ctx, const void *buf, size_t len) {
    if (!ctx || !ctx->is_open || !buf || len == 0) return NNG_EINVAL;
    return nng_send(ctx->sock, (void *)buf, len, 0);
}

int libnngio_recv(libnngio_ctx *ctx, void *buf, size_t *len) {
    if (!ctx || !ctx->is_open || !buf || !len || *len == 0) return NNG_EINVAL;
    size_t maxlen = *len;
    int rv = nng_recv(ctx->sock, buf, &maxlen, 0);
    if (rv == 0)
        *len = maxlen;
    return rv;
}

// Free all resources associated with context
void libnngio_free(libnngio_ctx *ctx) {
    if (!ctx) return;
    if (ctx->is_open) {
        if (ctx->is_dial)
            nng_dialer_close(ctx->dialer);
        else
            nng_listener_close(ctx->listener);
        nng_close(ctx->sock);
    }
    // Free TLS PEM buffers if allocated
    if (ctx->tls_cert_mem) free(ctx->tls_cert_mem);
    if (ctx->tls_key_mem && ctx->tls_key_mem != ctx->tls_cert_mem) free(ctx->tls_key_mem);
    if (ctx->tls_ca_mem) free(ctx->tls_ca_mem);

    free(ctx);
}

// User-invoked cleanup for global NNG state
void libnngio_cleanup(void) {
    nng_fini();
}
