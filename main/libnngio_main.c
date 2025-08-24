/**
 * @file libnngio_main.c
 * @brief Implementation file for the libnngio transport and context API.
 *      This file contains the core logic for initializing, managing, and freeing
 *      NNG transports and contexts, including protocol selection, TLS handling,
 *      synchronous/asynchronous I/O, and logging.
 */

#include "main/libnngio_main.h"

#include <nng/nng.h>
#include <nng/protocol/bus0/bus.h>
#include <nng/protocol/pair1/pair.h>
#include <nng/protocol/pipeline0/pull.h>
#include <nng/protocol/pipeline0/push.h>
#include <nng/protocol/pubsub0/pub.h>
#include <nng/protocol/pubsub0/sub.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/protocol/survey0/respond.h>
#include <nng/protocol/survey0/survey.h>
#include <nng/supplemental/tls/tls.h>
#include <nng/supplemental/util/platform.h>  // for nng_msleep if needed for timer
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Global ID counter for transports and contexts
static int free_transport_id = 0;  
static int free_context_id = 0;  

/**
 * @struct libnngio_transport
 * @brief Opaque structure holding the state of a transport (socket, dialer/listener, TLS).
 */
struct libnngio_transport {
  nng_socket sock;          /**< NNG socket handle */
  nng_dialer dialer;        /**< Dialer handle (if in dial mode) */
  nng_listener listener;    /**< Listener handle (if in listen mode) */
  int is_open;              /**< 1 if transport is open, 0 if closed */
  int is_dial;              /**< 1 if dialer, 0 if listener */
  int id;                   /**< Unique ID for this transport */
  char *tls_cert_mem;       /**< In-memory TLS certificate (if loaded) */
  char *tls_key_mem;        /**< In-memory TLS private key (if loaded) */
  char *tls_ca_mem;         /**< In-memory TLS CA certificate (if loaded) */
};

/**
 * @struct libnngio_context
 * @brief Opaque structure holding the state of a context (NNG context, config, callback).
 */
struct libnngio_context {
  int id;                          /**< Unique ID for this context */
  libnngio_transport *transport;   /**< Associated transport */
  libnngio_config config;          /**< Configuration used to create context */
  libnngio_ctx_cb cb;              /**< User-defined callback function */
  nng_ctx nng_ctx;                 /**< NNG context handle */
  void *user_data;                 /**< Opaque user data pointer for callback */
};

/**
 * @struct libnngio_recv_async_cbdata
 * @brief Internal structure to hold data for asynchronous receive callback info.
 */
typedef struct {
  libnngio_async_cb user_cb; /**< User-defined callback function */
  libnngio_context *ctx;     /**< Associated context */
  void *user_buf;            /**< User buffer to receive data into */
  size_t *user_len;          /**< Pointer to user length variable */
  void *user_data;           /**< Opaque user data pointer for callback */
  nng_aio *aio;              /**< NNG AIO handle */
} libnngio_recv_async_cbdata;

/**
 * @struct libnngio_send_async_cbdata
 * @brief Internal structure to hold data for asynchronous send callback info.
 */
typedef struct {
  libnngio_async_cb user_cb; /**< User-defined callback function */
  libnngio_context *ctx;     /**< Associated context */
  void *user_data;           /**< Opaque user data pointer for callback */
  nng_aio *aio;              /**< NNG AIO handle */
} libnngio_send_async_cbdata;

/**
 * @brief Read the entire contents of a file into a newly allocated buffer.
 * @param filename Path to the file to read.
 * @return Pointer to allocated buffer containing file contents, or NULL on error.
 *         The caller is responsible for freeing the returned buffer.
 */
static char *libnngio_read_file(const char *filename) {
  FILE *f = fopen(filename, "rb");
  char *buf = NULL;
  long sz;
  if (!f) return NULL;
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return NULL;
  }
  sz = ftell(f);
  if (sz < 0) {
    fclose(f);
    return NULL;
  }
  rewind(f);
  buf = (char *)malloc(sz + 1);
  if (!buf) {
    fclose(f);
    return NULL;
  }
  if (fread(buf, 1, sz, f) != (size_t)sz) {
    free(buf);
    fclose(f);
    return NULL;
  }
  buf[sz] = 0;
  fclose(f);
  return buf;
}

/**
 * @brief Open an NNG socket with the specified protocol.
 * @param sock Pointer to nng_socket to initialize.
 * @param proto Protocol enum specifying which protocol to use.
 * @return 0 on success, nonzero error code on failure.
 */
static int libnngio_proto_open(nng_socket *sock, libnngio_proto proto) {
  switch (proto) {
    case LIBNNGIO_PROTO_PAIR:
      return nng_pair_open(sock);
    case LIBNNGIO_PROTO_REQ:
      return nng_req_open(sock);
    case LIBNNGIO_PROTO_REP:
      return nng_rep_open(sock);
    case LIBNNGIO_PROTO_PUB:
      return nng_pub_open(sock);
    case LIBNNGIO_PROTO_SUB:
      return nng_sub_open(sock);
    case LIBNNGIO_PROTO_PUSH:
      return nng_push_open(sock);
    case LIBNNGIO_PROTO_PULL:
      return nng_pull_open(sock);
    case LIBNNGIO_PROTO_SURVEYOR:
      return nng_surveyor_open(sock);
    case LIBNNGIO_PROTO_RESPONDENT:
      return nng_respondent_open(sock);
    case LIBNNGIO_PROTO_BUS:
      return nng_bus_open(sock);
    default:
      return NNG_ENOTSUP;
  }
}

/**
 * @brief Get the string name of a protocol enum.
 * @param proto Protocol enum.
 * @return String name of the protocol, or NULL if unknown.
 */
static char *libnngio_proto_name(libnngio_proto proto) {
  switch (proto) {
    case LIBNNGIO_PROTO_PAIR:
      return "pair";
    case LIBNNGIO_PROTO_REQ:
      return "req";
    case LIBNNGIO_PROTO_REP:
      return "rep";
    case LIBNNGIO_PROTO_PUB:
      return "pub";
    case LIBNNGIO_PROTO_SUB:
      return "sub";
    case LIBNNGIO_PROTO_PUSH:
      return "push";
    case LIBNNGIO_PROTO_PULL:
      return "pull";
    case LIBNNGIO_PROTO_SURVEYOR:
      return "survey";
    case LIBNNGIO_PROTO_RESPONDENT:
      return "respondent";
    case LIBNNGIO_PROTO_BUS:
      return "bus";
    default:
      return NULL;
  }
}

/**
 * @brief Get the string name of a mode enum.
 * @param mode Mode enum.
 * @return String name of the mode, or NULL if unknown.
 */
static char *libnngio_mode_name(libnngio_mode mode) {
  switch (mode) {
    case LIBNNGIO_MODE_DIAL:
      return "dial";
    case LIBNNGIO_MODE_LISTEN:
      return "listen";
    default:
      return NULL;
  }
}

/**
 * @brief Configure TLS for a dialer or listener based on provided file paths.
 * @param t Transport structure to hold in-memory cert/key data.
 * @param dialer Dialer handle (if is_dial is 1).
 * @param listener Listener handle (if is_dial is 0).
 * @param is_dial 1 if configuring a dialer, 0 if listener.
 * @param certfile Path to TLS certificate file (or NULL).
 * @param keyfile Path to TLS private key file (or NULL).
 * @param cacert Path to TLS CA certificate file (or NULL).
 * @return 0 on success, nonzero error code on failure.
 */
static int libnngio_configure_tls(libnngio_transport *t, nng_dialer dialer,
                                  nng_listener listener, int is_dial,
                                  const char *certfile, const char *keyfile,
                                  const char *cacert) {
  nng_tls_config *tls = NULL;
  int rv = 0;
  char *certbuf = NULL, *keybuf = NULL, *cabuf = NULL;

  if (is_dial) {
    rv = nng_dialer_get_ptr(dialer, NNG_OPT_TLS_CONFIG, (void **)&tls);
  } else {
    rv = nng_listener_get_ptr(listener, NNG_OPT_TLS_CONFIG, (void **)&tls);
  }

  // Read cert and key if supplied
  if (certfile != NULL) {
    certbuf = libnngio_read_file(certfile);
    if (!certbuf) return NNG_EINVAL;
    t->tls_cert_mem = certbuf;
    // Use keyfile if supplied, else certfile (for combined file)
    if (keyfile && strcmp(certfile, keyfile) != 0) {
      keybuf = libnngio_read_file(keyfile);
      if (!keybuf) return NNG_EINVAL;
      t->tls_key_mem = keybuf;
    } else {
      keybuf = certbuf;
    }
    rv = nng_tls_config_own_cert(tls, certbuf, keybuf, NULL);
    if (rv != 0) return rv;
  }
  if (cacert != NULL) {
    cabuf = libnngio_read_file(cacert);
    if (!cabuf) return NNG_EINVAL;
    t->tls_ca_mem = cabuf;
    rv = nng_tls_config_ca_chain(tls, cabuf, NULL);
    if (rv != 0) return rv;
  }
  return 0;
}

/**
 * @brief Apply an array of arbitrary nng socket options to a socket.
 * @param sock NNG socket handle.
 * @param opts Array of libnngio_option structures.
 * @param nopts Number of options in the array.
 * @return 0 on success, nonzero error code on failure.
 */
static int libnngio_apply_options(nng_socket sock, const libnngio_option *opts,
                                  size_t nopts) {
  int rv = 0;
  for (size_t i = 0; i < nopts; ++i) {
    rv = nng_socket_set(sock, opts[i].key, (void *)opts[i].value,
                        strlen(opts[i].value));
    if (rv != 0) return rv;
  }
  return 0;
}

/**
 * @brief Initialize logging for libnngio.
 * @param level Logging level as a string ("DBG", "INF", "NTC", "WRN", "ERR").
 */
void libnngio_log_init(const char *level) {
  // Initialize logging system with the specified level
  if (level == NULL || strlen(level) == 0) {
    nng_log_set_level(NNG_LOG_ERR);  // Default to ERR if no level specified
  } else if (strcmp(level, "DBG") == 0) {
    nng_log_set_level(NNG_LOG_DEBUG);
  } else if (strcmp(level, "INF") == 0) {
    nng_log_set_level(NNG_LOG_INFO);
  } else if (strcmp(level, "NTC") == 0) {
    nng_log_set_level(NNG_LOG_NOTICE);
  } else if (strcmp(level, "WRN") == 0) {
    nng_log_set_level(NNG_LOG_WARN);
  } else if (strcmp(level, "ERR") == 0) {
    nng_log_set_level(NNG_LOG_ERR);
  } else {
    fprintf(stderr, "Unknown log level '%s', defaulting to ERR.\n", level);
    nng_log_set_level(NNG_LOG_ERR);  // Default to ERR
  }
  nng_log_set_logger(nng_stderr_logger);
}

/**
 * @brief Log a message using libnngio's logging subsystem. (wraps nng_log)
 * @param level Logging level ("DBG", "INF", "NTC", "WRN", "ERR").
 * @param routine Routine or function name generating the log.
 * @param file Source file name.
 * @param line Source line number.
 * @param id Context or transport id (or -1 if not applicable).
 * @param msg printf-style format string.
 * @param ... Arguments for format string.
 */
void libnngio_log(const char *level, const char *routine, const char *file,
                  const int line, const int id, const char *msg, ...) {
  // Allocate header and body strings
  char *header = (char *)malloc(1024);
  char *body = (char *)malloc(1024);

  if (!header || !body) {
    // Allocation failed, clean up and return
    free(header);
    free(body);
    return;
  }

  // Create header string
  if (id < 0) {
    snprintf(header, 1024, "%s >>> [%s:%d]", routine, file, line);
  } else {
    snprintf(header, 1024, "%s >>> (ID: %d) [%s:%d]", routine, id, file, line);
  }

  // Create body string using variadic arguments
  va_list args;
  va_start(args, msg);
  vsnprintf(body, 1024, msg, args);
  va_end(args);

  switch (level[0]) {
    case 'D':
      nng_log_debug(header, body);  // Debug level
      break;
    case 'I':
      nng_log_info(header, body);  // Info level
      break;
    case 'N':
      nng_log_notice(header, body);  // Notice level
      break;
    case 'W':
      nng_log_warn(header, body);  // Warning level
      break;
    case 'E':
      nng_log_err(header, body);  // Error level
      break;
    default:
      nng_log_info(header, body);  // Default to info
      // log an error if level is unknown
      fprintf(stderr, "Unknown log level '%s' in %s:%d\n", level, file, line);
      break;
  }

  free(header);
  free(body);
}

/**
 * @brief Validate a libnngio_config structure.
 * @param config Pointer to configuration structure to validate.
 * @return 0 if valid, nonzero error code if invalid.
 */
static int validate_config(const libnngio_config *config) {
  // Validate the configuration parameters, print an error message if invalid,
  // and return an appropriate error code. Also, make sure protocol and mode
  // are compatible
  if (!config) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "Configuration is NULL.");
    return NNG_EINVAL;
  }
  if (config->mode != LIBNNGIO_MODE_DIAL &&
      config->mode != LIBNNGIO_MODE_LISTEN) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "Invalid mode: %d. Must be DIAL or LISTEN.", config->mode);
    return NNG_EINVAL;
  }
  if (config->proto < LIBNNGIO_PROTO_PAIR ||
      config->proto > LIBNNGIO_PROTO_BUS) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "Invalid protocol: %d.", config->proto);
    return NNG_EINVAL;
  }
  if (!config->url || strlen(config->url) == 0) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "URL is NULL or empty.");
    return NNG_EINVAL;
  }
  if (config->tls_cert && (!config->tls_key || !config->tls_ca_cert)) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "TLS certificate provided without key or CA certificate.");
    return NNG_EINVAL;
  }
  if (config->tls_key && (!config->tls_cert || !config->tls_ca_cert)) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "TLS key provided without certificate or CA certificate.");
    return NNG_EINVAL;
  }
  if (config->recv_timeout_ms < 0 || config->send_timeout_ms < 0 ||
      config->max_msg_size < 0) {
    libnngio_log(
        "ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
        "Negative timeout or max message size: recv=%d, send=%d, max_msg=%d",
        config->recv_timeout_ms, config->send_timeout_ms, config->max_msg_size);
    return NNG_EINVAL;
  }
  if (config->proto == LIBNNGIO_PROTO_PAIR &&
      config->mode != LIBNNGIO_MODE_DIAL &&
      config->mode != LIBNNGIO_MODE_LISTEN) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "PAIR protocol can only be used in DIAL or LISTEN mode.");
    return NNG_EINVAL;
  }
  if (config->proto == LIBNNGIO_PROTO_REQ &&
      config->mode != LIBNNGIO_MODE_DIAL) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "REQ protocol can only be used in DIAL mode.");
    return NNG_EINVAL;
  }
  if (config->proto == LIBNNGIO_PROTO_REP &&
      config->mode != LIBNNGIO_MODE_LISTEN) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "REP protocol can only be used in LISTEN mode.");
    return NNG_EINVAL;
  }
  if (config->proto == LIBNNGIO_PROTO_PUB &&
      config->mode != LIBNNGIO_MODE_LISTEN) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "PUB protocol can only be used in LISTEN mode.");
    return NNG_EINVAL;
  }
  if (config->proto == LIBNNGIO_PROTO_SUB &&
      config->mode != LIBNNGIO_MODE_DIAL) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "SUB protocol can only be used in DIAL mode.");
    return NNG_EINVAL;
  }
  if (config->proto == LIBNNGIO_PROTO_PUSH &&
      config->mode != LIBNNGIO_MODE_LISTEN) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "PUSH protocol can only be used in LISTEN mode.");
    return NNG_EINVAL;
  }
  if (config->proto == LIBNNGIO_PROTO_PULL &&
      config->mode != LIBNNGIO_MODE_DIAL) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "PULL protocol can only be used in DIAL mode.");
    return NNG_EINVAL;
  }
  if (config->proto == LIBNNGIO_PROTO_SURVEYOR &&
      config->mode != LIBNNGIO_MODE_DIAL) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "SURVEYOR protocol can only be used in DIAL mode.");
    return NNG_EINVAL;
  }
  if (config->proto == LIBNNGIO_PROTO_RESPONDENT &&
      config->mode != LIBNNGIO_MODE_LISTEN) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "RESPONDENT protocol can only be used in LISTEN mode.");
    return NNG_EINVAL;
  }
  if (config->proto == LIBNNGIO_PROTO_BUS &&
      config->mode != LIBNNGIO_MODE_LISTEN &&
      config->mode != LIBNNGIO_MODE_DIAL) {
    libnngio_log("ERR", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, -1,
                 "BUS protocol can only be used in DIAL or LISTEN mode.");
    return NNG_EINVAL;
  }
  libnngio_log(
      "DBG", "LIBNNGIO_VALIDATE_CONFIG", __FILE__, __LINE__, free_transport_id,
      "Configuration validated successfully: mode=%s, proto=%s, url=%s",
      libnngio_mode_name(config->mode), libnngio_proto_name(config->proto),
      config->url);
  return 0;
}

/**
 * @brief Initialize a libnngio transport based on the provided configuration.
 * @param tp Pointer to transport pointer to initialize.
 * @param config Pointer to configuration structure.
 * @return 0 on success, nonzero error code on failure.
 */
int libnngio_transport_init(libnngio_transport **tp,
                            const libnngio_config *config) {
  libnngio_log("DBG", "NNGIO_TRANSPORT_INIT", __FILE__, __LINE__,
               free_transport_id, "Initializing transport.");
  int rv;
  libnngio_transport *t = calloc(1, sizeof(*t));
  if (!tp || !config) return NNG_EINVAL;
  if (!t) return NNG_ENOMEM;
  rv = validate_config(config);
  if (rv != 0) {
    free(t);
    return rv;
  }

  t->id = free_transport_id++;

  t->is_dial = (config->mode == LIBNNGIO_MODE_DIAL);

  libnngio_log("DBG", "NNGIO_TRANSPORT_INIT", __FILE__, __LINE__, t->id,
               "Creating %s transport.", libnngio_mode_name(config->mode));
  libnngio_log("DBG", "NNGIO_TRANSPORT_INIT", __FILE__, __LINE__, t->id,
               "Protocol: %s, URL: %s", libnngio_proto_name(config->proto),
               config->url);
  libnngio_log("DBG", "NNGIO_TRANSPORT_INIT", __FILE__, __LINE__, t->id,
               "Opening socket!");
  rv = libnngio_proto_open(&t->sock, config->proto);
  if (rv != 0) {
    free(t);
    return rv;
  }

  if (config->proto == LIBNNGIO_PROTO_SUB) {
    // Subscribe to all topics
    int rv = nng_socket_set(t->sock, NNG_OPT_SUB_SUBSCRIBE, "", 0);
    if (rv != 0) {
      // Handle error (optional: log or abort)
      libnngio_log("DBG", "NNGIO_TRANSPORT_INIT", __FILE__, __LINE__, t->id,
                   "Failed to set SUB subscribe filter: %s\n",
                   nng_strerror(rv));
      return rv;
    }
  }

  if (t->is_dial) {
    libnngio_log("DBG", "NNGIO_TRANSPORT_INIT", __FILE__, __LINE__, t->id,
                 "Creating dialer for URL %s.\n", config->url);
    rv = nng_dialer_create(&t->dialer, t->sock, config->url);
    if (rv != 0) {
      nng_close(t->sock);
      free(t);
      return rv;
    }
  } else {
    libnngio_log("DBG", "NNGIO_TRANSPORT_INIT", __FILE__, __LINE__, t->id,
                 "Creating listener for URL %s.\n", config->url);
    rv = nng_listener_create(&t->listener, t->sock, config->url);
    if (rv != 0) {
      nng_close(t->sock);
      free(t);
      return rv;
    }
  }
  rv = libnngio_configure_tls(t, t->dialer, t->listener, t->is_dial,
                              config->tls_cert, config->tls_key,
                              config->tls_ca_cert);
  if (rv != 0) {
    libnngio_log("ERR", "NNGIO_TRANSPORT_INIT", __FILE__, __LINE__, t->id,
                 "Failed to configure TLS with error %d\n", rv);
    if (t->is_dial)
      nng_dialer_close(t->dialer);
    else
      nng_listener_close(t->listener);
    nng_close(t->sock);
    free(t);
    return rv;
  }

  if (config->options && config->option_count > 0) {
    rv = libnngio_apply_options(t->sock, config->options, config->option_count);
    if (rv != 0) {
      libnngio_log("ERR", "NNGIO_TRANSPORT_INIT", __FILE__, __LINE__, t->id,
                   "Failed to apply options with error %d\n", rv);
      if (t->is_dial)
        nng_dialer_close(t->dialer);
      else
        nng_listener_close(t->listener);
      nng_close(t->sock);
      free(t);
      return rv;
    }
  }

  if (config->recv_timeout_ms > 0)
    nng_socket_set_ms(t->sock, NNG_OPT_RECVTIMEO, config->recv_timeout_ms);
  if (config->send_timeout_ms > 0)
    nng_socket_set_ms(t->sock, NNG_OPT_SENDTIMEO, config->send_timeout_ms);
  if (config->max_msg_size > 0)
    nng_socket_set_size(t->sock, NNG_OPT_RECVMAXSZ, config->max_msg_size);

  if (t->is_dial) {
    libnngio_log("INF", "NNGIO_TRANSPORT_INIT", __FILE__, __LINE__, t->id,
                 "Starting dialer for URL: %s.\n", config->url);
    rv = nng_dialer_start(t->dialer, 0);
  } else {
    libnngio_log("INF", "NNGIO_TRANSPORT_INIT", __FILE__, __LINE__, t->id,
                 "Starting listener for URL: %s.\n", config->url);
    rv = nng_listener_start(t->listener, 0);
  }

  if (config->tls_cert && config->tls_key && config->tls_ca_cert) {
    libnngio_log("INF", "NNGIO_TRANSPORT_INIT", __FILE__, __LINE__, t->id,
                 "--tls-- cert: %s, key: %s, ca: %s",
                 config->tls_cert ? config->tls_cert : "NULL",
                 config->tls_key ? config->tls_key : "NULL",
                 config->tls_ca_cert ? config->tls_ca_cert : "NULL");
  } else {
    libnngio_log(
        "WRN", "NNGIO_TRANSPORT_INIT", __FILE__, __LINE__, t->id,
        "--tls-- Not enough information provided for TLS configuration.");
    libnngio_log("WRN", "NNGIO_TRANSPORT_INIT", __FILE__, __LINE__, t->id,
                 "--tls-- cert: %s, key: %s, ca: %s",
                 config->tls_cert ? config->tls_cert : "NULL",
                 config->tls_key ? config->tls_key : "NULL",
                 config->tls_ca_cert ? config->tls_ca_cert : "NULL");
  }

  if (rv != 0) {
    libnngio_log("ERR", "NNGIO_TRANSPORT_INIT", __FILE__, __LINE__, t->id,
                 "Failed to start %s with error %d.\n",
                 libnngio_mode_name(config->mode), rv);
    if (t->is_dial)
      nng_dialer_close(t->dialer);
    else
      nng_listener_close(t->listener);
    nng_close(t->sock);
    free(t);
    return rv;
  }

  t->is_open = 1;
  *tp = t;

  libnngio_log("DBG", "NNGIO_TRANSPORT_INIT", __FILE__, __LINE__, t->id,
               "Transport initialized successfully: %s %s %s",
               libnngio_mode_name(config->mode),
               libnngio_proto_name(config->proto), config->url);
  return 0;
}

/**
 * @brief Send data over the transport synchronously.
 * @param t Pointer to transport structure.
 * @param buf Pointer to data buffer to send.
 * @param len Length of data buffer in bytes.
 * @return 0 on success, nonzero error code on failure.
 */
int libnngio_transport_send(libnngio_transport *t, const void *buf,
                            size_t len) {
  if (!t || !t->is_open || !buf || len == 0) return NNG_EINVAL;
  libnngio_log("INF", "NNGIO_TRANSPORT_SEND", __FILE__, __LINE__, t->id,
               "Sending %zu bytes.\n", len);
  return nng_send(t->sock, (void *)buf, len, 0);
}

/**
 * @brief Receive data from the transport synchronously.
 * @param t Pointer to transport structure.
 * @param buf Pointer to buffer to receive data into.
 * @param len Pointer to size_t variable holding the size of the buffer on
 *             input, and updated with the number of bytes received on output.
 * @return 0 on success, nonzero error code on failure.
 */
int libnngio_transport_recv(libnngio_transport *t, void *buf, size_t *len) {
  if (!t || !t->is_open || !buf || !len || *len == 0) return NNG_EINVAL;
  size_t maxlen = *len;
  libnngio_log("INF", "NNGIO_TRANSPORT_RECV", __FILE__, __LINE__, t->id,
               "Receiving up to %zu bytes.\n", maxlen);
  int rv = nng_recv(t->sock, buf, &maxlen, 0);
  if (rv == 0) *len = maxlen;
  return rv;
}

/**
 * @brief Free a libnngio transport, closing any open sockets and freeing resources.
 * @param t Pointer to transport structure to free.
 */
void libnngio_transport_free(libnngio_transport *t) {
  if (!t) return;
  libnngio_log("DBG", "LIBNNGIO_TRANSPORT_FREE", __FILE__, __LINE__, t->id,
               "Freeing transport.\n");
  if (t->is_open) {
    if (t->is_dial) {
      libnngio_log("DBG", "LIBNNGIO_TRANSPORT_FREE", __FILE__, __LINE__, t->id,
                   "Closing dialer for transport.\n");
      nng_dialer_close(t->dialer);
    } else {
      libnngio_log("DBG", "LIBNNGIO_TRANSPORT_FREE", __FILE__, __LINE__, t->id,
                   "Closing listener for transport.\n");
      nng_listener_close(t->listener);
    }
    libnngio_log("DBG", "LIBNNGIO_TRANSPORT_FREE", __FILE__, __LINE__, t->id,
                 "Closing socket for transport.\n");
    nng_close(t->sock);
  }

  libnngio_log("INF", "LIBNNGIO_TRANSPORT_FREE", __FILE__, __LINE__, t->id,
               "Transport freed successfully.\n");
  // Free TLS PEM buffers if allocated
  if (t->tls_cert_mem) free(t->tls_cert_mem);
  if (t->tls_key_mem && t->tls_key_mem != t->tls_cert_mem) free(t->tls_key_mem);
  if (t->tls_ca_mem) free(t->tls_ca_mem);

  free(t);
}

/**
 * @brief Initialize a libnngio context with the specified transport and configuration.
 * @param ctxp Pointer to context pointer to initialize.
 * @param t Pointer to transport structure to associate with the context.
 * @param config Pointer to configuration structure for the context.
 * @param cb User-defined callback function to invoke when the context starts and
 *           when messages are received.
 * @param user_data Opaque user data pointer to pass to the callback.
 * @return 0 on success, nonzero error code on failure.
 */
int libnngio_context_init(libnngio_context **ctxp, libnngio_transport *t,
                          const libnngio_config *config, libnngio_ctx_cb cb,
                          void *user_data) {
  if (!ctxp || !t || !config) return NNG_EINVAL;

  libnngio_log("DBG", "LIBNNGIO_CONTEXT_INIT", __FILE__, __LINE__,
               free_context_id, "Initializing context with transport ID %d.",
               t->id);
  libnngio_context *ctx = calloc(1, sizeof(*ctx));
  if (!ctx) return NNG_ENOMEM;

  ctx->transport = t;
  ctx->id = free_context_id++;

  // Store the configuration, callback, and user data for later use
  ctx->config = *config;
  ctx->cb = cb;
  ctx->user_data = user_data;

  *ctxp = ctx;

  // Create NNG context
  int rv = nng_ctx_open(&ctx->nng_ctx, t->sock);
  if (rv != 0) {
    libnngio_log("ERR", "LIBNNGIO_CONTEXT_INIT", __FILE__, __LINE__, ctx->id,
                 "Failed to open NNG context with error %d.\n", rv);
    free(ctx);
    return rv;
  }

  libnngio_log("INF", "LIBNNGIO_CONTEXT_INIT", __FILE__, __LINE__, ctx->id,
               "Context initialized successfully with transport ID %d.", t->id);

  return 0;
}

/**
 * @brief Start the libnngio context, invoking the user-defined callback.
 * @param ctx Pointer to context to start.
 */
void libnngio_context_start(libnngio_context *ctx) {
  if (!ctx || !ctx->transport || !ctx->transport->is_open) {
    libnngio_log("ERR", "LIBNNGIO_CONTEXT_START", __FILE__, __LINE__,
                 ctx ? ctx->id : -1,
                 "Invalid context or transport not open.\n");
    return;
  }

  libnngio_log("INF", "LIBNNGIO_CONTEXT_START", __FILE__, __LINE__, ctx->id,
               "Starting context with transport ID %d.", ctx->transport->id);

  // Start the context by invoking the callback
  if (ctx->cb) {
    libnngio_log("DBG", "LIBNNGIO_CONTEXT_START", __FILE__, __LINE__, ctx->id,
                 "Invoking user callback for context ID %d.", ctx->id);
    ctx->cb(ctx);  // Call the user-defined callback
  } else {
    libnngio_log("WRN", "LIBNNGIO_CONTEXT_START", __FILE__, __LINE__, ctx->id,
                 "No callback defined for context ID %d.", ctx->id);
  }
}

/** 
 *  @brief nngio internal callback to manage async recv callback data.
 *  @param arg Pointer to the libnngio recv callback data (void*) for parity
 *              with nng_aio cb signature.
 */
static void nngio_recv_aio_cb(void *arg) {
  libnngio_recv_async_cbdata *cbdata = (libnngio_recv_async_cbdata *)arg;

  int result = nng_aio_result(cbdata->aio);
  void *msg_data = NULL;
  size_t msg_len = 0;

  libnngio_log("DBG", "CTX_RECV_CB", __FILE__, __LINE__, -1,
               "nngio_recv_aio_cb called with result=%d", result);

  if (result == 0) {
    nng_msg *msg = nng_aio_get_msg(cbdata->aio);
    msg_data = nng_msg_body(msg);
    msg_len = nng_msg_len(msg);
    libnngio_log("DBG", "CTX_RECV_CB", __FILE__, __LINE__, -1,
                 "Received message of length %zu", msg_len);

    if (cbdata->user_buf && cbdata->user_len) {
      size_t copy_len =
          (*cbdata->user_len < msg_len) ? *cbdata->user_len : msg_len;
      memcpy(cbdata->user_buf, msg_data, copy_len);
      *cbdata->user_len = copy_len;
      libnngio_log("DBG", "CTX_RECV_CB", __FILE__, __LINE__, -1,
                   "Copied %zu bytes to user buffer", copy_len);
    }
    nng_msg_free(msg);
  } else {
    if (result == NNG_ECLOSED) {
      libnngio_log("WRN", "CTX_RECV_CB", __FILE__, __LINE__, -1,
                   "Receive operation closed, no message received.");
    } else {
      libnngio_log("ERR", "CTX_RECV_CB", __FILE__, __LINE__, -1,
                   "Receive operation failed with error: %s",
                   nng_strerror(result));
    }
  }

  // Call user callback
  cbdata->user_cb(cbdata->ctx, result, cbdata->user_buf,
                  cbdata->user_len ? *cbdata->user_len : 0, cbdata->user_data);

  nng_aio_reap(cbdata->aio);  // Clean up AIO
  free(cbdata);
}

/**
 * @brief Asynchronously receive data using the libnngio context.
 * @param ctx Pointer to libnngio context.
 * @param buf Pointer to buffer to receive data into.
 * @param len Pointer to size_t variable holding the size of the buffer on
 *            input, and updated with the number of bytes received on output.
 * @param cb User-defined callback function to invoke when the receive operation
 *           completes.
 * @param user_data Opaque user data pointer to pass to the callback.
 * @return 0 on success, nonzero error code on failure.
 */
int libnngio_context_recv_async(libnngio_context *ctx, void *buf, size_t *len,
                                libnngio_async_cb cb, void *user_data) {
  libnngio_log("DBG", "CTX_RECV_ASYNC", __FILE__, __LINE__, -1,
               "Entering libnngio_context_recv_async");

  if (!ctx || !cb || !buf || !len || *len == 0) {
    libnngio_log("ERR", "CTX_RECV_ASYNC", __FILE__, __LINE__, -1,
                 "Invalid arguments to libnngio_context_recv_async");
    return NNG_EINVAL;
  }

  libnngio_recv_async_cbdata *cbdata = calloc(1, sizeof(*cbdata));
  if (!cbdata) {
    libnngio_log("ERR", "CTX_RECV_ASYNC", __FILE__, __LINE__, -1,
                 "Failed to allocate cbdata");
    return NNG_ENOMEM;
  }

  cbdata->user_cb = cb;
  cbdata->ctx = ctx;
  cbdata->user_buf = buf;
  cbdata->user_len = len;
  cbdata->user_data = user_data;

  int rv = nng_aio_alloc(&cbdata->aio, nngio_recv_aio_cb, cbdata);
  if (rv != 0) {
    libnngio_log("ERR", "CTX_RECV_ASYNC", __FILE__, __LINE__, -1,
                 "Failed to allocate aio: %s", nng_strerror(rv));
    free(cbdata);
    return rv;
  }

  libnngio_log("DBG", "CTX_RECV_ASYNC", __FILE__, __LINE__, -1,
               "Posting nng_ctx_recv for context id %d",
               nng_ctx_id(ctx->nng_ctx));

  nng_ctx_recv(ctx->nng_ctx, cbdata->aio);
  return 0;
}

/**
 * @brief nngio internal callback to manage async send callback data.
 * @param arg Pointer to the libnngio send callback data (void*) for parity
 *              with nng_aio cb signature.
 */
static void nngio_send_aio_cb(void *arg) {
  libnngio_send_async_cbdata *cbdata = (libnngio_send_async_cbdata *)arg;

  int result = nng_aio_result(cbdata->aio);

  libnngio_log("DBG", "CTX_SEND_CB", __FILE__, __LINE__, -1,
               "nngio_send_aio_cb called with result=%d", result);

  if (result != 0) {
    libnngio_log("ERR", "CTX_SEND_CB", __FILE__, __LINE__, -1,
                 "Send failed: %s", nng_strerror(result));
  }

  cbdata->user_cb(cbdata->ctx, result, NULL, 0, cbdata->user_data);

  nng_aio_reap(cbdata->aio);  // Clean up AIO
  free(cbdata);
}

/**
 * @brief Asynchronously send data using the libnngio context.
 * @param ctx Pointer to libnngio context.
 * @param buf Pointer to data buffer to send.
 * @param len Length of data buffer in bytes.
 * @param cb User-defined callback function to invoke when the send operation
 *           completes.
 * @param user_data Opaque user data pointer to pass to the callback.
 * @return 0 on success, nonzero error code on failure.
 */
int libnngio_context_send_async(libnngio_context *ctx, const void *buf,
                                size_t len, libnngio_async_cb cb,
                                void *user_data) {
  libnngio_log("DBG", "CTX_SEND_ASYNC", __FILE__, __LINE__, -1,
               "Entering libnngio_context_send_async");

  if (!ctx || !cb || !buf || len == 0) {
    libnngio_log("ERR", "CTX_SEND_ASYNC", __FILE__, __LINE__, -1,
                 "Invalid arguments to libnngio_context_send_async");
    return NNG_EINVAL;
  }

  libnngio_send_async_cbdata *cbdata = calloc(1, sizeof(*cbdata));
  if (!cbdata) {
    libnngio_log("ERR", "CTX_SEND_ASYNC", __FILE__, __LINE__, -1,
                 "Failed to allocate cbdata");
    return NNG_ENOMEM;
  }

  cbdata->user_cb = cb;
  cbdata->ctx = ctx;
  cbdata->user_data = user_data;

  int rv = nng_aio_alloc(&cbdata->aio, nngio_send_aio_cb, cbdata);
  if (rv != 0) {
    libnngio_log("ERR", "CTX_SEND_ASYNC", __FILE__, __LINE__, -1,
                 "Failed to allocate aio: %s", nng_strerror(rv));
    free(cbdata);
    return rv;
  }

  nng_msg *msg;
  rv = nng_msg_alloc(&msg, len);
  if (rv != 0) {
    libnngio_log("ERR", "CTX_SEND_ASYNC", __FILE__, __LINE__, -1,
                 "Failed to allocate nng_msg: %s", nng_strerror(rv));
    nng_aio_free(cbdata->aio);
    free(cbdata);
    return rv;
  }
  memcpy(nng_msg_body(msg), buf, len);

  nng_aio_set_msg(cbdata->aio, msg);

  libnngio_log("DBG", "CTX_SEND_ASYNC", __FILE__, __LINE__, -1,
               "Posting nng_ctx_send for context id %d",
               nng_ctx_id(ctx->nng_ctx));

  nng_ctx_send(ctx->nng_ctx, cbdata->aio);
  return 0;
}

/**
 * @brief Set user data pointer for the libnngio context.
 * @param ctx Pointer to libnngio context.
 * @param user_data Opaque user data pointer to associate with the context.
 */
void libnngio_context_set_user_data(libnngio_context *ctx, void *user_data) {
  if (!ctx) return;
  libnngio_log("DBG", "LIBNNGIO_CONTEXT_SET_USER_DATA", __FILE__, __LINE__,
               ctx->id, "Setting user data for context ID %d.", ctx->id);
  ctx->user_data = user_data;
}

/**
 * @brief Get user data pointer associated with the libnngio context.
 * @param ctx Pointer to libnngio context.
 * @return Opaque user data pointer associated with the context, or NULL if none.
 */
void *libnngio_context_get_user_data(libnngio_context *ctx) {
  if (!ctx) return NULL;
  libnngio_log("DBG", "LIBNNGIO_CONTEXT_GET_USER_DATA", __FILE__, __LINE__,
               ctx->id, "Retrieving user data for context ID %d.", ctx->id);
  return ctx->user_data;
}

/**
 * @brief Free a libnngio context, closing the associated NNG context and
 *        freeing resources. The associated transport is not freed here, as it
 *        may be shared by multiple contexts. Caller should take care of
 *        freeing the transport if needed.
 * @param ctx Pointer to libnngio context to free.
 */
void libnngio_context_free(libnngio_context *ctx) {
  if (!ctx) return;
  libnngio_log("DBG", "LIBNNGIO_CONTEXT_FREE", __FILE__, __LINE__, ctx->id,
               "Freeing context with transport ID %d.", ctx->transport->id);
  // transport is not freed here, as it may be shared by multiple contexts
  // Caller should take care of freeing the transport if needed
  nng_ctx_close(ctx->nng_ctx);  // Close NNG context
  int id = ctx->id;             // hold ID on stack before freeing
  free(ctx);
  libnngio_log("INF", "LIBNNGIO_CONTEXT_FREE", __FILE__, __LINE__, id,
               "Context freed successfully.\n");
}

/**
 * @brief Initialize multiple libnngio contexts with the specified transport
 *        and configuration.
 * @param ctxs Pointer to array of context pointers to initialize.
 * @param n Number of contexts to initialize.
 * @param t Pointer to transport structure to associate with the contexts.
 * @param config Pointer to configuration structure for the contexts.
 * @param cb User-defined callback function to invoke when each context starts
 *           and when messages are received.
 * @param user_datas Array of opaque user data pointers to pass to each context's
 *                   callback. Can be NULL if no user data is needed.
 * @return 0 on success, nonzero error code on failure.
 */
int libnngio_contexts_init(libnngio_context ***ctxs, size_t n,
                           libnngio_transport *t, const libnngio_config *config,
                           libnngio_ctx_cb cb, void **user_datas) {
  if (!ctxs || n == 0) return -1;
  *ctxs = calloc(n, sizeof(libnngio_context *));
  if (!*ctxs) return -2;

  for (size_t i = 0; i < n; ++i) {
    int rv = libnngio_context_init(&(*ctxs)[i], t, config, cb,
                                   user_datas ? user_datas[i] : NULL);
    if (rv != 0) {
      // Roll back and free any already-initialized contexts
      for (size_t j = 0; j < i; ++j) libnngio_context_free((*ctxs)[j]);
      free(*ctxs);
      *ctxs = NULL;
      return rv;
    }
  }
  return 0;
}

/**
 * @brief Free multiple libnngio contexts.
 * @param ctxs Pointer to array of context pointers to free.
 * @param n Number of contexts in the array.
 */
void libnngio_contexts_free(libnngio_context **ctxs, size_t n) {
  if (!ctxs) return;
  for (size_t i = 0; i < n; ++i) {
    if (ctxs[i]) libnngio_context_free(ctxs[i]);
  }
  free(ctxs);
}

/**
 * @brief Start multiple libnngio contexts, invoking their user-defined callbacks.
 * @param ctxs Pointer to array of context pointers to start.
 * @param n Number of contexts in the array.
 */
void libnngio_contexts_start(libnngio_context **ctxs, size_t n) {
  if (!ctxs) return;
  for (size_t i = 0; i < n; ++i) {
    if (ctxs[i]) libnngio_context_start(ctxs[i]);
  }
}

/**
 * @brief Initialize global libnngio state. Must be called before any other
 *        libnngio functions.
 */
void libnngio_cleanup(void) {
  libnngio_log("INF", "LIBNNGIO_CLEANUP", __FILE__, __LINE__, -1,
               "Cleaning up global NNG state.\n");
  nng_fini();
}
