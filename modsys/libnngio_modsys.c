/**
 * @file libnngio_modsys.c
 * @brief Implementation of the libnngio module system API.
 */

#include "modsys/libnngio_modsys.h"
#include <stdlib.h>
#include <string.h>

/**
 * @brief Internal structure for module system context.
 */
struct libnngio_modsys_context {
  libnngio_modsys_module_entry *modules;  ///< Array of registered modules
  size_t n_modules;                       ///< Number of registered modules
  size_t modules_capacity;                ///< Capacity of modules array
};

// =============================================================================
// Helper Functions
// =============================================================================

static char *strdup_safe(const char *s) {
  if (!s) return NULL;
  return strdup(s);
}

// =============================================================================
// Core Module System Functions
// =============================================================================

libnngio_modsys_error_code libnngio_modsys_init(
    libnngio_modsys_context **ctx) {
  if (!ctx) {
    return LIBNNGIO_MODSYS_ERR_INVALID_PARAM;
  }

  libnngio_modsys_context *modsys_ctx = calloc(1, sizeof(libnngio_modsys_context));
  if (!modsys_ctx) {
    return LIBNNGIO_MODSYS_ERR_MEMORY;
  }

  // Initialize with capacity for 10 modules
  modsys_ctx->modules_capacity = 10;
  modsys_ctx->modules = calloc(modsys_ctx->modules_capacity, sizeof(libnngio_modsys_module_entry));
  
  if (!modsys_ctx->modules) {
    free(modsys_ctx);
    return LIBNNGIO_MODSYS_ERR_MEMORY;
  }

  modsys_ctx->n_modules = 0;
  *ctx = modsys_ctx;
  return LIBNNGIO_MODSYS_ERR_NONE;
}

void libnngio_modsys_free(libnngio_modsys_context *ctx) {
  if (!ctx) return;

  // Free module entries
  for (size_t i = 0; i < ctx->n_modules; i++) {
    free(ctx->modules[i].transport_name);
  }
  free(ctx->modules);
  free(ctx);
}

libnngio_modsys_error_code libnngio_modsys_register_module(
    libnngio_modsys_context *ctx,
    const libnngio_module_descriptor *module,
    libnngio_server *server,
    const char *transport_name) {
  if (!ctx || !module || !server) {
    return LIBNNGIO_MODSYS_ERR_INVALID_PARAM;
  }

  // Check if module already exists
  for (size_t i = 0; i < ctx->n_modules; i++) {
    if (ctx->modules[i].descriptor && 
        strcmp(ctx->modules[i].descriptor->module_name, module->module_name) == 0) {
      return LIBNNGIO_MODSYS_ERR_ALREADY_EXISTS;
    }
  }

  // Expand array if needed
  if (ctx->n_modules >= ctx->modules_capacity) {
    size_t new_capacity = ctx->modules_capacity * 2;
    libnngio_modsys_module_entry *new_modules = 
        realloc(ctx->modules, new_capacity * sizeof(libnngio_modsys_module_entry));
    if (!new_modules) {
      return LIBNNGIO_MODSYS_ERR_MEMORY;
    }
    ctx->modules = new_modules;
    ctx->modules_capacity = new_capacity;
  }

  // Register the module's services with the server
  libnngio_protobuf_error_code proto_rv = 
      libnngio_module_register_services(server, module);
  if (proto_rv != LIBNNGIO_PROTOBUF_ERR_NONE) {
    return LIBNNGIO_MODSYS_ERR_INTERNAL;
  }

  // Add module entry
  libnngio_modsys_module_entry *entry = &ctx->modules[ctx->n_modules];
  entry->descriptor = module;
  entry->server = server;
  entry->transport_name = strdup_safe(transport_name);
  
  if (!entry->transport_name) {
    return LIBNNGIO_MODSYS_ERR_MEMORY;
  }

  ctx->n_modules++;
  return LIBNNGIO_MODSYS_ERR_NONE;
}

libnngio_modsys_error_code libnngio_modsys_unregister_module(
    libnngio_modsys_context *ctx,
    const char *module_name) {
  if (!ctx || !module_name) {
    return LIBNNGIO_MODSYS_ERR_INVALID_PARAM;
  }

  // Find the module
  size_t module_idx = (size_t)-1;
  for (size_t i = 0; i < ctx->n_modules; i++) {
    if (ctx->modules[i].descriptor &&
        strcmp(ctx->modules[i].descriptor->module_name, module_name) == 0) {
      module_idx = i;
      break;
    }
  }

  if (module_idx == (size_t)-1) {
    return LIBNNGIO_MODSYS_ERR_NOT_FOUND;
  }

  // Note: We don't actually unregister services from the server here
  // because the protobuf API doesn't provide a way to unregister services.
  // In a real implementation, you would need to add that functionality.
  
  // Free the transport name
  free(ctx->modules[module_idx].transport_name);

  // Shift remaining modules down
  for (size_t i = module_idx; i < ctx->n_modules - 1; i++) {
    ctx->modules[i] = ctx->modules[i + 1];
  }

  ctx->n_modules--;
  return LIBNNGIO_MODSYS_ERR_NONE;
}

size_t libnngio_modsys_get_module_count(libnngio_modsys_context *ctx) {
  if (!ctx) return 0;
  return ctx->n_modules;
}

const libnngio_modsys_module_entry *libnngio_modsys_get_module(
    libnngio_modsys_context *ctx,
    size_t index) {
  if (!ctx || index >= ctx->n_modules) {
    return NULL;
  }
  return &ctx->modules[index];
}

const libnngio_modsys_module_entry *libnngio_modsys_find_module(
    libnngio_modsys_context *ctx,
    const char *module_name) {
  if (!ctx || !module_name) {
    return NULL;
  }

  for (size_t i = 0; i < ctx->n_modules; i++) {
    if (ctx->modules[i].descriptor &&
        strcmp(ctx->modules[i].descriptor->module_name, module_name) == 0) {
      return &ctx->modules[i];
    }
  }

  return NULL;
}
