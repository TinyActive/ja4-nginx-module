#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event_openssl.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include "ngx_http_ja4_module.h"
#include <ngx_http_v2.h>

#if (NGX_GCC)
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-function"
#endif

#ifndef TCP_SAVE_SYN
#define TCP_SAVE_SYN 27
#endif
#ifndef TCP_SAVED_SYN
#define TCP_SAVED_SYN 28
#endif


// Global index for storing our context in SSL object
int ngx_ja4_ssl_ex_index = -1;

// Forward declarations
static ngx_int_t ngx_http_ja4_add_variables(ngx_conf_t *cf);
static void *ngx_http_ja4_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_ja4_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_ja4_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_ja4_init_process(ngx_cycle_t *cycle);


static ngx_int_t ngx_http_ja4_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);


// Grease and Ignore lists (copied from original)
static const char *GREASE[] = {
    "0a0a", "1a1a", "2a2a", "3a3a", "4a4a", "5a5a", "6a6a", "7a7a",
    "8a8a", "9a9a", "aaaa", "baba", "caca", "dada", "eaea", "fafa",
};

/* Unused in simplified version - NOW USED */
static const char *EXT_IGNORE_DYNAMIC[] = {
    "0029", // PRE_SHARED_KEY
    "0015", // PADDING
};

static const char *EXT_IGNORE[] = {
    "0000", // SNI
    "0010", // ALPN
};

static int ngx_ja4_is_grease(uint16_t v) {
    if ((v & 0x0f0f) == 0x0a0a) return 1;
    return 0;
}


static int ngx_ja4_is_ignored(uint16_t v) {
    if (v == 0x0000 || v == 0x0010) return 1; // SNI, ALPN
    return 0;
}

static int ngx_ja4_is_dynamic(uint16_t v) {
    if (v == 0x0029 || v == 0x0015) return 1; // PSK, Padding
    return 0;
}

static int compare_uint16(const void *a, const void *b) {
    return (*(uint16_t*)a - *(uint16_t*)b);
}



// Client Hello Callback
// This replaces the patch logic
int ngx_ja4_client_hello_cb(SSL *s, int *al, void *arg) {
    ngx_connection_t *c;
    ngx_ja4_ssl_ctx_t *ctx;
    int *ext_out;
    size_t ext_len;
    
    c = SSL_get_ex_data(s, ngx_ssl_connection_index);
    if (c == NULL) {
        return 1;
    }

    // Allocate our context
    ctx = ngx_pcalloc(c->pool, sizeof(ngx_ja4_ssl_ctx_t));
    if (ctx == NULL) return 0; // Error

    ctx->pool = c->pool;
    ctx->ja4_data = ngx_pcalloc(c->pool, sizeof(ngx_ssl_ja4_t));
    if (ctx->ja4_data == NULL) return 0;

    SSL_set_ex_data(s, ngx_ja4_ssl_ex_index, ctx);

    // --- LOGIC PORTED FROM PATCH ---
    if (!SSL_client_hello_get1_extensions_present(s, &ext_out, &ext_len)) {
        return 1;
    }
    if (!ext_out || !ext_len) { 
         if(ext_out) OPENSSL_free(ext_out);
         return 1; 
    }

    // Store raw extensions in our struct
    
    ctx->ja4_data->extensions_sz = ext_len;
    ctx->ja4_data->extensions = ngx_pcalloc(c->pool, sizeof(uint16_t) * ext_len);
    
    // Also capture highest version
    int highest_ver = 0;

    for (size_t i = 0; i < ext_len; i++) {
        ctx->ja4_data->extensions[i] = (uint16_t)ext_out[i];

        // Supported Versions logic (0x002b)
        if (ext_out[i] == 0x002b) {
             const unsigned char *ver_data;
             size_t ver_len;
             if (SSL_client_hello_get0_ext(s, 0x002b, &ver_data, &ver_len) && ver_len >= 3) {
                 size_t list_len = ver_data[0];
                 const unsigned char *p = ver_data + 1;
                 for (size_t j = 0; j + 1 < list_len && (j+1 < ver_len); j += 2) {
                     int v = (p[j] << 8) | p[j+1];
                     if ((v & 0x0f0f) == 0x0a0a) continue; // Grease
                     if (v > highest_ver) highest_ver = v;
                 }
             }
        }
    }
    
    if (highest_ver == 0) {
        highest_ver = SSL_client_hello_get0_legacy_version(s);
    }
    
    ctx->ja4_data->highest_supported_tls_client_version = (char*)(uintptr_t)highest_ver; 
    ctx->ja4_data->calculated = 0;

    OPENSSL_free(ext_out);
    return 1;
}

#define NGX_HTTP_JA4_ALLOW 1
#define NGX_HTTP_JA4_DENY  2

// Forward declarations
static char *ngx_http_ja4_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_ja4_access_handler(ngx_http_request_t *r);
void ngx_ja4_calculate(ngx_connection_t *c, ngx_ssl_ja4_t *ja4);
void ngx_ja4h_calculate(ngx_http_request_t *r, ngx_ssl_ja4h_t *ja4h);
void ngx_ja4one_calculate(ngx_http_request_t *r, ngx_ssl_ja4one_t *ja4one);
void ngx_ja4tcp_calculate(ngx_connection_t *c, ngx_ssl_ja4tcp_t *ja4tcp);
void ngx_ja4s_calculate(ngx_http_request_t *r, ngx_ssl_ja4s_t *ja4s, ngx_pool_t *pool);


// --- Internal HTTP/2 Structure Definitions (Simulated) ---
// Since we don't have direct access to internal headers easily, we define necessary subsets.
// This matches standard NGINX 1.18+ structure beginning.
typedef struct {
    ngx_uint_t                      id;
    ngx_uint_t                      value;
} ngx_http_v2_setting_t;

typedef struct {
    ngx_connection_t               *connection;
    ngx_http_connection_t          *http_connection;
    ngx_uint_t                      processing;
    
    // In NGINX, settings are usually further down, but let's assume we can access them via offset or if we include the header?
    // Wait, reusing exact definition is risky if it changes.
    // However, for standard NGINX, accessing `init_window` is common.
    
    // We will attempt to rely on standard NGINX includes being available during build.
    // If this fails, we will need to revisit.
    // BUT since I am writing this into the file, I should define a "compatible" struct 
    // that mimics the layout just enough, or assume we can include the file.
} ngx_http_v2_connection_subset_t;
// NOTE: I will strictly rely on `ngx_http_v2_module.h` implicit availability or similar? No.
// I'll proceed with the assumption we can access `ngx_ssl_ja4s_t` logic.
// I'll add the logic now.




// Module Directives
static ngx_command_t ngx_http_ja4_commands[] = {
    { ngx_string("ja4"),
      NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ja4_srv_conf_t, enable),
      NULL },
      
    { ngx_string("ja4_deny"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_ja4_handler,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ja4_allow"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_ja4_handler,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ja4h_deny"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_ja4_handler,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ja4h_allow"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_ja4_handler,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },
      
    { ngx_string("ja4one_deny"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_ja4_handler,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ja4one_allow"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_ja4_handler,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ja4s_deny"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_ja4_handler,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ja4s_allow"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_ja4_handler,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

// Module Context
static ngx_http_module_t ngx_http_ja4_module_ctx = {
    ngx_http_ja4_add_variables,    /* preconfiguration */
    ngx_http_ja4_init,             /* postconfiguration */
    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */
    ngx_http_ja4_create_srv_conf,  /* create server configuration */
    ngx_http_ja4_merge_srv_conf,   /* merge server configuration */
    NULL,                          /* create location configuration */
    NULL                           /* merge location configuration */
};

ngx_module_t ngx_http_ja4_module = {
    NGX_MODULE_V1,
    &ngx_http_ja4_module_ctx,      /* module context */
    ngx_http_ja4_commands,         /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    ngx_http_ja4_init_process,     /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

// Config functions
static void *ngx_http_ja4_create_srv_conf(ngx_conf_t *cf) {
    ngx_http_ja4_srv_conf_t  *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ja4_srv_conf_t));
    if (conf == NULL) return NULL;
    conf->enable = NGX_CONF_UNSET;
    return conf;
}

static char *ngx_http_ja4_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_ja4_srv_conf_t *prev = parent;
    ngx_http_ja4_srv_conf_t *conf = child;
    
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    
    if (conf->rules == NULL) conf->rules = prev->rules;
    if (conf->rules_h == NULL) conf->rules_h = prev->rules_h;
    if (conf->rules_one == NULL) conf->rules_one = prev->rules_one;
    if (conf->rules_s == NULL) conf->rules_s = prev->rules_s;

    return NGX_CONF_OK;
}

static char *ngx_http_ja4_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_ja4_srv_conf_t *jcf = conf;
    ngx_str_t *value;
    ngx_http_ja4_rule_t *rule;
    ngx_array_t **rules_ptr;
    
    value = cf->args->elts;
    
    if (ngx_strstr(cmd->name.data, (u_char *)"ja4h_")) {
        rules_ptr = &jcf->rules_h;
    } else if (ngx_strstr(cmd->name.data, (u_char *)"ja4one_")) {
        rules_ptr = &jcf->rules_one;
    } else if (ngx_strstr(cmd->name.data, (u_char *)"ja4s_")) {
        rules_ptr = &jcf->rules_s;
    } else {
        rules_ptr = &jcf->rules;
    }
    
    if (*rules_ptr == NULL) {
        *rules_ptr = ngx_array_create(cf->pool, 4, sizeof(ngx_http_ja4_rule_t));
        if (*rules_ptr == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    
    rule = ngx_array_push(*rules_ptr);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }
    
    rule->name = value[1];
    
    if (ngx_strstr(cmd->name.data, (u_char *)"_allow")) {
        rule->type = NGX_HTTP_JA4_ALLOW;
    } else {
        rule->type = NGX_HTTP_JA4_DENY;
    }
    
    return NGX_CONF_OK;
}


static ngx_http_variable_t  ngx_http_ja4_vars[] = {
    { ngx_string("http_ssl_ja4"), NULL, ngx_http_ja4_variable, 0, 0, 0 },
    { ngx_string("http_ssl_ja4h"), NULL, ngx_http_ja4_variable, 1, 0, 0 },
    { ngx_string("http_ssl_ja4one"), NULL, ngx_http_ja4_variable, 2, 0, 0 },
    { ngx_string("http_ssl_ja4tcp"), NULL, ngx_http_ja4_variable, 3, 0, 0 },
    { ngx_string("http_ssl_ja4s"), NULL, ngx_http_ja4_variable, 4, 0, 0 },
    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_int_t ngx_http_ja4_add_variables(ngx_conf_t *cf) {
    ngx_http_variable_t *var, *v;
    for (v = ngx_http_ja4_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) return NGX_ERROR;
        var->get_handler = v->get_handler;
        var->data = v->data;
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_ja4_init(ngx_conf_t *cf) {
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_handler_pt *h;
    ngx_http_core_srv_conf_t **cscfp;
    ngx_uint_t s;

    // 1. Get global ex index
    ngx_ja4_ssl_ex_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if (ngx_ja4_ssl_ex_index == -1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ja4: Failed to get SSL ex index");
        return NGX_ERROR;
    }

    // 2. Add Access Phase Handler
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_ja4_access_handler;

    // 3. Iterate servers and add ClientHello Callback
    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
         ngx_http_ssl_srv_conf_t *sscf = cscfp[s]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];
         
         if (sscf && sscf->ssl.ctx) {
             SSL_CTX_set_client_hello_cb(sscf->ssl.ctx, ngx_ja4_client_hello_cb, NULL);
         }
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_ja4_init_process(ngx_cycle_t *cycle) {
    ngx_uint_t i;
    ngx_listening_t *ls;
    int optval = 1;

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        // Only enable for TCP sockets
        if (ls[i].type == SOCK_STREAM) {
            if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_SAVE_SYN, &optval, sizeof(optval)) == -1) {
                ngx_log_error(NGX_LOG_WARN, cycle->log, ngx_errno, 
                              "ja4: setsockopt(TCP_SAVE_SYN) failed for %V", &ls[i].addr_text);
            } else {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cycle->log, 0, 
                               "ja4: TCP_SAVE_SYN enabled for %V", &ls[i].addr_text);
            }
        }
    }
    return NGX_OK;
}


static ngx_int_t ngx_http_ja4_access_handler(ngx_http_request_t *r) {
    ngx_http_ja4_srv_conf_t *jcf;
    
    jcf = ngx_http_get_module_srv_conf(r, ngx_http_ja4_module);
    
    // 1. JA4 Checks (Only if SSL)
    if (r->connection->ssl && jcf->rules) {
        ngx_ja4_ssl_ctx_t *ctx;
        ngx_uint_t i;
        ngx_http_ja4_rule_t *rules;
        SSL *ssl;
        u_char buf[65];
        u_char *last;
        ngx_str_t fp;

        ssl = r->connection->ssl->connection;
        ctx = SSL_get_ex_data(ssl, ngx_ja4_ssl_ex_index);
        
        if (ctx && ctx->ja4_data) {
             if ((uintptr_t)ctx->ja4_data->highest_supported_tls_client_version < 65535) {
                ngx_ja4_calculate(r->connection, ctx->ja4_data);
            }
             
            last = ngx_snprintf(buf, 64, "%c%s%c%02d%02d_%s_%s",
                ctx->ja4_data->transport,
                ctx->ja4_data->version,
                ctx->ja4_data->has_sni,
                (int)ctx->ja4_data->ciphers_sz,
                (int)ctx->ja4_data->extensions_sz,
                ctx->ja4_data->cipher_hash_truncated,
                ctx->ja4_data->extension_hash_truncated
            );
            *last = '\0';
            
            fp.data = buf;
            fp.len = last - buf;
            
            rules = jcf->rules->elts;
            for (i = 0; i < jcf->rules->nelts; i++) {
                 if (rules[i].name.len == fp.len && ngx_strncmp(rules[i].name.data, fp.data, fp.len) == 0) {
                     if (rules[i].type == NGX_HTTP_JA4_DENY) {
                         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "access forbidden by JA4: %V", &fp);
                         return NGX_HTTP_FORBIDDEN;
                     }
                  }
             }
        }
    }
    
    // 2. JA4H Checks
    if (jcf->rules_h) {
        ngx_ssl_ja4h_t ja4h;
        u_char buf[65];
        u_char *last;
        ngx_str_t fp;
        ngx_uint_t i;
        ngx_http_ja4_rule_t *rules;
        
        ngx_memzero(&ja4h, sizeof(ngx_ssl_ja4h_t));
        
        ngx_ja4h_calculate(r, &ja4h);
        
        last = ngx_snprintf(buf, 64, "%s%s%c%02d_%s", 
            ja4h.method, ja4h.version, ja4h.cookie, ja4h.header_count, ja4h.header_hash);
        *last = '\0';
        
        fp.data = buf;
        fp.len = last - buf;
        
        rules = jcf->rules_h->elts;
        
        for (i = 0; i < jcf->rules_h->nelts; i++) {
             if (rules[i].name.len == fp.len && ngx_strncmp(rules[i].name.data, fp.data, fp.len) == 0) {
                 if (rules[i].type == NGX_HTTP_JA4_DENY) {
                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "access forbidden by JA4H: %V", &fp);
                     return NGX_HTTP_FORBIDDEN;
                 }
             }
        }
    }

    // 3. JA4one Checks
    if (jcf->rules_one) {
        ngx_ssl_ja4one_t ja4one;
        ngx_str_t fp;
        ngx_uint_t i;
        ngx_http_ja4_rule_t *rules;

        ngx_ja4one_calculate(r, &ja4one);
        
        fp.data = (u_char*)ja4one.fingerprint;
        fp.len = ngx_strlen(ja4one.fingerprint);
        
        rules = jcf->rules_one->elts;
         for (i = 0; i < jcf->rules_one->nelts; i++) {
             if (rules[i].name.len == fp.len && ngx_strncmp(rules[i].name.data, fp.data, fp.len) == 0) {
                 if (rules[i].type == NGX_HTTP_JA4_DENY) {
                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "access forbidden by JA4one: %V", &fp);
                     return NGX_HTTP_FORBIDDEN;
                 }
             }
        }
    }

    // 4. JA4S Checks (HTTP/2)
    if (jcf->rules_s) {
        ngx_ssl_ja4s_t ja4s;
        ngx_str_t fp;
        ngx_uint_t i;
        ngx_http_ja4_rule_t *rules;
        
        ngx_memzero(&ja4s, sizeof(ngx_ssl_ja4s_t));
        
        ngx_ja4s_calculate(r, &ja4s, r->pool);
        
        if (ja4s.fingerprint[0] != '\0') {
            fp.data = (u_char*)ja4s.fingerprint;
            fp.len = ngx_strlen(ja4s.fingerprint);
            
            rules = jcf->rules_s->elts;
            for (i = 0; i < jcf->rules_s->nelts; i++) {
                 if (rules[i].name.len == fp.len && ngx_strncmp(rules[i].name.data, fp.data, fp.len) == 0) {
                     if (rules[i].type == NGX_HTTP_JA4_DENY) {
                         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "access forbidden by JA4S: %V", &fp);
                         return NGX_HTTP_FORBIDDEN;
                     }
                 }
            }
        }
    }
    
    return NGX_DECLINED;
}
    

// Variables

// ... (existing code for add_variables)

static ngx_int_t ngx_http_ja4_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_ja4_ssl_ctx_t *ssl_ctx;
    ngx_http_ja4_ctx_t *ctx;
    u_char *p;
    u_char *last;
    
    ctx = ngx_http_get_module_ctx(r, ngx_http_ja4_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_ja4_ctx_t));
        if (ctx == NULL) return NGX_ERROR;
        ngx_http_set_ctx(r, ctx, ngx_http_ja4_module);
    }
    
    if (data == 0) { // JA4
        if (ctx->ja4.len > 0) {
             v->len = ctx->ja4.len;
             v->data = ctx->ja4.data;
             v->valid = 1;
             v->no_cacheable = 0;
             v->not_found = 0;
             return NGX_OK;
        }

        SSL *ssl;
        
        if (!r->connection || !r->connection->ssl) return NGX_OK; // Return empty if not SSL

        ssl = r->connection->ssl->connection;
        ssl_ctx = SSL_get_ex_data(ssl, ngx_ja4_ssl_ex_index);
        
        if (!ssl_ctx || !ssl_ctx->ja4_data) {
            v->not_found = 1;
            return NGX_OK;
        }
        
        ngx_ja4_calculate(r->connection, ssl_ctx->ja4_data);
        
        p = ngx_pnalloc(r->pool, 64);
        if (p == NULL) return NGX_ERROR;
        
        last = ngx_snprintf(p, 64, "%c%s%c%02d%02d_%s_%s",
            ssl_ctx->ja4_data->transport,
            ssl_ctx->ja4_data->version,
            ssl_ctx->ja4_data->has_sni,
            (int)ssl_ctx->ja4_data->ciphers_sz,
            (int)ssl_ctx->ja4_data->extensions_sz,
            ssl_ctx->ja4_data->cipher_hash_truncated,
            ssl_ctx->ja4_data->extension_hash_truncated
        );
        
        v->len = last - p;
        v->data = p;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        
        ctx->ja4.data = p;
        ctx->ja4.len = v->len;
        
        return NGX_OK;
    }
    else if (data == 1) { // JA4H
        if (ctx->ja4h.len > 0) {
             v->len = ctx->ja4h.len;
             v->data = ctx->ja4h.data;
             v->valid = 1;
             v->no_cacheable = 0;
             v->not_found = 0;
             return NGX_OK;
        }
    
        ngx_ssl_ja4h_t ja4h;
        ngx_memzero(&ja4h, sizeof(ngx_ssl_ja4h_t));
        
        ngx_ja4h_calculate(r, &ja4h);
        
        p = ngx_pnalloc(r->pool, 64);
        if (p == NULL) return NGX_ERROR;
        // MMVVCHH_HHHH...
        last = ngx_snprintf(p, 64, "%s%s%c%02d_%s", 
            ja4h.method, ja4h.version, ja4h.cookie, ja4h.header_count, ja4h.header_hash);
            
        v->len = last - p;
        v->data = p;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        
        ctx->ja4h.data = p;
        ctx->ja4h.len = v->len;
        
        return NGX_OK;
    }
    else if (data == 2) { // JA4one
         if (ctx->ja4one.len > 0) {
             v->len = ctx->ja4one.len;
             v->data = ctx->ja4one.data;
             v->valid = 1;
             v->no_cacheable = 0;
             v->not_found = 0;
             return NGX_OK;
         }
         
         ngx_ssl_ja4one_t ja4one;
         ngx_ja4one_calculate(r, &ja4one);
         
         p = ngx_pnalloc(r->pool, 64);
         if (p == NULL) return NGX_ERROR;
         
         last = ngx_snprintf(p, 64, "%s", ja4one.fingerprint);
         v->len = last - p;
         v->data = p;
         v->valid = 1;
         v->no_cacheable = 0;
         v->not_found = 0;
         
         ctx->ja4one.data = p;
         ctx->ja4one.len = v->len;
         
         return NGX_OK;
    }

    else if (data == 3) { // JA4TCP
        // Check Request Cache
        if (ctx->ja4tcp.len > 0) {
             v->len = ctx->ja4tcp.len;
             v->data = ctx->ja4tcp.data;
             v->valid = 1;
             v->no_cacheable = 0;
             v->not_found = 0;
             return NGX_OK;
        }

        // Check Connection Cache (if SSL)
        if (ssl_ctx && ssl_ctx->ja4tcp_data && ssl_ctx->ja4tcp_data->calculated) {
             v->len = ssl_ctx->ja4tcp_data->len;
             v->data = ssl_ctx->ja4tcp_data->data;
             v->valid = 1;
             v->no_cacheable = 0;
             v->not_found = 0;
             
             ctx->ja4tcp.data = v->data;
             ctx->ja4tcp.len = v->len;
             return NGX_OK;
        }

        ngx_ssl_ja4tcp_t ja4tcp_db;
        ngx_memzero(&ja4tcp_db, sizeof(ngx_ssl_ja4tcp_t));

        if (ssl_ctx) {
            // Allocate in connection pool if SSL
             if (!ssl_ctx->ja4tcp_data) {
                 ssl_ctx->ja4tcp_data = ngx_pcalloc(r->connection->pool, sizeof(ngx_ssl_ja4tcp_t));
             }
             if (ssl_ctx->ja4tcp_data) {
                 ngx_ja4tcp_calculate(r->connection, ssl_ctx->ja4tcp_data);
                 if (ssl_ctx->ja4tcp_data->len > 0) {
                     v->len = ssl_ctx->ja4tcp_data->len;
                     v->data = ssl_ctx->ja4tcp_data->data;
                     v->valid = 1;
                     v->no_cacheable = 0;
                     v->not_found = 0;
                     
                     ctx->ja4tcp.data = v->data;
                     ctx->ja4tcp.len = v->len;
                     return NGX_OK;
                 }
             }
        }
        
        // Fallback for non-SSL or failure (use request pool temp)
        ngx_ja4tcp_calculate(r->connection, &ja4tcp_db);
        
        if (ja4tcp_db.len == 0) {
            v->not_found = 1;
            return NGX_OK;
        }

        v->len = ja4tcp_db.len;
        v->data = ja4tcp_db.data;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        
        ctx->ja4tcp.data = ja4tcp_db.data;
        ctx->ja4tcp.len = ja4tcp_db.len;
        
        return NGX_OK;
    }
    
    else if (data == 4) { // JA4S
        if (ctx->ja4s.len > 0) {
             v->len = ctx->ja4s.len;
             v->data = ctx->ja4s.data;
             v->valid = 1;
             v->no_cacheable = 0;
             v->not_found = 0;
             return NGX_OK;
        }
        
        // Check Connection Cache (JA4S should be stable per connection)
        if (ssl_ctx && ssl_ctx->ja4s_data && ssl_ctx->ja4s_data->calculated) {
             v->len = ngx_strlen(ssl_ctx->ja4s_data->fingerprint);
             v->data = (u_char*)ssl_ctx->ja4s_data->fingerprint;
             v->valid = 1;
             v->no_cacheable = 0;
             v->not_found = 0;
             
             ctx->ja4s.data = v->data;
             ctx->ja4s.len = v->len;
             return NGX_OK;
        }

        ngx_ssl_ja4s_t ja4s;
        ngx_memzero(&ja4s, sizeof(ngx_ssl_ja4s_t));
        
        if (ssl_ctx) {
            // Allocate string in connection pool
            if (!ssl_ctx->ja4s_data) {
                ssl_ctx->ja4s_data = ngx_pcalloc(r->connection->pool, sizeof(ngx_ssl_ja4s_t));
            }
            if (ssl_ctx->ja4s_data) {
                ngx_ja4s_calculate(r, ssl_ctx->ja4s_data, r->connection->pool);
                if (ssl_ctx->ja4s_data->calculated) {
                     v->len = ngx_strlen(ssl_ctx->ja4s_data->fingerprint);
                     v->data = (u_char*)ssl_ctx->ja4s_data->fingerprint;
                     v->valid = 1;
                     v->no_cacheable = 0;
                     v->not_found = 0;
                     
                     ctx->ja4s.data = v->data;
                     ctx->ja4s.len = v->len;
                     return NGX_OK;
                }
            }
        }
        
        // Fallback or non-SSL
        ngx_ja4s_calculate(r, &ja4s, r->pool);
        
        if (ja4s.fingerprint[0] == '\0') {
            v->not_found = 1;
            return NGX_OK;
        }

        v->len = ngx_strlen(ja4s.fingerprint);
        v->data = ngx_pnalloc(r->pool, v->len + 1);
        if (v->data == NULL) return NGX_ERROR;
        ngx_memcpy(v->data, ja4s.fingerprint, v->len);
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        
        ctx->ja4s.data = v->data;
        ctx->ja4s.len = v->len;
        
        return NGX_OK;
    }

    return NGX_ERROR;
}

// ... (access handler updates will come in next step or I can do it here logic-wise)
// I will keep access handler logic separate for clarity if possible, or merge it. 
// The prompt asked for "JA4H Calculation Logic".

// --- CALCULATION LOGIC ---

void ngx_ja4h_calculate(ngx_http_request_t *r, ngx_ssl_ja4h_t *ja4h) {
    // 1. Method
    if (r->method & NGX_HTTP_GET) ngx_memcpy(ja4h->method, "ge", 2);
    else if (r->method & NGX_HTTP_POST) ngx_memcpy(ja4h->method, "po", 2);
    else if (r->method & NGX_HTTP_PUT) ngx_memcpy(ja4h->method, "pu", 2);
    else if (r->method & NGX_HTTP_DELETE) ngx_memcpy(ja4h->method, "de", 2);
    else if (r->method & NGX_HTTP_HEAD) ngx_memcpy(ja4h->method, "he", 2);
    else if (r->method & NGX_HTTP_OPTIONS) ngx_memcpy(ja4h->method, "op", 2);
    else if (r->method & NGX_HTTP_TRACE) ngx_memcpy(ja4h->method, "tr", 2);
    else if (r->method & NGX_HTTP_PATCH) ngx_memcpy(ja4h->method, "pa", 2);
    else ngx_memcpy(ja4h->method, "xx", 2);
    
    // 2. Version
    if (r->http_version == NGX_HTTP_VERSION_11) ngx_memcpy(ja4h->version, "11", 2);
    else if (r->http_version == NGX_HTTP_VERSION_10) ngx_memcpy(ja4h->version, "10", 2);
    else if (r->http_version == NGX_HTTP_VERSION_20) ngx_memcpy(ja4h->version, "20", 2);
    else if (r->http_version == NGX_HTTP_VERSION_30) ngx_memcpy(ja4h->version, "30", 2);
    else ngx_memcpy(ja4h->version, "00", 2);
    
// 2. Cookie & 4. Headers
    {
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *h = part->elts;
    ngx_uint_t i;
    SHA256_CTX sha256;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    int first = 1;

    ja4h->cookie = 'n';
    ja4h->header_count = 0;
    
    // For hashing
    SHA256_Init(&sha256);
    
    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) break;
            part = part->next;
            h = part->elts;
            i = 0;
        }
        
        // Check for Cookie
        if (h[i].key.len == 6 && ngx_strncasecmp(h[i].key.data, (u_char *)"Cookie", 6) == 0) {
            ja4h->cookie = 'c';
        }
        
        // Add to Hash (Key only)
        if (!first) {
            SHA256_Update(&sha256, ",", 1);
        }
        SHA256_Update(&sha256, h[i].key.data, h[i].key.len);
        first = 0;
        
        ja4h->header_count++;
    }
    
    
    
    SHA256_Final(hash, &sha256);
    ngx_hex_dump((u_char*)ja4h->header_hash, hash, 32); // Full SHA256 (64 chars)
    }
}

void ngx_ja4one_calculate(ngx_http_request_t *r, ngx_ssl_ja4one_t *ja4one) {
    // Placeholder logic for JA4one: Hash(JA4H + JA4)
    // For now purely experimental
    char ja4_part[128] = "";
    char ja4h_part[128];
    
    u_char *last;
    
    // 1. Get JA4H
    ngx_ssl_ja4h_t ja4h;
    ngx_memzero(&ja4h, sizeof(ngx_ssl_ja4h_t));
    ngx_ja4h_calculate(r, &ja4h);
    
    last = ngx_snprintf((u_char*)ja4h_part, 128, "%s%s%c%02d_%s", 
            ja4h.method, ja4h.version, ja4h.cookie, ja4h.header_count, ja4h.header_hash);
    *last = '\0';
            
    // 2. Get JA4 (if SSL)
    if (r->connection->ssl) {
        SSL *ssl = r->connection->ssl->connection;
        ngx_ja4_ssl_ctx_t *ctx = SSL_get_ex_data(ssl, ngx_ja4_ssl_ex_index);
        
        if (ctx && ctx->ja4_data) {
             if ((uintptr_t)ctx->ja4_data->highest_supported_tls_client_version < 65535) {
                ngx_ja4_calculate(r->connection, ctx->ja4_data);
            }
             last = ngx_snprintf((u_char*)ja4_part, 128, "%c%s%c%02d%02d_%s_%s_",
                ctx->ja4_data->transport,
                ctx->ja4_data->version,
                ctx->ja4_data->has_sni,
                (int)ctx->ja4_data->ciphers_sz,
                (int)ctx->ja4_data->extensions_sz,
                ctx->ja4_data->cipher_hash,
                ctx->ja4_data->extension_hash
            );
            *last = '\0';
        }
    }
    
    // 3. Combine
    // JA4one = JA4 + JA4H
    // If no JA4, matches just JA4H (or we could prefix with delimiter)
    
    u_char final_buf[256];
    last = ngx_snprintf(final_buf, 256, "%s%s", ja4_part, ja4h_part);
    *last = '\0';
    
    ngx_memcpy(ja4one->fingerprint, final_buf, ngx_strlen(final_buf) + 1);
}

// ------ JA4 CALCULATION LOGIC ------

void ngx_ja4_calculate(ngx_connection_t *c, ngx_ssl_ja4_t *ja4) {
    SSL *ssl = c->ssl->connection;
    ngx_pool_t *pool = c->pool;
    
    if (ja4->calculated) return;

    int max_ver, client_ver, ver;
    STACK_OF(SSL_CIPHER) *cp;
    int num_ciphers, i, id;
    const SSL_CIPHER *c_obj;
    char hex[5];
    SHA256_CTX sha256;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    
    uint16_t *filtered_exts;
    size_t count, raw_count, j;
    uint16_t ext;
    
    // 1. Version
    max_ver = (int)(uintptr_t)ja4->highest_supported_tls_client_version;
    client_ver = SSL_client_version(ssl);
    ver = max_ver ? max_ver : client_ver;
    
    switch (ver) {
        case TLS1_3_VERSION_INT: ja4->version = "13"; break;
        case TLS1_2_VERSION_INT: ja4->version = "12"; break;
        case TLS1_1_VERSION_INT: ja4->version = "11"; break;
        case TLS1_VERSION_INT:   ja4->version = "10"; break;
        default:                 ja4->version = "00"; break;
    }
    
    ja4->transport = (c->quic) ? 'q' : 't';
    ja4->has_sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name) ? 'd' : 'i';

    // 2. Ciphers
    cp = SSL_get_client_ciphers(ssl);
    if (cp) {
        ja4->ciphers_sz = 0;
        num_ciphers = sk_SSL_CIPHER_num(cp);
        ja4->ciphers = ngx_pnalloc(pool, num_ciphers * sizeof(uint16_t));
        
        // Populate and Filter
        for (i = 0; i < num_ciphers; i++) {
             c_obj = sk_SSL_CIPHER_value(cp, i);
             id = SSL_CIPHER_get_protocol_id(c_obj);
             
             if (ngx_ja4_is_grease((uint16_t)id)) continue;
             
             ja4->ciphers[ja4->ciphers_sz++] = (uint16_t)id;
        }
        
        // Sort Ciphers
        qsort(ja4->ciphers, ja4->ciphers_sz, sizeof(uint16_t), compare_uint16);
        
        // Hash Ciphers
        SHA256_Init(&sha256);
        for (j = 0; j < ja4->ciphers_sz; j++) {
            ngx_snprintf((u_char*)hex, 5, "%04x", ja4->ciphers[j]);
            SHA256_Update(&sha256, hex, 4);
            if (j < ja4->ciphers_sz - 1) {
                SHA256_Update(&sha256, ",", 1);
            }
        }
        SHA256_Final(hash, &sha256);
        
        ngx_hex_dump((u_char*)ja4->cipher_hash_truncated, hash, 6);
        ngx_hex_dump((u_char*)ja4->cipher_hash, hash, 32); 

    } else {
         ngx_memcpy(ja4->cipher_hash_truncated, "000000000000", 12);
         ngx_memset(ja4->cipher_hash, '0', 64);
         ja4->cipher_hash[64] = '\0';
    }
    
    // 3. Extensions Hashing
    if (ja4->extensions_sz > 0) {
        // We have raw extensions in ja4->extensions.
        filtered_exts = ngx_pnalloc(pool, ja4->extensions_sz * sizeof(uint16_t));
        count = 0;
        
        for (j = 0; j < ja4->extensions_sz; j++) {
            ext = ja4->extensions[j];
            if (ngx_ja4_is_grease(ext) || ngx_ja4_is_ignored(ext) || ngx_ja4_is_dynamic(ext)) continue;
            
            filtered_exts[count] = ext;
            count++;
        }
        
        // Sort
        qsort(filtered_exts, count, sizeof(uint16_t), compare_uint16);
        
        // Hash
        SHA256_Init(&sha256);
        for (j = 0; j < count; j++) {
            ngx_snprintf((u_char*)hex, 5, "%04x", filtered_exts[j]);
            SHA256_Update(&sha256, hex, 4);
            if (j < count - 1) {
                SHA256_Update(&sha256, ",", 1);
            }
        }
        SHA256_Final(hash, &sha256);
        
        ngx_hex_dump((u_char*)ja4->extension_hash_truncated, hash, 6);
        ngx_hex_dump((u_char*)ja4->extension_hash, hash, 32);
        
        raw_count = 0;
        for (j = 0; j < ja4->extensions_sz; j++) {
            if (!ngx_ja4_is_grease(ja4->extensions[j])) raw_count++;
        }
        ja4->extensions_sz = raw_count;

    } else {
        ngx_memcpy(ja4->extension_hash_truncated, "000000000000", 12);
        ngx_memset(ja4->extension_hash, '0', 64);
        ja4->extension_hash[64] = '\0';
    }

    ja4->calculated = 1;
}

void ngx_ja4tcp_calculate(ngx_connection_t *c, ngx_ssl_ja4tcp_t *ja4tcp) {
    u_char buf[1024];
    socklen_t len = sizeof(buf);
    int fd;
    u_char *p, *tcp_hdr, *opts;
    u_char *last;
    int ip_ver, ip_hdr_len, tcp_hdr_len;
    uint16_t src_port, dst_port, window;
    int mss = 0, scale = 0;
    u_char opt_kinds[64];
    int opt_count = 0;
    int i;
    u_char *out_buf;
    
    ja4tcp->len = 0;
    ja4tcp->data = NULL;
    ja4tcp->calculated = 0;

    if (!c) return;
    fd = c->fd;

    if (getsockopt(fd, IPPROTO_TCP, TCP_SAVED_SYN, buf, &len) == -1) {
        return;
    }
    
    // Parse IP Header
    if (len < 20) return;
    ip_ver = (buf[0] >> 4);
    
    if (ip_ver == 4) {
        ip_hdr_len = (buf[0] & 0x0F) * 4;
    } else if (ip_ver == 6) {
        ip_hdr_len = 40;
    } else {
        return; // Unknown IP version
    }
    
    if (len < ip_hdr_len + 20) return;
    
    tcp_hdr = buf + ip_hdr_len;
    
    // TCP Header offset
    tcp_hdr_len = ((tcp_hdr[12] >> 4) & 0x0F) * 4;
    
    if (len < ip_hdr_len + tcp_hdr_len) return;
    
    window = (tcp_hdr[14] << 8) | tcp_hdr[15];
    
    // Parse Options
    if (tcp_hdr_len > 20) {
        opts = tcp_hdr + 20;
        int opt_len = tcp_hdr_len - 20;
        int idx = 0;
        
        while (idx < opt_len) {
            uint8_t kind = opts[idx];
            
            if (kind == 0) break; // EOL
            
            if (kind == 1) { // NOP
                if (opt_count < 63) {
                    opt_kinds[opt_count++] = kind;
                }
                idx++;
                continue;
            }
            
            if (idx + 1 >= opt_len) break;
            uint8_t length = opts[idx+1];
            if (length < 2 || idx + length > opt_len) break;
            
            if (opt_count < 63) {
                opt_kinds[opt_count++] = kind;
            }
            
            // Extract specific values
            if (kind == 2 && length == 4) { // MSS
                mss = (opts[idx+2] << 8) | opts[idx+3];
            } else if (kind == 3 && length == 3) { // Window Scale
                scale = opts[idx+2];
            }
            
            idx += length;
        }
    }
    
    out_buf = ngx_pnalloc(c->pool, 256);
    if (out_buf == NULL) return;
    
    last = ngx_snprintf(out_buf, 256, "%d_", window);
    
    if (opt_count > 0) {
        for (i = 0; i < opt_count; i++) {
            if (i > 0) {
                last = ngx_snprintf(last, 256 - (last - out_buf), "-");
            }
            last = ngx_snprintf(last, 256 - (last - out_buf), "%d", (int)opt_kinds[i]);
        }
    } else {
        last = ngx_snprintf(last, 256 - (last - out_buf), "0");
    }
    
    last = ngx_snprintf(last, 256 - (last - out_buf), "_%d_%d", mss, scale);
    *last = '\0';
    
    ja4tcp->data = out_buf;
    ja4tcp->len = last - out_buf;
    ja4tcp->calculated = 1;
}





// HTTP/2 Setting IDs (Standard RFC 7540)
#define JA4S_SETTING_HEADER_TABLE_SIZE      0x1
#define JA4S_SETTING_ENABLE_PUSH            0x2
#define JA4S_SETTING_MAX_CONCURRENT_STREAMS 0x3
#define JA4S_SETTING_INITIAL_WINDOW_SIZE    0x4
#define JA4S_SETTING_MAX_FRAME_SIZE         0x5
#define JA4S_SETTING_MAX_HEADER_LIST_SIZE   0x6

typedef struct {
    uint32_t id;
    uint32_t val;
} ngx_ja4s_setting_pair_t;

static int ngx_ja4s_cmp_pair(const void *a, const void *b) {
    return (int)(((const ngx_ja4s_setting_pair_t *)a)->id - ((const ngx_ja4s_setting_pair_t *)b)->id);
}

void ngx_ja4s_calculate(ngx_http_request_t *r, ngx_ssl_ja4s_t *ja4s, ngx_pool_t *pool) {
    ngx_http_v2_stream_t *stream;
    ngx_http_v2_connection_t *h2c;
    ngx_ja4s_setting_pair_t pairs[32];
    uint32_t cnt;
    uint32_t i;
    u_char buf[1024];
    u_char *p, *last;
    u_char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    
    if (ja4s->calculated) return;

    // 1. Check HTTP/2 Version (Robust check)
    if (r->http_version < NGX_HTTP_VERSION_20) {
        return;
    }
    
    // 2. Access Internal Structures (Safe with Patch)
    if (r->stream == NULL) return;
    
    stream = r->stream;
    h2c = stream->connection;
    
    if (h2c == NULL) return;

    // 3. Process Settings (No-Patch / Reconstruction Mode)
    // Since we cannot patch NGINX to capture raw settings, we reconstruct the known settings
    // from the connection state. This loses "Order" and "Unknown/Grease" settings,
    // but ensures upgrade compatibility.
    
    cnt = 0;
    
    // Setting 1: INITIAL_WINDOW_SIZE (ID 4)
    // h2c->init_window tracks valid window size
    pairs[cnt].id = JA4S_SETTING_INITIAL_WINDOW_SIZE;
    pairs[cnt].val = (uint32_t)h2c->init_window;
    cnt++;
    
    // Setting 2: MAX_FRAME_SIZE (ID 5)
    // h2c->frame_size tracks frame size
    pairs[cnt].id = JA4S_SETTING_MAX_FRAME_SIZE;
    pairs[cnt].val = (uint32_t)h2c->frame_size;
    cnt++;
    
    // Setting 3: HEADER_TABLE_SIZE (ID 1)
    // h2c->hpack.size tracks table size? NGINX uses dynamic table but stores limit?
    // h2c->hpack.size seems to be current size.
    // NGINX doesn't store the SETTING value if it's strictly internal. 
    // We will skip it to be safe, or include if we can verify correctness.
    // For now, we stick to robust fields.
    
    // Sort logic (Strictly by ID for consistency)
    qsort(pairs, cnt, sizeof(ngx_ja4s_setting_pair_t), ngx_ja4s_cmp_pair);
    
    // Generate Hash String: id:val,id:val,...
    p = buf;
    last = buf + sizeof(buf);
    
    for (i = 0; i < cnt; i++) {
        if (i > 0) {
            p = ngx_snprintf(p, last - p, ",");
        }
        p = ngx_snprintf(p, last - p, "%ui:%ui", (ngx_uint_t)pairs[i].id, (ngx_uint_t)pairs[i].val);
    }
    
    // SHA256
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, buf, p - buf);
    SHA256_Final(hash, &sha256);
    
    // Truncate Hash (12 chars = 6 bytes hex)
    ngx_hex_dump((u_char*)ja4s->settings_hash, hash, 6);
    ja4s->settings_hash[12] = '\0'; 
    
    // 4. Construct Final Fingerprint
    // Format: h2<ProtoVer>_<Count>_<Hash>_<InitWindow>_<ConnectionWindow>_<Priority?>
    // "Connection Window" (h2c->send_window) tracks the client's advertised connection-level flow control.
    // This is a critical signal mentioned in research (e.g. Chrome ~15MB, Firefox ~12MB).
    
    ngx_snprintf((u_char*)ja4s->fingerprint, 255, "h220_%02d_%s_%uz_%uz_0", 
                 cnt, 
                 ja4s->settings_hash,
                 h2c->init_window,
                 h2c->send_window); 
    
    ja4s->calculated = 1;
}

