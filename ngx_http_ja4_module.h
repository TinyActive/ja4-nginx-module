#ifndef _NGX_HTTP_JA4_MODULE_H_INCLUDED_
#define _NGX_HTTP_JA4_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/ssl.h>

// Struct to store JA4 data attached to the SSL Connection via ex_data
typedef struct {
    ngx_pool_t *pool;
    // We can store the raw ja4 struct here
    // Note: We need to define ngx_ssl_ja4_t first, so I'll move this typedef below or forward declare
    struct ngx_ssl_ja4_s *ja4_data; 
    struct ngx_ssl_ja4s_s *ja4s_data;
    struct ngx_ssl_ja4tcp_s *ja4tcp_data;
} ngx_ja4_ssl_ctx_t;


typedef struct {
    ngx_str_t   ja4;
    ngx_str_t   ja4_string;
    ngx_str_t   ja4one;
    ngx_str_t   ja4h;
    ngx_str_t   ja4s;
    ngx_str_t   ja4tcp;
} ngx_http_ja4_ctx_t;

// STRUCTS
typedef struct ngx_ssl_ja4_s
{
    char *version; // TLS version
    char *highest_supported_tls_client_version;

    unsigned char transport; // 'q' for QUIC, 't' for TCP

    unsigned char has_sni; // 'd' if SNI is present, 'i' otherwise

    size_t ciphers_sz; // Count of ciphers
    uint16_t *ciphers;    // List of ciphers

    size_t extensions_count; // Count of extensions including ignored extensions
    size_t extensions_sz; // Count of extensions NOT including ignored extensions
    uint16_t *extensions;    // List of extensions

    size_t extensions_no_psk_count;
    char **extensions_no_psk; // Left as is for now, or could optimize if used

    char extension_hash_no_psk[65];
    char extension_hash_no_psk_truncated[13];

    size_t sigalgs_sz;
    char **sigalgs;

    char *alpn_first_value;

    char cipher_hash[65];
    char cipher_hash_truncated[13];

    char extension_hash[65];
    char extension_hash_truncated[13];
    
    unsigned int calculated:1;

} ngx_ssl_ja4_t;

typedef struct ngx_ssl_ja4tcp_s {
    u_char *data;
    size_t len;
    unsigned int calculated:1;
} ngx_ssl_ja4tcp_t;

typedef struct ngx_ssl_ja4s_s {
    // JA4S = h2<count>_<settings_hash>_<window>_<order>_<priority>
    uint8_t settings_count;
    char settings_hash[65];        // SHA256 full hash
    
    uint32_t window_increment;
    
    char pseudo_order[5];          // e.g., "masp"
    uint8_t priority_count;
    
    char fingerprint[256];         // Final JA4S string
    unsigned int calculated:1;
} ngx_ssl_ja4s_t;

typedef struct ngx_ssl_ja4h_s {
     // JA4H: MMVVCHH_HHHHHHHHHHHH
     char method[3];   // e.g. "GE", "PO"
     char version[3];  // e.g. "11", "20"
     char cookie;      // 'c' or 'n'
     int  header_count;// e.g. 12
     char header_hash[65]; // Full SHA256
     
     // Storage for raw calculation
     char *sorted_headers; // Comma separated string of header names
} ngx_ssl_ja4h_t;

typedef struct ngx_ssl_ja4one_s {
    // JA4one: JA4_JA4H
    char fingerprint[512]; 
} ngx_ssl_ja4one_t;

typedef struct ngx_ssl_ja4t_s { int dummy; } ngx_ssl_ja4t_t;
typedef struct ngx_ssl_ja4ts_s { int dummy; } ngx_ssl_ja4ts_t;
typedef struct ngx_ssl_ja4x_s { int dummy; } ngx_ssl_ja4x_t;
typedef struct ngx_ssl_ja4l_s { int dummy; } ngx_ssl_ja4l_t;


// CONSTANTS
#define SSL3_VERSION_INT    0x0300
#define TLS1_VERSION_INT    0x0301
#define TLS1_1_VERSION_INT  0x0302
#define TLS1_2_VERSION_INT  0x0303
#define TLS1_3_VERSION_INT  0x0304
#define QUICV1_VERSION_INT  0x0001


// Configuration structs
// Configuration structs
typedef struct {
    ngx_str_t name;
    ngx_uint_t type; // NGX_HTTP_JA4_ALLOW or NGX_HTTP_JA4_DENY
} ngx_http_ja4_rule_t;

typedef struct {
    ngx_flag_t  enable;
    ngx_array_t *rules;      // Array of ngx_http_ja4_rule_t for JA4
    ngx_array_t *rules_h;    // Array of ngx_http_ja4_rule_t for JA4H
    ngx_array_t *rules_one;  // Array of ngx_http_ja4_rule_t for JA4one
    ngx_array_t *rules_s;    // Array of ngx_http_ja4_rule_t for JA4S
} ngx_http_ja4_srv_conf_t;

#endif
