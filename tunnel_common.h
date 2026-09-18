#ifndef LIVEKADEH_TUNNEL_COMMON_H
#define LIVEKADEH_TUNNEL_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "crypto.h"

#define LIVEKADEH_VERSION "1.2.0"

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #include <process.h>

  typedef SOCKET socket_t;
  #define IS_VALIDSOCK(s) ((s) != INVALID_SOCKET)
  #define CLOSE_SOCK(s) closesocket(s)
  #define SOCK_ERRNO WSAGetLastError()

  static inline void net_init(void) {
      WSADATA wsa;
      WSAStartup(MAKEWORD(2, 2), &wsa);
  }

  static inline void net_cleanup(void) {
      WSACleanup();
  }

  typedef DWORD (WINAPI *thread_func_t)(LPVOID);

  static inline int spawn_thread(thread_func_t func, void *arg) {
      HANDLE h = CreateThread(NULL, 0, func, arg, 0, NULL);
      if (h == NULL) return -1;
      CloseHandle(h);
      return 0;
  }

#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <pthread.h>
  #include <signal.h>
  #include <errno.h>

  typedef int socket_t;
  #define INVALID_SOCKET (-1)
  #define SOCKET_ERROR   (-1)
  #define IS_VALIDSOCK(s) ((s) >= 0)
  #define CLOSE_SOCK(s) close(s)
  #define SOCK_ERRNO errno

  static inline void net_init(void) {
      signal(SIGPIPE, SIG_IGN);
  }

  static inline void net_cleanup(void) {}

  typedef void *(*thread_func_t)(void *);

  static inline int spawn_thread(thread_func_t func, void *arg) {
      pthread_t tid;
      pthread_attr_t attr;
      pthread_attr_init(&attr);
      pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
      int rc = pthread_create(&tid, &attr, func, arg);
      pthread_attr_destroy(&attr);
      return rc;
  }
#endif

#define BUFFER_SIZE (32 * 1024)
#define NONCE_SIZE  16

#ifndef MAX_PATH
#define MAX_PATH 1024
#endif

/* Set TCP_NODELAY for minimum latency */
static inline void set_tcp_nodelay(socket_t sock) {
    int opt = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&opt, sizeof(opt));
}

/* Parse host and port from string "host:port", "host", or "port" */
static inline int parse_host_port(const char *input, char *host, size_t host_len, int *port) {
    const char *colon = strrchr(input, ':');
    if (colon) {
        size_t hlen = (size_t)(colon - input);
        if (hlen >= host_len) return -1;
        if (hlen == 0) {
            snprintf(host, host_len, "0.0.0.0");
        } else {
            memcpy(host, input, hlen);
            host[hlen] = '\0';
        }
        *port = atoi(colon + 1);
    } else {
        int all_digits = 1;
        for (size_t k = 0; input[k]; k++) {
            if (input[k] < '0' || input[k] > '9') { all_digits = 0; break; }
        }
        if (all_digits) {
            snprintf(host, host_len, "0.0.0.0");
            *port = atoi(input);
        } else {
            snprintf(host, host_len, "%s", input);
        }
    }
    return (*port > 0 && *port <= 65535) ? 0 : -1;
}

/* Create listening socket */
static inline socket_t create_listener(const char *bind_host, int port) {
    socket_t s = socket(AF_INET, SOCK_STREAM, 0);
    if (!IS_VALIDSOCK(s)) return INVALID_SOCKET;

    int opt = 1;
#ifdef _WIN32
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
#else
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons((uint16_t)port);

    if (strcmp(bind_host, "0.0.0.0") == 0 || strcmp(bind_host, "") == 0) {
        sin.sin_addr.s_addr = INADDR_ANY;
    } else {
        struct hostent *he = gethostbyname(bind_host);
        if (!he) {
            CLOSE_SOCK(s);
            return INVALID_SOCKET;
        }
        memcpy(&sin.sin_addr, he->h_addr_list[0], sizeof(sin.sin_addr));
    }

    if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) == SOCKET_ERROR) {
        CLOSE_SOCK(s);
        return INVALID_SOCKET;
    }

    if (listen(s, 128) == SOCKET_ERROR) {
        CLOSE_SOCK(s);
        return INVALID_SOCKET;
    }

    return s;
}

/* Connect to remote host */
static inline socket_t connect_remote(const char *target_host, int port) {
    struct hostent *he = gethostbyname(target_host);
    if (!he) return INVALID_SOCKET;

    socket_t s = socket(AF_INET, SOCK_STREAM, 0);
    if (!IS_VALIDSOCK(s)) return INVALID_SOCKET;

    set_tcp_nodelay(s);

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons((uint16_t)port);
    memcpy(&sin.sin_addr, he->h_addr_list[0], sizeof(sin.sin_addr));

    if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) == SOCKET_ERROR) {
        CLOSE_SOCK(s);
        return INVALID_SOCKET;
    }

    return s;
}

/* Read exact n bytes */
static inline int read_exact(socket_t sock, uint8_t *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        int n = recv(sock, (char *)buf + total, (int)(len - total), 0);
        if (n <= 0) return -1;
        total += (size_t)n;
    }
    return 0;
}

/* Write exact n bytes */
static inline int write_exact(socket_t sock, const uint8_t *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        int n = send(sock, (const char *)buf + total, (int)(len - total), 0);
        if (n <= 0) return -1;
        total += (size_t)n;
    }
    return 0;
}

/* Derive master key from passphrase */
static inline void derive_master_key(const char *passphrase, uint8_t master_key[32]) {
    lk_sha256((const uint8_t *)passphrase, strlen(passphrase), master_key);
}

/* Derive direction key using HMAC */
static inline void derive_direction_key(const uint8_t master_key[32],
                                        const char *label,
                                        const uint8_t nonce[16],
                                        uint8_t out_key[32]) {
    uint8_t salt[64];
    size_t label_len = strlen(label);
    memcpy(salt, label, label_len);
    memcpy(salt + label_len, nonce, 16);
    lk_hmac_sha256(master_key, 32, salt, label_len + 16, out_key);
}

#define AUTH_NONCE_SIZE 16
#define AUTH_TAG_SIZE   32
#define AUTH_VER_SIZE   16
#define AUTH_PACKET_SIZE (AUTH_NONCE_SIZE + AUTH_TAG_SIZE)
#define AUTH_FULL_PACKET_SIZE (AUTH_PACKET_SIZE + AUTH_VER_SIZE)

/* Encrypt 16-byte version field using key derived from nonce */
static inline void encrypt_version_field(const uint8_t master_key[32],
                                         const uint8_t nonce[AUTH_NONCE_SIZE],
                                         const char *version,
                                         uint8_t out[AUTH_VER_SIZE]) {
    uint8_t raw[AUTH_VER_SIZE];
    memset(raw, 0, sizeof(raw));
    snprintf((char *)raw, sizeof(raw), "%s", version);

    uint8_t k_ver[32];
    derive_direction_key(master_key, "LK-VER-KEY", nonce, k_ver);

    lk_chacha20_ctx ctx;
    lk_chacha20_init(&ctx, k_ver, nonce, 1);
    lk_chacha20_xor(&ctx, raw, out, AUTH_VER_SIZE);
}

/* Decrypt 16-byte version field */
static inline void decrypt_version_field(const uint8_t master_key[32],
                                         const uint8_t nonce[AUTH_NONCE_SIZE],
                                         const uint8_t in[AUTH_VER_SIZE],
                                         char *out_version, size_t max_len) {
    uint8_t k_ver[32];
    derive_direction_key(master_key, "LK-VER-KEY", nonce, k_ver);

    lk_chacha20_ctx ctx;
    lk_chacha20_init(&ctx, k_ver, nonce, 1);
    uint8_t raw[AUTH_VER_SIZE];
    lk_chacha20_xor(&ctx, in, raw, AUTH_VER_SIZE);
    raw[AUTH_VER_SIZE - 1] = '\0';

    snprintf(out_version, max_len, "%s", (char *)raw);
}

/* Calculate authentication tag */
static inline void compute_auth_tag(const uint8_t master_key[32],
                                    const char *label,
                                    const uint8_t nonce[AUTH_NONCE_SIZE],
                                    uint8_t out_tag[AUTH_TAG_SIZE]) {
    uint8_t data[64];
    size_t label_len = strlen(label);
    memcpy(data, label, label_len);
    memcpy(data + label_len, nonce, AUTH_NONCE_SIZE);
    lk_hmac_sha256(master_key, 32, data, label_len + AUTH_NONCE_SIZE, out_tag);
}

#define NUM_TUNNEL_CONNS 8
#define ATTACH_PACKET_SIZE 64

/* Tune socket with TCP_NODELAY and large send/recv buffers */
static inline void tune_tunnel_socket(socket_t s) {
    set_tcp_nodelay(s);
    int buf = 1024 * 1024; /* 1MB socket buffer */
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char *)&buf, sizeof(buf));
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, (const char *)&buf, sizeof(buf));
}

/* 5-Tuple flow hash to guarantee in-order delivery within any TCP connection */
static inline uint32_t flow_hash_packet(const uint8_t *pkt, size_t len) {
    if (!pkt || len < 20) return 0;
    uint8_t ver = pkt[0] >> 4;
    if (ver == 4) {
        uint32_t src_ip = *(const uint32_t *)(pkt + 12);
        uint32_t dst_ip = *(const uint32_t *)(pkt + 16);
        uint8_t proto = pkt[9];
        uint16_t src_port = 0, dst_port = 0;
        size_t ihl = (pkt[0] & 0x0F) * 4;
        if ((proto == 6 || proto == 17) && len >= ihl + 4) {
            src_port = *(const uint16_t *)(pkt + ihl);
            dst_port = *(const uint16_t *)(pkt + ihl + 2);
        }
        uint32_t h = src_ip ^ dst_ip ^ ((uint32_t)proto << 16) ^ ((uint32_t)src_port << 16) ^ dst_port;
        h ^= (h >> 16);
        h *= 0x85ebca6b;
        h ^= (h >> 13);
        return h;
    } else if (ver == 6 && len >= 40) {
        uint32_t h = 0;
        for (size_t i = 8; i < 40; i += 4) h ^= *(const uint32_t *)(pkt + i);
        uint8_t next_hdr = pkt[6];
        if ((next_hdr == 6 || next_hdr == 17) && len >= 44) {
            uint16_t sp = *(const uint16_t *)(pkt + 40);
            uint16_t dp = *(const uint16_t *)(pkt + 42);
            h ^= ((uint32_t)sp << 16) | dp;
        }
        h ^= (h >> 16);
        return h;
    }
    return 0;
}

/* Make attach packet for auxiliary lane */
static inline void make_attach_packet(const uint8_t master_key[32],
                                      const uint8_t c_nonce[AUTH_NONCE_SIZE],
                                      uint8_t lane_idx,
                                      uint8_t out[ATTACH_PACKET_SIZE]) {
    memset(out, 0, ATTACH_PACKET_SIZE);
    memcpy(out, c_nonce, AUTH_NONCE_SIZE);
    out[AUTH_NONCE_SIZE] = lane_idx;

    uint8_t data[AUTH_NONCE_SIZE + 1];
    memcpy(data, c_nonce, AUTH_NONCE_SIZE);
    data[AUTH_NONCE_SIZE] = lane_idx;

    compute_auth_tag(master_key, "LK-ATTACH-LANE", data, out + AUTH_NONCE_SIZE + 16);
}

/* Verify attach packet on server */
static inline int verify_attach_packet(const uint8_t master_key[32],
                                       const uint8_t in[ATTACH_PACKET_SIZE],
                                       uint8_t out_c_nonce[AUTH_NONCE_SIZE],
                                       uint8_t *out_lane_idx) {
    memcpy(out_c_nonce, in, AUTH_NONCE_SIZE);
    *out_lane_idx = in[AUTH_NONCE_SIZE];

    uint8_t data[AUTH_NONCE_SIZE + 1];
    memcpy(data, out_c_nonce, AUTH_NONCE_SIZE);
    data[AUTH_NONCE_SIZE] = *out_lane_idx;

    uint8_t expected_tag[AUTH_TAG_SIZE];
    compute_auth_tag(master_key, "LK-ATTACH-LANE", data, expected_tag);

    if (memcmp(in + AUTH_NONCE_SIZE + 16, expected_tag, AUTH_TAG_SIZE) != 0) {
        return -1;
    }
    return 0;
}

/* Perform client handshake authentication with version exchange */
static inline int client_authenticate(socket_t sock, const uint8_t master_key[32],
                                      uint8_t c_nonce[AUTH_NONCE_SIZE],
                                      uint8_t s_nonce[AUTH_NONCE_SIZE],
                                      char *out_server_version, size_t ver_len) {
    if (out_server_version && ver_len > 0) {
        snprintf(out_server_version, ver_len, "unknown");
    }

    if (lk_random_bytes(c_nonce, AUTH_NONCE_SIZE) != 0) return -1;

    uint8_t c_pkt[AUTH_FULL_PACKET_SIZE];
    memcpy(c_pkt, c_nonce, AUTH_NONCE_SIZE);
    compute_auth_tag(master_key, "LK-CLIENT-AUTH", c_nonce, c_pkt + AUTH_NONCE_SIZE);
    encrypt_version_field(master_key, c_nonce, LIVEKADEH_VERSION, c_pkt + AUTH_PACKET_SIZE);

    if (write_exact(sock, c_pkt, AUTH_FULL_PACKET_SIZE) != 0) return -1;

    uint8_t s_pkt[AUTH_FULL_PACKET_SIZE];
    if (read_exact(sock, s_pkt, AUTH_PACKET_SIZE) != 0) return -1;

    memcpy(s_nonce, s_pkt, AUTH_NONCE_SIZE);
    uint8_t expected_s_tag[AUTH_TAG_SIZE];
    compute_auth_tag(master_key, "LK-SERVER-AUTH", s_nonce, expected_s_tag);

    if (memcmp(s_pkt + AUTH_NONCE_SIZE, expected_s_tag, AUTH_TAG_SIZE) != 0) {
        return -2; /* Authentication failed: Invalid key */
    }

    /* Check for server encrypted version field (16 bytes) */
    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(sock, &rset);
    struct timeval tv = { 0, 100000 }; /* 100 ms timeout */
    if (select((int)sock + 1, &rset, NULL, NULL, &tv) > 0) {
        if (read_exact(sock, s_pkt + AUTH_PACKET_SIZE, AUTH_VER_SIZE) == 0) {
            if (out_server_version && ver_len > 0) {
                decrypt_version_field(master_key, s_nonce, s_pkt + AUTH_PACKET_SIZE, out_server_version, ver_len);
            }
        }
    } else {
        if (out_server_version && ver_len > 0) {
            snprintf(out_server_version, ver_len, "1.0.0");
        }
    }

    return 0; /* Verified */
}

/* Perform server handshake authentication with version exchange */
static inline int server_authenticate(socket_t sock, const uint8_t master_key[32],
                                      uint8_t c_nonce[AUTH_NONCE_SIZE],
                                      uint8_t s_nonce[AUTH_NONCE_SIZE],
                                      char *out_client_version, size_t ver_len) {
    if (out_client_version && ver_len > 0) {
        snprintf(out_client_version, ver_len, "unknown");
    }

    uint8_t c_pkt[AUTH_FULL_PACKET_SIZE];
    if (read_exact(sock, c_pkt, AUTH_PACKET_SIZE) != 0) return -1;

    memcpy(c_nonce, c_pkt, AUTH_NONCE_SIZE);
    uint8_t expected_c_tag[AUTH_TAG_SIZE];
    compute_auth_tag(master_key, "LK-CLIENT-AUTH", c_nonce, expected_c_tag);

    if (memcmp(c_pkt + AUTH_NONCE_SIZE, expected_c_tag, AUTH_TAG_SIZE) != 0) {
        return -2; /* Authentication failed: Invalid key */
    }

    /* Check if client sent 16 extra bytes for version */
    int has_client_ver = 0;
    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(sock, &rset);
    struct timeval tv = { 0, 50000 }; /* 50 ms timeout */
    if (select((int)sock + 1, &rset, NULL, NULL, &tv) > 0) {
        if (read_exact(sock, c_pkt + AUTH_PACKET_SIZE, AUTH_VER_SIZE) == 0) {
            has_client_ver = 1;
            if (out_client_version && ver_len > 0) {
                decrypt_version_field(master_key, c_nonce, c_pkt + AUTH_PACKET_SIZE, out_client_version, ver_len);
            }
        }
    }

    if (lk_random_bytes(s_nonce, AUTH_NONCE_SIZE) != 0) return -1;

    uint8_t s_pkt[AUTH_FULL_PACKET_SIZE];
    memcpy(s_pkt, s_nonce, AUTH_NONCE_SIZE);
    compute_auth_tag(master_key, "LK-SERVER-AUTH", s_nonce, s_pkt + AUTH_NONCE_SIZE);

    if (has_client_ver) {
        encrypt_version_field(master_key, s_nonce, LIVEKADEH_VERSION, s_pkt + AUTH_PACKET_SIZE);
        if (write_exact(sock, s_pkt, AUTH_FULL_PACKET_SIZE) != 0) return -1;
    } else {
        if (write_exact(sock, s_pkt, AUTH_PACKET_SIZE) != 0) return -1;
    }

    return 0; /* Verified */
}

/* Helper to generate a random 32-byte cryptographic key as a hex string */
static inline int generate_random_key_hex(char *out_hex, size_t max_len) {
    if (max_len < 65) return -1;
    uint8_t rand_bytes[32];
    if (lk_random_bytes(rand_bytes, 32) != 0) return -1;
    for (int i = 0; i < 32; ++i) {
        sprintf(out_hex + (i * 2), "%02x", rand_bytes[i]);
    }
    out_hex[64] = '\0';
    return 0;
}

/* Server Session Worker */
typedef struct {
    socket_t sock_tunnel;
    char target_host[256];
    int target_port;
    uint8_t master_key[32];
} server_conn_t;

#ifdef _WIN32
static DWORD WINAPI handle_server_client(LPVOID arg)
#else
static void *handle_server_client(void *arg)
#endif
{
    server_conn_t *conn = (server_conn_t *)arg;
    socket_t sock_tunnel = conn->sock_tunnel;
    socket_t sock_target = INVALID_SOCKET;

    uint8_t c_nonce[NONCE_SIZE];
    uint8_t s_nonce[NONCE_SIZE];

    if (read_exact(sock_tunnel, c_nonce, NONCE_SIZE) != 0) {
        CLOSE_SOCK(sock_tunnel);
        free(conn);
        return 0;
    }

    if (lk_random_bytes(s_nonce, NONCE_SIZE) != 0) {
        CLOSE_SOCK(sock_tunnel);
        free(conn);
        return 0;
    }

    if (write_exact(sock_tunnel, s_nonce, NONCE_SIZE) != 0) {
        CLOSE_SOCK(sock_tunnel);
        free(conn);
        return 0;
    }

    sock_target = connect_remote(conn->target_host, conn->target_port);
    if (!IS_VALIDSOCK(sock_target)) {
        CLOSE_SOCK(sock_tunnel);
        free(conn);
        return 0;
    }

    uint8_t key_c2s[32];
    uint8_t key_s2c[32];
    derive_direction_key(conn->master_key, "C2S", c_nonce, key_c2s);
    derive_direction_key(conn->master_key, "S2C", s_nonce, key_s2c);

    lk_chacha20_ctx ctx_dec;
    lk_chacha20_ctx ctx_enc;
    lk_chacha20_init(&ctx_dec, key_c2s, c_nonce, 1);
    lk_chacha20_init(&ctx_enc, key_s2c, s_nonce, 1);

    uint8_t *buf_in = (uint8_t *)malloc(BUFFER_SIZE);
    uint8_t *buf_out = (uint8_t *)malloc(BUFFER_SIZE);
    if (!buf_in || !buf_out) {
        free(buf_in);
        free(buf_out);
        CLOSE_SOCK(sock_target);
        CLOSE_SOCK(sock_tunnel);
        free(conn);
        return 0;
    }

    while (1) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sock_tunnel, &read_fds);
        FD_SET(sock_target, &read_fds);

        int max_fd = (sock_tunnel > sock_target ? (int)sock_tunnel : (int)sock_target) + 1;
        int activity = select(max_fd, &read_fds, NULL, NULL, NULL);
        if (activity <= 0) break;

        if (FD_ISSET(sock_tunnel, &read_fds)) {
            int n = recv(sock_tunnel, (char *)buf_in, BUFFER_SIZE, 0);
            if (n <= 0) break;
            lk_chacha20_xor(&ctx_dec, buf_in, buf_in, (size_t)n);
            if (write_exact(sock_target, buf_in, (size_t)n) != 0) break;
        }

        if (FD_ISSET(sock_target, &read_fds)) {
            int n = recv(sock_target, (char *)buf_out, BUFFER_SIZE, 0);
            if (n <= 0) break;
            lk_chacha20_xor(&ctx_enc, buf_out, buf_out, (size_t)n);
            if (write_exact(sock_tunnel, buf_out, (size_t)n) != 0) break;
        }
    }

    free(buf_in);
    free(buf_out);
    CLOSE_SOCK(sock_target);
    CLOSE_SOCK(sock_tunnel);
    free(conn);
    return 0;
}

/* Client Session Worker */
typedef struct {
    socket_t sock_local;
    char server_host[256];
    int server_port;
    uint8_t master_key[32];
} client_conn_t;

#ifdef _WIN32
static DWORD WINAPI handle_client_local(LPVOID arg)
#else
static void *handle_client_local(void *arg)
#endif
{
    client_conn_t *conn = (client_conn_t *)arg;
    socket_t sock_local = conn->sock_local;
    socket_t sock_tunnel = INVALID_SOCKET;

    uint8_t c_nonce[NONCE_SIZE];
    uint8_t s_nonce[NONCE_SIZE];

    sock_tunnel = connect_remote(conn->server_host, conn->server_port);
    if (!IS_VALIDSOCK(sock_tunnel)) {
        fprintf(stderr, "[Error] Could not connect to remote tunnel server %s:%d\n",
                conn->server_host, conn->server_port);
        CLOSE_SOCK(sock_local);
        free(conn);
        return 0;
    }

    if (lk_random_bytes(c_nonce, NONCE_SIZE) != 0) {
        CLOSE_SOCK(sock_tunnel);
        CLOSE_SOCK(sock_local);
        free(conn);
        return 0;
    }

    if (write_exact(sock_tunnel, c_nonce, NONCE_SIZE) != 0) {
        CLOSE_SOCK(sock_tunnel);
        CLOSE_SOCK(sock_local);
        free(conn);
        return 0;
    }

    if (read_exact(sock_tunnel, s_nonce, NONCE_SIZE) != 0) {
        CLOSE_SOCK(sock_tunnel);
        CLOSE_SOCK(sock_local);
        free(conn);
        return 0;
    }

    uint8_t key_c2s[32];
    uint8_t key_s2c[32];
    derive_direction_key(conn->master_key, "C2S", c_nonce, key_c2s);
    derive_direction_key(conn->master_key, "S2C", s_nonce, key_s2c);

    lk_chacha20_ctx ctx_enc;
    lk_chacha20_ctx ctx_dec;
    lk_chacha20_init(&ctx_enc, key_c2s, c_nonce, 1);
    lk_chacha20_init(&ctx_dec, key_s2c, s_nonce, 1);

    uint8_t *buf_in = (uint8_t *)malloc(BUFFER_SIZE);
    uint8_t *buf_out = (uint8_t *)malloc(BUFFER_SIZE);
    if (!buf_in || !buf_out) {
        free(buf_in);
        free(buf_out);
        CLOSE_SOCK(sock_tunnel);
        CLOSE_SOCK(sock_local);
        free(conn);
        return 0;
    }

    while (1) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sock_local, &read_fds);
        FD_SET(sock_tunnel, &read_fds);

        int max_fd = (sock_local > sock_tunnel ? (int)sock_local : (int)sock_tunnel) + 1;
        int activity = select(max_fd, &read_fds, NULL, NULL, NULL);
        if (activity <= 0) break;

        if (FD_ISSET(sock_local, &read_fds)) {
            int n = recv(sock_local, (char *)buf_in, BUFFER_SIZE, 0);
            if (n <= 0) break;
            lk_chacha20_xor(&ctx_enc, buf_in, buf_in, (size_t)n);
            if (write_exact(sock_tunnel, buf_in, (size_t)n) != 0) break;
        }

        if (FD_ISSET(sock_tunnel, &read_fds)) {
            int n = recv(sock_tunnel, (char *)buf_out, BUFFER_SIZE, 0);
            if (n <= 0) break;
            lk_chacha20_xor(&ctx_dec, buf_out, buf_out, (size_t)n);
            if (write_exact(sock_local, buf_out, (size_t)n) != 0) break;
        }
    }

    free(buf_in);
    free(buf_out);
    CLOSE_SOCK(sock_tunnel);
    CLOSE_SOCK(sock_local);
    free(conn);
    return 0;
}

/* Global flag to control server/client loops (for graceful GUI stopping) */
static volatile int g_tunnel_running = 1;
static socket_t g_active_listener = INVALID_SOCKET;

static inline void stop_active_tunnel(void) {
    g_tunnel_running = 0;
    if (IS_VALIDSOCK(g_active_listener)) {
        CLOSE_SOCK(g_active_listener);
        g_active_listener = INVALID_SOCKET;
    }
}

/* Server Loop Runner */
static inline int run_tunnel_server(const char *listen_host, int listen_port,
                                    const char *target_host, int target_port,
                                    const char *key) {
    uint8_t master_key[32];
    derive_master_key(key, master_key);

    socket_t listen_sock = create_listener(listen_host, listen_port);
    if (!IS_VALIDSOCK(listen_sock)) {
        fprintf(stderr, "[Error] Failed to bind and listen on %s:%d\n", listen_host, listen_port);
        return 1;
    }

    g_active_listener = listen_sock;
    g_tunnel_running = 1;

    printf("[Livekadeh Server] Listening on %s:%d -> Forwarding to %s:%d\n",
           listen_host, listen_port, target_host, target_port);

    while (g_tunnel_running) {
        struct sockaddr_in client_addr;
#ifdef _WIN32
        int addr_len = sizeof(client_addr);
#else
        socklen_t addr_len = sizeof(client_addr);
#endif
        socket_t client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (!IS_VALIDSOCK(client_sock)) {
            if (!g_tunnel_running) break;
            continue;
        }

        set_tcp_nodelay(client_sock);

        server_conn_t *conn = (server_conn_t *)malloc(sizeof(server_conn_t));
        if (!conn) {
            CLOSE_SOCK(client_sock);
            continue;
        }

        conn->sock_tunnel = client_sock;
        snprintf(conn->target_host, sizeof(conn->target_host), "%s", target_host);
        conn->target_port = target_port;
        memcpy(conn->master_key, master_key, 32);

        if (spawn_thread(handle_server_client, conn) != 0) {
            CLOSE_SOCK(client_sock);
            free(conn);
        }
    }

    CLOSE_SOCK(listen_sock);
    return 0;
}

/* Client Loop Runner */
static inline int run_tunnel_client(const char *listen_host, int listen_port,
                                    const char *server_host, int server_port,
                                    const char *key) {
    uint8_t master_key[32];
    derive_master_key(key, master_key);

    socket_t listen_sock = create_listener(listen_host, listen_port);
    if (!IS_VALIDSOCK(listen_sock)) {
        fprintf(stderr, "[Error] Failed to bind local listener on %s:%d\n", listen_host, listen_port);
        return 1;
    }

    g_active_listener = listen_sock;
    g_tunnel_running = 1;

    printf("[Livekadeh Client] Listening on %s:%d -> Tunneling to %s:%d\n",
           listen_host, listen_port, server_host, server_port);

    while (g_tunnel_running) {
        struct sockaddr_in client_addr;
#ifdef _WIN32
        int addr_len = sizeof(client_addr);
#else
        socklen_t addr_len = sizeof(client_addr);
#endif
        socket_t local_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (!IS_VALIDSOCK(local_sock)) {
            if (!g_tunnel_running) break;
            continue;
        }

        set_tcp_nodelay(local_sock);

        client_conn_t *conn = (client_conn_t *)malloc(sizeof(client_conn_t));
        if (!conn) {
            CLOSE_SOCK(local_sock);
            continue;
        }

        conn->sock_local = local_sock;
        snprintf(conn->server_host, sizeof(conn->server_host), "%s", server_host);
        conn->server_port = server_port;
        memcpy(conn->master_key, master_key, 32);

        if (spawn_thread(handle_client_local, conn) != 0) {
            CLOSE_SOCK(local_sock);
            free(conn);
        }
    }

    CLOSE_SOCK(listen_sock);
    return 0;
}

#endif /* LIVEKADEH_TUNNEL_COMMON_H */
