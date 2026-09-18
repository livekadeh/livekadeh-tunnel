#include "tunnel_common.h"

typedef struct {
    socket_t sock_local;
    char server_host[256];
    int server_port;
    uint8_t master_key[32];
} client_conn_t;

#ifdef _WIN32
static DWORD WINAPI handle_local_conn(LPVOID arg)
#else
static void *handle_local_conn(void *arg)
#endif
{
    client_conn_t *conn = (client_conn_t *)arg;
    socket_t sock_local = conn->sock_local;
    socket_t sock_tunnel = INVALID_SOCKET;

    uint8_t c_nonce[NONCE_SIZE];
    uint8_t s_nonce[NONCE_SIZE];

    /* Step 1: Connect to remote Livekadeh server */
    sock_tunnel = connect_remote(conn->server_host, conn->server_port);
    if (!IS_VALIDSOCK(sock_tunnel)) {
        fprintf(stderr, "[Error] Could not connect to remote tunnel server %s:%d\n",
                conn->server_host, conn->server_port);
        CLOSE_SOCK(sock_local);
        free(conn);
        return 0;
    }

    /* Step 2: Generate and send client nonce */
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

    /* Step 3: Read server nonce */
    if (read_exact(sock_tunnel, s_nonce, NONCE_SIZE) != 0) {
        CLOSE_SOCK(sock_tunnel);
        CLOSE_SOCK(sock_local);
        free(conn);
        return 0;
    }

    /* Step 4: Initialize cryptographic contexts */
    uint8_t key_c2s[32];
    uint8_t key_s2c[32];
    derive_direction_key(conn->master_key, "C2S", c_nonce, key_c2s);
    derive_direction_key(conn->master_key, "S2C", s_nonce, key_s2c);

    lk_chacha20_ctx ctx_enc; /* Encrypt outgoing client-to-server traffic */
    lk_chacha20_ctx ctx_dec; /* Decrypt incoming server-to-client traffic */
    lk_chacha20_init(&ctx_enc, key_c2s, c_nonce, 1);
    lk_chacha20_init(&ctx_dec, key_s2c, s_nonce, 1);

    /* Allocate I/O buffers */
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

    /* Step 5: Full-duplex forwarding loop */
    while (1) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sock_local, &read_fds);
        FD_SET(sock_tunnel, &read_fds);

        int max_fd = (sock_local > sock_tunnel ? (int)sock_local : (int)sock_tunnel) + 1;
        int activity = select(max_fd, &read_fds, NULL, NULL, NULL);

        if (activity <= 0) {
            break;
        }

        /* Forward from local app (plain) -> tunnel (encrypted) */
        if (FD_ISSET(sock_local, &read_fds)) {
            int n = recv(sock_local, (char *)buf_in, BUFFER_SIZE, 0);
            if (n <= 0) break;

            /* Encrypt in-place */
            lk_chacha20_xor(&ctx_enc, buf_in, buf_in, (size_t)n);

            if (write_exact(sock_tunnel, buf_in, (size_t)n) != 0) {
                break;
            }
        }

        /* Forward from tunnel (encrypted) -> local app (plain) */
        if (FD_ISSET(sock_tunnel, &read_fds)) {
            int n = recv(sock_tunnel, (char *)buf_out, BUFFER_SIZE, 0);
            if (n <= 0) break;

            /* Decrypt in-place */
            lk_chacha20_xor(&ctx_dec, buf_out, buf_out, (size_t)n);

            if (write_exact(sock_local, buf_out, (size_t)n) != 0) {
                break;
            }
        }
    }

    free(buf_in);
    free(buf_out);
    CLOSE_SOCK(sock_tunnel);
    CLOSE_SOCK(sock_local);
    free(conn);
    return 0;
}

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -l, --listen <host:port>   Local listen host:port (default: 127.0.0.1:2222)\n");
    fprintf(stderr, "  -s, --server <host:port>   Remote tunnel server:port (required)\n");
    fprintf(stderr, "  -k, --key <passphrase>     Shared secret key (required)\n");
    fprintf(stderr, "  -h, --help                 Show this help message\n");
}

int main(int argc, char **argv) {
    char listen_host[256] = "127.0.0.1";
    int listen_port = 2222;
    char server_host[256] = "";
    int server_port = 8443;
    char key[512] = "";

    for (int i = 1; i < argc; ++i) {
        if ((strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--listen") == 0) && i + 1 < argc) {
            if (parse_host_port(argv[++i], listen_host, sizeof(listen_host), &listen_port) != 0) {
                fprintf(stderr, "Invalid listen address: %s\n", argv[i]);
                return 1;
            }
        } else if ((strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--server") == 0) && i + 1 < argc) {
            if (parse_host_port(argv[++i], server_host, sizeof(server_host), &server_port) != 0) {
                fprintf(stderr, "Invalid server address: %s\n", argv[i]);
                return 1;
            }
        } else if ((strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--key") == 0) && i + 1 < argc) {
            strncpy(key, argv[++i], sizeof(key) - 1);
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (strlen(server_host) == 0) {
        fprintf(stderr, "Error: Remote server (-s / --server) is required.\n");
        print_usage(argv[0]);
        return 1;
    }

    if (strlen(key) == 0) {
        fprintf(stderr, "Error: Shared secret key (-k / --key) is required.\n");
        print_usage(argv[0]);
        return 1;
    }

    net_init();

    uint8_t master_key[32];
    derive_master_key(key, master_key);

    socket_t listen_sock = create_listener(listen_host, listen_port);
    if (!IS_VALIDSOCK(listen_sock)) {
        fprintf(stderr, "Failed to bind and listen on %s:%d\n", listen_host, listen_port);
        net_cleanup();
        return 1;
    }

    printf("[Livekadeh Client] Local listener active on %s:%d -> Tunneling to %s:%d\n",
           listen_host, listen_port, server_host, server_port);

    while (1) {
        struct sockaddr_in client_addr;
#ifdef _WIN32
        int addr_len = sizeof(client_addr);
#else
        socklen_t addr_len = sizeof(client_addr);
#endif
        socket_t local_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (!IS_VALIDSOCK(local_sock)) {
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

        if (spawn_thread(handle_local_conn, conn) != 0) {
            CLOSE_SOCK(local_sock);
            free(conn);
        }
    }

    CLOSE_SOCK(listen_sock);
    net_cleanup();
    return 0;
}
