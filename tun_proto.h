#ifndef LIVEKADEH_TUN_PROTO_H
#define LIVEKADEH_TUN_PROTO_H

#include "tunnel_common.h"

#ifdef _WIN32
#include "tun_wintun.h"
#else
#include "tun_linux.h"
#endif

#define MAX_PACKET_SIZE 2048

volatile uint64_t g_traffic_tx_bytes = 0;
volatile uint64_t g_traffic_rx_bytes = 0;

/* Send length-prefixed encrypted packet */
static inline int send_tun_packet(socket_t sock, lk_chacha20_ctx *ctx, const uint8_t *packet, uint16_t len) {
    if (len == 0 || len > MAX_PACKET_SIZE) return -1;

    uint8_t buffer[MAX_PACKET_SIZE + 2];
    buffer[0] = (uint8_t)(len >> 8);
    buffer[1] = (uint8_t)(len & 0xFF);

    lk_chacha20_xor(ctx, packet, buffer + 2, len);

    return write_exact(sock, buffer, (size_t)len + 2);
}

/* Receive length-prefixed encrypted packet */
static inline int recv_tun_packet(socket_t sock, lk_chacha20_ctx *ctx, uint8_t *packet, uint16_t *out_len) {
    uint8_t hdr[2];
    if (read_exact(sock, hdr, 2) != 0) return -1;

    uint16_t len = ((uint16_t)hdr[0] << 8) | (uint16_t)hdr[1];
    if (len == 0 || len > MAX_PACKET_SIZE) return -1;

    if (read_exact(sock, packet, len) != 0) return -1;

    lk_chacha20_xor(ctx, packet, packet, len);
    *out_len = len;
    return 0;
}

#define SPEEDTEST_PORT 9090

#ifndef _WIN32
static void *speedtest_server_worker(void *arg) {
    socket_t csock = (socket_t)(intptr_t)arg;
    tune_tunnel_socket(csock);
    char cmd[64] = "";
    int r = recv(csock, cmd, sizeof(cmd) - 1, 0);
    if (r > 0) {
        cmd[r] = '\0';
        if (strncmp(cmd, "PING", 4) == 0) {
            send(csock, "PONG\n", 5, 0);
        } else if (strncmp(cmd, "DOWNLOAD", 8) == 0) {
            uint8_t dummy[65536];
            memset(dummy, 0x5A, sizeof(dummy));
            struct timespec ts_start, ts_now;
            clock_gettime(CLOCK_MONOTONIC, &ts_start);
            while (g_tunnel_running) {
                clock_gettime(CLOCK_MONOTONIC, &ts_now);
                long elapsed_ms = (ts_now.tv_sec - ts_start.tv_sec) * 1000 + (ts_now.tv_nsec - ts_start.tv_nsec) / 1000000;
                if (elapsed_ms >= 3500) break;
                if (send(csock, (const char *)dummy, sizeof(dummy), 0) <= 0) break;
            }
        } else if (strncmp(cmd, "UPLOAD", 6) == 0) {
            uint8_t dummy[65536];
            while (g_tunnel_running && recv(csock, (char *)dummy, sizeof(dummy), 0) > 0) {}
        }
    }
    CLOSE_SOCK(csock);
    return NULL;
}

static void *speedtest_server_thread(void *arg) {
    (void)arg;
    socket_t s = create_listener("0.0.0.0", SPEEDTEST_PORT);
    if (!IS_VALIDSOCK(s)) return NULL;

    while (g_tunnel_running) {
        struct sockaddr_in caddr;
        socklen_t clen = sizeof(caddr);
        socket_t csock = accept(s, (struct sockaddr *)&caddr, &clen);
        if (!IS_VALIDSOCK(csock)) continue;

        pthread_t tid;
        if (pthread_create(&tid, NULL, speedtest_server_worker, (void *)(intptr_t)csock) == 0) {
            pthread_detach(tid);
        } else {
            CLOSE_SOCK(csock);
        }
    }
    CLOSE_SOCK(s);
    return NULL;
}

/* Linux Server TUN Handler */
static inline int run_linux_tun_server(int listen_port, const char *key) {
    char dev[IFNAMSIZ] = "tun0";
    int tun_fd = tun_alloc_linux(dev, sizeof(dev));
    if (tun_fd < 0) return 1;

    tun_configure_linux(dev, "10.10.10.1", "10.10.10.2");

    pthread_t st_tid;
    if (pthread_create(&st_tid, NULL, speedtest_server_thread, NULL) == 0) {
        pthread_detach(st_tid);
    }

    socket_t listen_sock = create_listener("0.0.0.0", listen_port);
    if (!IS_VALIDSOCK(listen_sock)) {
        close(tun_fd);
        return 1;
    }

    FILE *fk = fopen("/etc/livekadeh_tunnel.key", "w");
    if (!fk) fk = fopen("/tmp/livekadeh_tunnel.key", "w");
    if (fk) {
        fprintf(fk, "%s\n", key);
        fclose(fk);
    }

    printf("\n==================================================================\n");
    printf("       Livekadeh Tunnel Server (v%s)\n", LIVEKADEH_VERSION);
    printf("==================================================================\n");
    printf(" [TUN] Device:        %s (10.10.10.1 <-> 10.10.10.2)\n", dev);
    printf(" [TCP] Listen Port:   %d\n", listen_port);
    printf(" [SEC] Server Key:    %s\n", key);
    printf("==================================================================\n\n");

    uint8_t master_key[32];
    derive_master_key(key, master_key);

    while (g_tunnel_running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        socket_t sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (!IS_VALIDSOCK(sock)) continue;

        set_tcp_nodelay(sock);

        /* Set 3-second receive timeout for handshake authentication */
        struct timeval tv_auth = { 3, 0 };
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv_auth, sizeof(tv_auth));

        uint8_t c_nonce[AUTH_NONCE_SIZE];
        uint8_t s_nonce[AUTH_NONCE_SIZE];
        char client_version[64] = "unknown";

        int auth_res = server_authenticate(sock, master_key, c_nonce, s_nonce, client_version, sizeof(client_version));
        if (auth_res != 0) {
            printf("[Livekadeh VPN Server] Unauthorized probe or invalid key from %s (Rejected)\n",
                   inet_ntoa(client_addr.sin_addr));
            CLOSE_SOCK(sock);
            continue;
        }

        /* Reset receive timeout to 0 (normal blocking operation) and tune socket */
        struct timeval tv_zero = { 0, 0 };
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv_zero, sizeof(tv_zero));
        tune_tunnel_socket(sock);

        socket_t client_socks[NUM_TUNNEL_CONNS];
        client_socks[0] = sock;
        int num_conns = 1;

        /* Accept auxiliary connection lanes (up to NUM_TUNNEL_CONNS) within a 1-second window */
        while (num_conns < NUM_TUNNEL_CONNS) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(listen_sock, &rfds);
            struct timeval tv = { 0, 400000 }; /* 400ms per check */
            int r = select((int)listen_sock + 1, &rfds, NULL, NULL, &tv);
            if (r <= 0) break;

            struct sockaddr_in aux_addr;
            socklen_t aux_len = sizeof(aux_addr);
            socket_t aux_sock = accept(listen_sock, (struct sockaddr *)&aux_addr, &aux_len);
            if (!IS_VALIDSOCK(aux_sock)) break;

            struct timeval to = { 1, 0 };
            setsockopt(aux_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof(to));

            uint8_t attach_buf[ATTACH_PACKET_SIZE];
            if (read_exact(aux_sock, attach_buf, ATTACH_PACKET_SIZE) != 0) {
                CLOSE_SOCK(aux_sock);
                continue;
            }

            uint8_t req_c_nonce[AUTH_NONCE_SIZE];
            uint8_t lane_idx = 0;
            if (verify_attach_packet(master_key, attach_buf, req_c_nonce, &lane_idx) != 0 ||
                memcmp(req_c_nonce, c_nonce, AUTH_NONCE_SIZE) != 0 ||
                lane_idx != (uint8_t)num_conns) {
                CLOSE_SOCK(aux_sock);
                continue;
            }

            /* Send attach ACK */
            uint8_t ack_pkt[ATTACH_PACKET_SIZE];
            memset(ack_pkt, 0, sizeof(ack_pkt));
            memcpy(ack_pkt, s_nonce, AUTH_NONCE_SIZE);
            ack_pkt[AUTH_NONCE_SIZE] = lane_idx;
            compute_auth_tag(master_key, "LK-ATTACH-OK", ack_pkt, ack_pkt + AUTH_NONCE_SIZE + 16);
            if (write_exact(aux_sock, ack_pkt, ATTACH_PACKET_SIZE) != 0) {
                CLOSE_SOCK(aux_sock);
                continue;
            }

            setsockopt(aux_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv_zero, sizeof(tv_zero));
            tune_tunnel_socket(aux_sock);

            client_socks[num_conns++] = aux_sock;
        }

        uint8_t key_c2s[32], key_s2c[32];
        derive_direction_key(master_key, "C2S", c_nonce, key_c2s);
        derive_direction_key(master_key, "S2C", s_nonce, key_s2c);

        lk_chacha20_ctx ctx_rx[NUM_TUNNEL_CONNS], ctx_tx[NUM_TUNNEL_CONNS];
        for (int i = 0; i < num_conns; i++) {
            uint8_t lane_c_nonce[16], lane_s_nonce[16];
            memcpy(lane_c_nonce, c_nonce, 16);
            memcpy(lane_s_nonce, s_nonce, 16);
            lane_c_nonce[15] ^= (uint8_t)i;
            lane_s_nonce[15] ^= (uint8_t)i;

            lk_chacha20_init(&ctx_rx[i], key_c2s, lane_c_nonce, 1);
            lk_chacha20_init(&ctx_tx[i], key_s2c, lane_s_nonce, 1);
        }

        printf("[Livekadeh VPN Server] Client (v%s) authenticated from %s! Multi-TCP active with %d lanes.\n",
               client_version, inet_ntoa(client_addr.sin_addr), num_conns);

        uint8_t buf[MAX_PACKET_SIZE];

        while (g_tunnel_running) {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(tun_fd, &read_fds);
            int max_fd = (int)tun_fd;

            for (int i = 0; i < num_conns; i++) {
                FD_SET(client_socks[i], &read_fds);
                if ((int)client_socks[i] > max_fd) max_fd = (int)client_socks[i];
            }

            int act = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
            if (act <= 0) break;

            /* Inbound: Sockets -> TUN */
            int client_alive = 1;
            for (int i = 0; i < num_conns; i++) {
                if (FD_ISSET(client_socks[i], &read_fds)) {
                    uint16_t plen = 0;
                    if (recv_tun_packet(client_socks[i], &ctx_rx[i], buf, &plen) != 0) {
                        client_alive = 0;
                        break;
                    }
                    if (write(tun_fd, buf, plen) != (ssize_t)plen) {
                        client_alive = 0;
                        break;
                    }
                    g_traffic_rx_bytes += plen;
                }
            }
            if (!client_alive) break;

            /* Outbound: TUN -> Sockets (5-Tuple Flow Hashed) */
            if (FD_ISSET(tun_fd, &read_fds)) {
                ssize_t n = read(tun_fd, buf, sizeof(buf));
                if (n <= 0) break;
                int lane = (int)(flow_hash_packet(buf, (size_t)n) % (uint32_t)num_conns);
                if (send_tun_packet(client_socks[lane], &ctx_tx[lane], buf, (uint16_t)n) != 0) break;
                g_traffic_tx_bytes += (uint64_t)n;
            }
        }

        printf("[Livekadeh VPN Server] Client disconnected.\n");
        for (int i = 0; i < num_conns; i++) {
            CLOSE_SOCK(client_socks[i]);
        }
    }

    CLOSE_SOCK(listen_sock);
    close(tun_fd);
    return 0;
}
#endif

#ifdef _WIN32
/* Windows Client Wintun & Per-App Worker */
typedef struct {
    char server_host[256];
    int server_port;
    char key[512];
    int is_per_app;
    int num_apps;
    char app_paths[MAX_PER_APPS][MAX_PATH];
    int max_conns;
} win_tun_client_params_t;

/* Forward declaration of log_append from gui_win32.h */
void log_append(int level, const char *format, ...);

static DWORD WINAPI win_tun_client_thread(LPVOID arg) {
    win_tun_client_params_t *p = (win_tun_client_params_t *)arg;
    g_tunnel_running = 1;
    g_traffic_tx_bytes = 0;
    g_traffic_rx_bytes = 0;

    /* Step 1: Connect to remote VPN server */
    log_append(1 /* INFO */, "Connecting to tunnel server %s:%d...", p->server_host, p->server_port);
    socket_t sock = connect_remote(p->server_host, p->server_port);
    if (!IS_VALIDSOCK(sock)) {
        log_append(3 /* ERROR */, "Cannot connect to server %s:%d. Verify IP, port, and firewall.",
                   p->server_host, p->server_port);
        free(p);
        return 1;
    }

    uint8_t master_key[32];
    derive_master_key(p->key, master_key);

    /* Step 2: Perform cryptographic mutual authentication */
    log_append(0 /* DEBUG */, "Sending challenge authentication probe...");
    uint8_t c_nonce[AUTH_NONCE_SIZE], s_nonce[AUTH_NONCE_SIZE];
    char server_version[64] = "unknown";
    int auth_res = client_authenticate(sock, master_key, c_nonce, s_nonce, server_version, sizeof(server_version));

    if (auth_res == -2) {
        log_append(3 /* ERROR */, "AUTHENTICATION FAILED: INVALID ENCRYPTION KEY! Server rejected connection.");
        CLOSE_SOCK(sock);
        free(p);
        return 1;
    } else if (auth_res != 0) {
        log_append(3 /* ERROR */, "Handshake timed out or connection dropped by server.");
        CLOSE_SOCK(sock);
        free(p);
        return 1;
    }

    log_append(1 /* INFO */, "Connected to Livekadeh Tunnel Server v%s! Authentication verified.", server_version);

    /* Step 2.5: Establish Multi-TCP connection pool (if requested) */
    tune_tunnel_socket(sock);
    socket_t socks[NUM_TUNNEL_CONNS];
    socks[0] = sock;
    int num_conns = 1;

    int target_conns = (p->max_conns > 0) ? p->max_conns : NUM_TUNNEL_CONNS;
    if (target_conns > NUM_TUNNEL_CONNS) target_conns = NUM_TUNNEL_CONNS;

    if (target_conns > 1) {
        log_append(1 /* INFO */, "Establishing %d-Lane Multi-TCP connection pool...", target_conns);

        for (int i = 1; i < target_conns; i++) {
            socket_t s_aux = connect_remote(p->server_host, p->server_port);
            if (!IS_VALIDSOCK(s_aux)) break;

            DWORD to = 2000;
            setsockopt(s_aux, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof(to));

            uint8_t attach_buf[ATTACH_PACKET_SIZE];
            make_attach_packet(master_key, c_nonce, (uint8_t)i, attach_buf);
            if (write_exact(s_aux, attach_buf, ATTACH_PACKET_SIZE) != 0) {
                CLOSE_SOCK(s_aux);
                break;
            }

            uint8_t ack_buf[ATTACH_PACKET_SIZE];
            if (read_exact(s_aux, ack_buf, ATTACH_PACKET_SIZE) != 0) {
                CLOSE_SOCK(s_aux);
                break;
            }

            uint8_t exp_tag[AUTH_TAG_SIZE];
            uint8_t exp_data[ATTACH_PACKET_SIZE];
            memset(exp_data, 0, sizeof(exp_data));
            memcpy(exp_data, s_nonce, AUTH_NONCE_SIZE);
            exp_data[AUTH_NONCE_SIZE] = (uint8_t)i;
            compute_auth_tag(master_key, "LK-ATTACH-OK", exp_data, exp_tag);

            if (memcmp(ack_buf + AUTH_NONCE_SIZE + 16, exp_tag, AUTH_TAG_SIZE) != 0) {
                CLOSE_SOCK(s_aux);
                break;
            }

            DWORD to_zero = 0;
            setsockopt(s_aux, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to_zero, sizeof(to_zero));
            tune_tunnel_socket(s_aux);

            socks[num_conns++] = s_aux;
        }

        log_append(1 /* INFO */, "Multi-TCP active! %d parallel lanes connected with 5-tuple flow hashing.", num_conns);
    } else {
        log_append(1 /* INFO */, "Single-TCP mode active (1 connection).");
    }

    /* Step 3: Initialize Wintun adapter */
    if (wintun_load_dll() != 0) {
        log_append(3 /* ERROR */, "Failed to load wintun.dll! Make sure wintun.dll is in the same folder.");
        for (int i = 0; i < num_conns; i++) CLOSE_SOCK(socks[i]);
        free(p);
        return 1;
    }

    WINTUN_ADAPTER_HANDLE adapter = pWintunCreateAdapter(L"LivekadehAdapter", L"Livekadeh", NULL);
    if (!adapter) {
        adapter = pWintunOpenAdapter(L"LivekadehAdapter");
        if (!adapter) {
            log_append(3 /* ERROR */, "Cannot create or open Wintun adapter. Ensure running as Administrator!");
            for (int i = 0; i < num_conns; i++) CLOSE_SOCK(socks[i]);
            free(p);
            return 1;
        }
    }

    /* Configure IP 10.10.10.2 and default internet routes through Wintun */
    log_append(1 /* INFO */, "Configuring adapter IP 10.10.10.2 and routing traffic through tunnel...");
    wintun_configure_ip("LivekadehAdapter", "10.10.10.2", "255.255.255.0", p->server_host);

    /* Setup WFP Per-App if requested */
    if (p->is_per_app && p->num_apps > 0) {
        log_append(1 /* INFO */, "Configuring WFP Per-App routing for %d applications...", p->num_apps);
        for (int i = 0; i < p->num_apps; i++) {
            log_append(0 /* DEBUG */, "  -> App: %s", p->app_paths[i]);
        }
        wfp_setup_per_apps((const char (*)[MAX_PATH])p->app_paths, p->num_apps, "10.10.10.2");
    }

    WINTUN_SESSION_HANDLE session = pWintunStartSession(adapter, 0x400000);
    if (!session) {
        log_append(3 /* ERROR */, "Failed to start Wintun session.");
        wintun_cleanup_routes("LivekadehAdapter", p->server_host);
        pWintunCloseAdapter(adapter);
        for (int i = 0; i < num_conns; i++) CLOSE_SOCK(socks[i]);
        free(p);
        return 1;
    }

    uint8_t key_c2s[32], key_s2c[32];
    derive_direction_key(master_key, "C2S", c_nonce, key_c2s);
    derive_direction_key(master_key, "S2C", s_nonce, key_s2c);

    lk_chacha20_ctx ctx_tx[NUM_TUNNEL_CONNS], ctx_rx[NUM_TUNNEL_CONNS];
    for (int i = 0; i < num_conns; i++) {
        uint8_t lane_c_nonce[16], lane_s_nonce[16];
        memcpy(lane_c_nonce, c_nonce, 16);
        memcpy(lane_s_nonce, s_nonce, 16);
        lane_c_nonce[15] ^= (uint8_t)i;
        lane_s_nonce[15] ^= (uint8_t)i;

        lk_chacha20_init(&ctx_tx[i], key_c2s, lane_c_nonce, 1);
        lk_chacha20_init(&ctx_rx[i], key_s2c, lane_s_nonce, 1);
    }

    HANDLE read_wait = pWintunGetReadWaitEvent(session);
    log_append(1 /* INFO */, "Tunnel active! All traffic encrypted and routed via 10.10.10.1.");
    log_append(1 /* INFO */, "Test in browser (whatismyip) or 'ping 10.10.10.1'");

    uint8_t recv_buf[MAX_PACKET_SIZE];

    while (g_tunnel_running) {
        /* Check for inbound packets from any of the Multi-TCP sockets */
        fd_set read_fds;
        FD_ZERO(&read_fds);
        int max_fd = 0;
        for (int i = 0; i < num_conns; i++) {
            FD_SET(socks[i], &read_fds);
            if ((int)socks[i] > max_fd) max_fd = (int)socks[i];
        }

        struct timeval tv = { 0, 5000 }; /* 5ms timeout */
        int act = select(max_fd + 1, &read_fds, NULL, NULL, &tv);

        int conn_drop = 0;
        if (act > 0) {
            for (int i = 0; i < num_conns; i++) {
                if (FD_ISSET(socks[i], &read_fds)) {
                    uint16_t plen = 0;
                    if (recv_tun_packet(socks[i], &ctx_rx[i], recv_buf, &plen) != 0) {
                        conn_drop = 1;
                        break;
                    }
                    BYTE *out_pkt = pWintunAllocateSendPacket(session, (DWORD)plen);
                    if (out_pkt) {
                        memcpy(out_pkt, recv_buf, plen);
                        pWintunSendPacket(session, out_pkt);
                        g_traffic_rx_bytes += plen;
                    }
                }
            }
        }
        if (conn_drop) {
            log_append(2 /* WARN */, "Server stream interrupted or connection dropped.");
            break;
        }

        /* Outbound from Wintun (5-Tuple Flow Hashed across lanes) */
        DWORD packet_size = 0;
        BYTE *packet = pWintunReceivePacket(session, &packet_size);
        if (packet) {
            int lane = (int)(flow_hash_packet(packet, (size_t)packet_size) % (uint32_t)num_conns);
            send_tun_packet(socks[lane], &ctx_tx[lane], packet, (uint16_t)packet_size);
            g_traffic_tx_bytes += packet_size;
            pWintunReleaseReceivePacket(session, packet);
        } else {
            WaitForSingleObject(read_wait, 5);
        }
    }

    log_append(1 /* INFO */, "Tunnel disconnected.");
    wintun_cleanup_routes("LivekadehAdapter", p->server_host);
    wfp_cleanup();
    for (int i = 0; i < num_conns; i++) {
        CLOSE_SOCK(socks[i]);
    }
    pWintunEndSession(session);
    pWintunCloseAdapter(adapter);
    free(p);

    extern HWND g_hMainWnd;
    if (g_hMainWnd) {
        PostMessage(g_hMainWnd, WM_USER + 200, 0, 0);
    }
    return 0;
}
#endif

#endif /* LIVEKADEH_TUN_PROTO_H */
