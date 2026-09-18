#ifndef LIVEKADEH_TUN_PROTO_H
#define LIVEKADEH_TUN_PROTO_H

#include "tunnel_common.h"

#ifdef _WIN32
#include "tun_wintun.h"
#else
#include "tun_linux.h"
#endif

#define MAX_PACKET_SIZE 2048

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

#ifndef _WIN32
/* Linux Server TUN Handler */
static inline int run_linux_tun_server(int listen_port, const char *key) {
    char dev[IFNAMSIZ] = "tun0";
    int tun_fd = tun_alloc_linux(dev, sizeof(dev));
    if (tun_fd < 0) return 1;

    tun_configure_linux(dev, "10.10.10.1", "10.10.10.2");

    socket_t listen_sock = create_listener("0.0.0.0", listen_port);
    if (!IS_VALIDSOCK(listen_sock)) {
        close(tun_fd);
        return 1;
    }

    printf("[Livekadeh VPN Server] TUN active on %s (10.10.10.1). Listening for clients on port %d...\n",
           dev, listen_port);

    uint8_t master_key[32];
    derive_master_key(key, master_key);

    while (g_tunnel_running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        socket_t sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (!IS_VALIDSOCK(sock)) continue;

        set_tcp_nodelay(sock);

        /* Handshake Nonce exchange */
        uint8_t c_nonce[NONCE_SIZE];
        uint8_t s_nonce[NONCE_SIZE];
        if (read_exact(sock, c_nonce, NONCE_SIZE) != 0 ||
            lk_random_bytes(s_nonce, NONCE_SIZE) != 0 ||
            write_exact(sock, s_nonce, NONCE_SIZE) != 0) {
            CLOSE_SOCK(sock);
            continue;
        }

        uint8_t key_c2s[32], key_s2c[32];
        derive_direction_key(master_key, "C2S", c_nonce, key_c2s);
        derive_direction_key(master_key, "S2C", s_nonce, key_s2c);

        lk_chacha20_ctx ctx_rx, ctx_tx;
        lk_chacha20_init(&ctx_rx, key_c2s, c_nonce, 1);
        lk_chacha20_init(&ctx_tx, key_s2c, s_nonce, 1);

        printf("[Livekadeh VPN Server] Client connected from %s! Tunneling L3 packets...\n",
               inet_ntoa(client_addr.sin_addr));

        uint8_t buf[MAX_PACKET_SIZE];

        while (g_tunnel_running) {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(sock, &read_fds);
            FD_SET(tun_fd, &read_fds);

            int max_fd = (sock > tun_fd ? (int)sock : tun_fd) + 1;
            int act = select(max_fd, &read_fds, NULL, NULL, NULL);
            if (act <= 0) break;

            /* Socket -> TUN */
            if (FD_ISSET(sock, &read_fds)) {
                uint16_t plen = 0;
                if (recv_tun_packet(sock, &ctx_rx, buf, &plen) != 0) break;
                if (write(tun_fd, buf, plen) != (ssize_t)plen) break;
            }

            /* TUN -> Socket */
            if (FD_ISSET(tun_fd, &read_fds)) {
                ssize_t n = read(tun_fd, buf, sizeof(buf));
                if (n <= 0) break;
                if (send_tun_packet(sock, &ctx_tx, buf, (uint16_t)n) != 0) break;
            }
        }

        printf("[Livekadeh VPN Server] Client disconnected.\n");
        CLOSE_SOCK(sock);
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
    char app_path[MAX_PATH];
} win_tun_client_params_t;

static DWORD WINAPI win_tun_client_thread(LPVOID arg) {
    win_tun_client_params_t *p = (win_tun_client_params_t *)arg;

    if (wintun_load_dll() != 0) {
        free(p);
        return 1;
    }

    /* Create Wintun adapter */
    WINTUN_ADAPTER_HANDLE adapter = pWintunCreateAdapter(L"LivekadehAdapter", L"Livekadeh", NULL);
    if (!adapter) {
        adapter = pWintunOpenAdapter(L"LivekadehAdapter");
        if (!adapter) {
            fprintf(stderr, "[Error] Failed to create or open Wintun adapter. Run as Administrator!\n");
            free(p);
            return 1;
        }
    }

    /* Configure IP 10.10.10.2 / Gateway 10.10.10.1 / DNS 1.1.1.1 */
    wintun_configure_ip("LivekadehAdapter", "10.10.10.2", "10.10.10.1", "1.1.1.1");

    /* Setup WFP Per-App if requested */
    if (strlen(p->app_path) > 0) {
        wfp_setup_per_app(p->app_path, "10.10.10.2");
    }

    WINTUN_SESSION_HANDLE session = pWintunStartSession(adapter, 0x400000);
    if (!session) {
        fprintf(stderr, "[Error] Failed to start Wintun session.\n");
        pWintunCloseAdapter(adapter);
        free(p);
        return 1;
    }

    socket_t sock = connect_remote(p->server_host, p->server_port);
    if (!IS_VALIDSOCK(sock)) {
        fprintf(stderr, "[Error] Could not connect to VPN server %s:%d\n", p->server_host, p->server_port);
        pWintunEndSession(session);
        pWintunCloseAdapter(adapter);
        free(p);
        return 1;
    }

    uint8_t master_key[32];
    derive_master_key(p->key, master_key);

    /* Handshake Nonce exchange */
    uint8_t c_nonce[NONCE_SIZE], s_nonce[NONCE_SIZE];
    if (lk_random_bytes(c_nonce, NONCE_SIZE) != 0 ||
        write_exact(sock, c_nonce, NONCE_SIZE) != 0 ||
        read_exact(sock, s_nonce, NONCE_SIZE) != 0) {
        CLOSE_SOCK(sock);
        pWintunEndSession(session);
        pWintunCloseAdapter(adapter);
        free(p);
        return 1;
    }

    uint8_t key_c2s[32], key_s2c[32];
    derive_direction_key(master_key, "C2S", c_nonce, key_c2s);
    derive_direction_key(master_key, "S2C", s_nonce, key_s2c);

    lk_chacha20_ctx ctx_tx, ctx_rx;
    lk_chacha20_init(&ctx_tx, key_c2s, c_nonce, 1);
    lk_chacha20_init(&ctx_rx, key_s2c, s_nonce, 1);

    HANDLE read_wait = pWintunGetReadWaitEvent(session);
    printf("[Livekadeh VPN Client] Connected to %s:%d! Wintun L3 streaming active.\n",
           p->server_host, p->server_port);

    uint8_t recv_buf[MAX_PACKET_SIZE];

    while (g_tunnel_running) {
        /* Check for inbound packet from server socket */
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);
        struct timeval tv = { 0, 5000 }; /* 5ms timeout */

        int act = select((int)sock + 1, &read_fds, NULL, NULL, &tv);
        if (act > 0 && FD_ISSET(sock, &read_fds)) {
            uint16_t plen = 0;
            if (recv_tun_packet(sock, &ctx_rx, recv_buf, &plen) != 0) break;

            BYTE *out_pkt = pWintunAllocateSendPacket(session, (DWORD)plen);
            if (out_pkt) {
                memcpy(out_pkt, recv_buf, plen);
                pWintunSendPacket(session, out_pkt);
            }
        }

        /* Check for outbound packets from Wintun */
        DWORD packet_size = 0;
        BYTE *packet = pWintunReceivePacket(session, &packet_size);
        if (packet) {
            send_tun_packet(sock, &ctx_tx, packet, (uint16_t)packet_size);
            pWintunReleaseReceivePacket(session, packet);
        } else {
            WaitForSingleObject(read_wait, 5);
        }
    }

    printf("[Livekadeh VPN Client] Stopped.\n");
    wfp_cleanup();
    CLOSE_SOCK(sock);
    pWintunEndSession(session);
    pWintunCloseAdapter(adapter);
    free(p);
    return 0;
}
#endif

#endif /* LIVEKADEH_TUN_PROTO_H */

