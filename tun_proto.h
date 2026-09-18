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

#define UDP_MAGIC_REQ "LK-UDP-REQ"
#define UDP_MAGIC_ACK "LK-UDP-ACK"
#define UDP_REQ_LEN   (10 + 16 + 32)      /* 58 bytes: Magic(10) + Nonce(16) + Tag(32) */
#define UDP_ACK_LEN   (10 + 16 + 32 + 32) /* 90 bytes: Magic(10) + Nonce(16) + Tag(32) + Ver(32) */
#define UDP_SALT_SIZE 4
#define UDP_SEQ_SIZE  8
#define UDP_HDR_SIZE  (UDP_SALT_SIZE + UDP_SEQ_SIZE) /* 12 bytes */
#define UDP_PING_MAGIC 0xFFFFFFFD

#ifndef _WIN32
#define MAX_TUN_CLIENTS 256
#define CLIENT_IP_START 2
#define CLIENT_IP_END   254

typedef enum {
    CLIENT_TYPE_NONE = 0,
    CLIENT_TYPE_TCP,
    CLIENT_TYPE_UDP
} client_type_t;

typedef struct {
    int active;
    client_type_t type;
    uint8_t ip_host;
    time_t last_seen;
    char client_version[32];
    char remote_ip[64];
    int remote_port;

    /* Multi-TCP lanes */
    int num_conns;
    socket_t socks[NUM_TUNNEL_CONNS];
    lk_chacha20_ctx ctx_tx[NUM_TUNNEL_CONNS];
    lk_chacha20_ctx ctx_rx[NUM_TUNNEL_CONNS];
    uint8_t c_nonce[AUTH_NONCE_SIZE];
    uint8_t s_nonce[AUTH_NONCE_SIZE];

    /* UDP datagram */
    struct sockaddr_in udp_addr;
    uint32_t udp_tx_salt;
    uint64_t udp_tx_seq;
} tun_client_session_t;

static tun_client_session_t g_clients[MAX_TUN_CLIENTS];
static pthread_mutex_t g_sessions_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_tun_write_lock = PTHREAD_MUTEX_INITIALIZER;
static socket_t g_server_udp_sock = -1;
static uint8_t g_server_master_key[32];

static inline void update_clients_file(void) {
    FILE *f = fopen("/tmp/livekadeh_clients.txt", "w");
    if (!f) return;
    pthread_mutex_lock(&g_sessions_lock);
    for (int i = CLIENT_IP_START; i <= CLIENT_IP_END; i++) {
        if (g_clients[i].active) {
            if (g_clients[i].type == CLIENT_TYPE_TCP) {
                fprintf(f, "10.10.10.%d [TCP %d-Lanes] %s:%d (v%s)\n",
                        i, g_clients[i].num_conns, g_clients[i].remote_ip, g_clients[i].remote_port,
                        g_clients[i].client_version);
            } else if (g_clients[i].type == CLIENT_TYPE_UDP) {
                fprintf(f, "10.10.10.%d [UDP] %s:%d\n",
                        i, g_clients[i].remote_ip, g_clients[i].remote_port);
            }
        }
    }
    pthread_mutex_unlock(&g_sessions_lock);
    fclose(f);
}

static inline uint8_t alloc_client_ip(void) {
    pthread_mutex_lock(&g_sessions_lock);
    for (int i = CLIENT_IP_START; i <= CLIENT_IP_END; i++) {
        if (!g_clients[i].active) {
            memset(&g_clients[i], 0, sizeof(tun_client_session_t));
            g_clients[i].active = 1;
            g_clients[i].ip_host = (uint8_t)i;
            g_clients[i].last_seen = time(NULL);
            pthread_mutex_unlock(&g_sessions_lock);
            return (uint8_t)i;
        }
    }
    pthread_mutex_unlock(&g_sessions_lock);
    return 0;
}

static inline void free_client_ip(uint8_t ip_host) {
    if (ip_host < CLIENT_IP_START || ip_host > CLIENT_IP_END) return;
    pthread_mutex_lock(&g_sessions_lock);
    if (g_clients[ip_host].active) {
        g_clients[ip_host].active = 0;
    }
    pthread_mutex_unlock(&g_sessions_lock);
    update_clients_file();
}

/* Outbound Router: reads from tun_fd and routes packets by destination IP */
static void *linux_tun_outbound_router_thread(void *arg) {
    int tun_fd = (int)(intptr_t)arg;
    uint8_t buf[MAX_PACKET_SIZE];

    while (g_tunnel_running) {
        ssize_t n = read(tun_fd, buf, sizeof(buf));
        if (n <= 0) continue;
        if (n < 20) continue;

        if (buf[16] == 10 && buf[17] == 10 && buf[18] == 10) {
            uint8_t dst_host = buf[19];
            if (dst_host >= CLIENT_IP_START && dst_host <= CLIENT_IP_END) {
                pthread_mutex_lock(&g_sessions_lock);
                if (g_clients[dst_host].active) {
                    if (g_clients[dst_host].type == CLIENT_TYPE_TCP) {
                        int num_c = g_clients[dst_host].num_conns;
                        if (num_c > 0) {
                            int lane = (int)(flow_hash_packet(buf, (size_t)n) % (uint32_t)num_c);
                            send_tun_packet(g_clients[dst_host].socks[lane], &g_clients[dst_host].ctx_tx[lane], buf, (uint16_t)n);
                            g_traffic_tx_bytes += (uint64_t)n;
                        }
                    } else if (g_clients[dst_host].type == CLIENT_TYPE_UDP && IS_VALIDSOCK(g_server_udp_sock)) {
                        uint64_t seq = ++g_clients[dst_host].udp_tx_seq;
                        uint32_t salt = g_clients[dst_host].udp_tx_salt;
                        uint8_t out[MAX_PACKET_SIZE + UDP_HDR_SIZE];
                        memcpy(out, &salt, 4);
                        memcpy(out + 4, &seq, 8);
                        uint8_t nonce[12];
                        memcpy(nonce, out, 12);
                        lk_chacha20_crypt_packet(g_server_master_key, nonce, 0, buf, out + UDP_HDR_SIZE, (size_t)n);
                        sendto(g_server_udp_sock, (const char *)out, (size_t)n + UDP_HDR_SIZE, 0,
                               (struct sockaddr *)&g_clients[dst_host].udp_addr, sizeof(struct sockaddr_in));
                        g_traffic_tx_bytes += (uint64_t)n;
                    }
                }
                pthread_mutex_unlock(&g_sessions_lock);
            }
        }
    }
    return NULL;
}

/* Worker thread servicing inbound traffic from a connected TCP client */
typedef struct {
    int tun_fd;
    uint8_t ip_host;
} tcp_worker_param_t;

static void *linux_tcp_client_worker(void *arg) {
    tcp_worker_param_t *p = (tcp_worker_param_t *)arg;
    int tun_fd = p->tun_fd;
    uint8_t ip_host = p->ip_host;
    free(p);

    uint8_t buf[MAX_PACKET_SIZE];

    while (g_tunnel_running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        int max_fd = 0;
        int num_c = 0;
        socket_t socks[NUM_TUNNEL_CONNS];

        pthread_mutex_lock(&g_sessions_lock);
        if (!g_clients[ip_host].active) {
            pthread_mutex_unlock(&g_sessions_lock);
            break;
        }
        num_c = g_clients[ip_host].num_conns;
        for (int i = 0; i < num_c; i++) {
            socks[i] = g_clients[ip_host].socks[i];
            FD_SET(socks[i], &rfds);
            if ((int)socks[i] > max_fd) max_fd = (int)socks[i];
        }
        pthread_mutex_unlock(&g_sessions_lock);

        struct timeval tv = { 1, 0 };
        int act = select(max_fd + 1, &rfds, NULL, NULL, &tv);
        if (act < 0) break;
        if (act == 0) continue;

        int drop = 0;
        for (int i = 0; i < num_c; i++) {
            if (FD_ISSET(socks[i], &rfds)) {
                uint16_t plen = 0;
                pthread_mutex_lock(&g_sessions_lock);
                lk_chacha20_ctx *p_ctx = &g_clients[ip_host].ctx_rx[i];
                int r = recv_tun_packet(socks[i], p_ctx, buf, &plen);
                pthread_mutex_unlock(&g_sessions_lock);
                if (r != 0) {
                    drop = 1;
                    break;
                }
                pthread_mutex_lock(&g_tun_write_lock);
                if (write(tun_fd, buf, plen) > 0) {
                    g_traffic_rx_bytes += plen;
                }
                pthread_mutex_unlock(&g_tun_write_lock);

                pthread_mutex_lock(&g_sessions_lock);
                if (g_clients[ip_host].active) {
                    g_clients[ip_host].last_seen = time(NULL);
                }
                pthread_mutex_unlock(&g_sessions_lock);
            }
        }
        if (drop) break;
    }

    pthread_mutex_lock(&g_sessions_lock);
    if (g_clients[ip_host].active) {
        printf("[Livekadeh VPN Server] TCP Client 10.10.10.%d disconnected from %s:%d\n",
               ip_host, g_clients[ip_host].remote_ip, g_clients[ip_host].remote_port);
        for (int i = 0; i < g_clients[ip_host].num_conns; i++) {
            CLOSE_SOCK(g_clients[ip_host].socks[i]);
        }
        g_clients[ip_host].active = 0;
    }
    pthread_mutex_unlock(&g_sessions_lock);
    update_clients_file();

    return NULL;
}

typedef struct {
    int tun_fd;
    socket_t udp_sock;
    uint8_t master_key[32];
} linux_udp_args_t;

static void *linux_tun_udp_server_thread(void *arg) {
    linux_udp_args_t *a = (linux_udp_args_t *)arg;
    int tun_fd = a->tun_fd;
    socket_t s = a->udp_sock;
    uint8_t master_key[32];
    memcpy(master_key, a->master_key, 32);
    free(a);

    uint8_t buf[MAX_PACKET_SIZE + UDP_HDR_SIZE];

    while (g_tunnel_running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(s, &rfds);

        struct timeval tv = { 0, 50000 }; /* 50ms */
        int sel = select((int)s + 1, &rfds, NULL, NULL, &tv);

        /* Periodically clean up timed-out UDP clients (60s inactivity) */
        static time_t last_reap = 0;
        time_t now = time(NULL);
        if (now - last_reap >= 5) {
            last_reap = now;
            pthread_mutex_lock(&g_sessions_lock);
            int changed = 0;
            for (int i = CLIENT_IP_START; i <= CLIENT_IP_END; i++) {
                if (g_clients[i].active && g_clients[i].type == CLIENT_TYPE_UDP) {
                    if (now - g_clients[i].last_seen > 60) {
                        printf("[Livekadeh VPN Server] UDP Client 10.10.10.%d timed out (idle > 60s).\n", i);
                        g_clients[i].active = 0;
                        changed = 1;
                    }
                }
            }
            pthread_mutex_unlock(&g_sessions_lock);
            if (changed) update_clients_file();
        }

        if (sel <= 0) continue;

        if (FD_ISSET(s, &rfds)) {
            struct sockaddr_in from;
            socklen_t from_len = sizeof(from);
            int n = recvfrom(s, (char *)buf, sizeof(buf), 0, (struct sockaddr *)&from, &from_len);
            if (n <= 0) continue;

            if (n == UDP_REQ_LEN && memcmp(buf, UDP_MAGIC_REQ, 10) == 0) {
                uint8_t *c_nonce = buf + 10;
                uint8_t *tag = buf + 26;
                uint8_t exp_tag[32];
                compute_auth_tag(master_key, "LK-UDP-AUTH", c_nonce, exp_tag);
                if (memcmp(tag, exp_tag, 32) == 0) {
                    uint8_t ip_host = 0;
                    pthread_mutex_lock(&g_sessions_lock);
                    for (int i = CLIENT_IP_START; i <= CLIENT_IP_END; i++) {
                        if (g_clients[i].active && g_clients[i].type == CLIENT_TYPE_UDP &&
                            g_clients[i].udp_addr.sin_addr.s_addr == from.sin_addr.s_addr &&
                            g_clients[i].udp_addr.sin_port == from.sin_port) {
                            ip_host = (uint8_t)i;
                            break;
                        }
                    }
                    pthread_mutex_unlock(&g_sessions_lock);

                    if (ip_host == 0) {
                        ip_host = alloc_client_ip();
                    }

                    if (ip_host == 0) {
                        continue;
                    }

                    pthread_mutex_lock(&g_sessions_lock);
                    g_clients[ip_host].active = 1;
                    g_clients[ip_host].type = CLIENT_TYPE_UDP;
                    g_clients[ip_host].ip_host = ip_host;
                    g_clients[ip_host].last_seen = time(NULL);
                    memcpy(&g_clients[ip_host].udp_addr, &from, sizeof(from));
                    lk_random_bytes((uint8_t *)&g_clients[ip_host].udp_tx_salt, 4);
                    g_clients[ip_host].udp_tx_seq = 0;
                    snprintf(g_clients[ip_host].remote_ip, sizeof(g_clients[ip_host].remote_ip), "%s", inet_ntoa(from.sin_addr));
                    g_clients[ip_host].remote_port = ntohs(from.sin_port);
                    pthread_mutex_unlock(&g_sessions_lock);

                    update_clients_file();

                    uint8_t ack[UDP_ACK_LEN];
                    memcpy(ack, UDP_MAGIC_ACK, 10);
                    uint8_t s_nonce[16];
                    lk_random_bytes(s_nonce, 16);
                    memcpy(ack + 10, s_nonce, 16);
                    compute_auth_tag(master_key, "LK-UDP-ACK", s_nonce, ack + 26);
                    memset(ack + 58, 0, 32);
                    snprintf((char *)(ack + 58), 32, "%s@10.10.10.%d", LIVEKADEH_VERSION, ip_host);

                    sendto(s, (const char *)ack, UDP_ACK_LEN, 0, (struct sockaddr *)&from, from_len);
                    printf("[Livekadeh VPN Server] UDP Client Authenticated: %s:%d -> Assigned IP: 10.10.10.%d\n",
                           inet_ntoa(from.sin_addr), ntohs(from.sin_port), ip_host);
                }
            } else if (n >= (int)UDP_HDR_SIZE) {
                uint8_t nonce[12];
                memcpy(nonce, buf, 12);
                size_t cipher_len = (size_t)(n - UDP_HDR_SIZE);
                if (cipher_len > 0 && cipher_len <= MAX_PACKET_SIZE) {
                    uint8_t plain[MAX_PACKET_SIZE];
                    lk_chacha20_crypt_packet(master_key, nonce, 0, buf + UDP_HDR_SIZE, plain, cipher_len);
                    if (cipher_len == 4 && *(uint32_t *)plain == UDP_PING_MAGIC) {
                        pthread_mutex_lock(&g_sessions_lock);
                        for (int i = CLIENT_IP_START; i <= CLIENT_IP_END; i++) {
                            if (g_clients[i].active && g_clients[i].type == CLIENT_TYPE_UDP) {
                                if (g_clients[i].udp_addr.sin_addr.s_addr == from.sin_addr.s_addr) {
                                    g_clients[i].udp_addr.sin_port = from.sin_port;
                                    g_clients[i].last_seen = time(NULL);
                                    break;
                                }
                            }
                        }
                        pthread_mutex_unlock(&g_sessions_lock);
                    } else if (cipher_len >= 20) {
                        if (plain[12] == 10 && plain[13] == 10 && plain[14] == 10) {
                            uint8_t src_host = plain[15];
                            if (src_host >= CLIENT_IP_START && src_host <= CLIENT_IP_END) {
                                pthread_mutex_lock(&g_sessions_lock);
                                if (g_clients[src_host].active && g_clients[src_host].type == CLIENT_TYPE_UDP) {
                                    memcpy(&g_clients[src_host].udp_addr, &from, sizeof(from));
                                    g_clients[src_host].last_seen = time(NULL);
                                }
                                pthread_mutex_unlock(&g_sessions_lock);
                            }
                        }
                        pthread_mutex_lock(&g_tun_write_lock);
                        if (write(tun_fd, plain, cipher_len) > 0) {
                            g_traffic_rx_bytes += cipher_len;
                        }
                        pthread_mutex_unlock(&g_tun_write_lock);
                    }
                }
            }
        }
    }
    CLOSE_SOCK(s);
    return NULL;
}
#endif

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

    derive_master_key(key, g_server_master_key);

    socket_t udp_sock = create_udp_listener("0.0.0.0", listen_port);
    if (IS_VALIDSOCK(udp_sock)) {
        g_server_udp_sock = udp_sock;
        linux_udp_args_t *uargs = (linux_udp_args_t *)malloc(sizeof(linux_udp_args_t));
        uargs->tun_fd = tun_fd;
        uargs->udp_sock = udp_sock;
        memcpy(uargs->master_key, g_server_master_key, 32);
        pthread_t udp_tid;
        if (pthread_create(&udp_tid, NULL, linux_tun_udp_server_thread, uargs) == 0) {
            pthread_detach(udp_tid);
        } else {
            free(uargs);
            CLOSE_SOCK(udp_sock);
        }
    }

    /* Start Outbound Router Thread */
    pthread_t router_tid;
    if (pthread_create(&router_tid, NULL, linux_tun_outbound_router_thread, (void *)(intptr_t)tun_fd) == 0) {
        pthread_detach(router_tid);
    }

    unlink("/tmp/livekadeh_clients.txt");

    printf("\n==================================================================\n");
    printf("       Livekadeh Tunnel Server (v%s)\n", LIVEKADEH_VERSION);
    printf("==================================================================\n");
    printf(" [TUN] Device:        %s (Subnet: 10.10.10.0/24)\n", dev);
    printf(" [NET] Dual-Stack:    TCP :%d & UDP :%d\n", listen_port, listen_port);
    printf(" [SEC] Server Key:    %s\n", key);
    printf(" [POOL] Capacity:     253 Concurrent Clients (10.10.10.2 - 10.10.10.254)\n");
    printf("==================================================================\n\n");

    while (g_tunnel_running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        socket_t sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (!IS_VALIDSOCK(sock)) continue;

        set_tcp_nodelay(sock);

        struct timeval tv_auth = { 3, 0 };
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv_auth, sizeof(tv_auth));

        uint8_t init_pkt[AUTH_FULL_PACKET_SIZE];
        if (read_exact(sock, init_pkt, AUTH_PACKET_SIZE) != 0) {
            CLOSE_SOCK(sock);
            continue;
        }

        uint8_t expected_c_tag[AUTH_TAG_SIZE];
        compute_auth_tag(g_server_master_key, "LK-CLIENT-AUTH", init_pkt, expected_c_tag);

        if (memcmp(init_pkt + AUTH_NONCE_SIZE, expected_c_tag, AUTH_TAG_SIZE) == 0) {
            char client_version[64] = "unknown";
            fd_set rset;
            FD_ZERO(&rset);
            FD_SET(sock, &rset);
            struct timeval tv = { 0, 50000 };
            if (select((int)sock + 1, &rset, NULL, NULL, &tv) > 0) {
                if (read_exact(sock, init_pkt + AUTH_PACKET_SIZE, AUTH_VER_SIZE) == 0) {
                    decrypt_version_field(g_server_master_key, init_pkt, init_pkt + AUTH_PACKET_SIZE, client_version, sizeof(client_version));
                }
            }

            uint8_t ip_host = alloc_client_ip();
            if (ip_host == 0) {
                printf("[Livekadeh VPN Server] Rejected connection from %s: IP pool full!\n",
                       inet_ntoa(client_addr.sin_addr));
                CLOSE_SOCK(sock);
                continue;
            }

            uint8_t c_nonce[AUTH_NONCE_SIZE];
            memcpy(c_nonce, init_pkt, AUTH_NONCE_SIZE);

            uint8_t s_nonce[AUTH_NONCE_SIZE];
            if (lk_random_bytes(s_nonce, AUTH_NONCE_SIZE) != 0) {
                free_client_ip(ip_host);
                CLOSE_SOCK(sock);
                continue;
            }

            char cfg_payload[32];
            snprintf(cfg_payload, sizeof(cfg_payload), "%s@10.10.10.%d", LIVEKADEH_VERSION, ip_host);

            uint8_t s_pkt[AUTH_FULL_PACKET_SIZE];
            memcpy(s_pkt, s_nonce, AUTH_NONCE_SIZE);
            compute_auth_tag(g_server_master_key, "LK-SERVER-AUTH", s_nonce, s_pkt + AUTH_NONCE_SIZE);
            encrypt_version_field(g_server_master_key, s_nonce, cfg_payload, s_pkt + AUTH_PACKET_SIZE);

            if (write_exact(sock, s_pkt, AUTH_FULL_PACKET_SIZE) != 0) {
                free_client_ip(ip_host);
                CLOSE_SOCK(sock);
                continue;
            }

            struct timeval tv_zero = { 0, 0 };
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv_zero, sizeof(tv_zero));
            tune_tunnel_socket(sock);

            uint8_t key_c2s[32], key_s2c[32];
            derive_direction_key(g_server_master_key, "C2S", c_nonce, key_c2s);
            derive_direction_key(g_server_master_key, "S2C", s_nonce, key_s2c);

            pthread_mutex_lock(&g_sessions_lock);
            g_clients[ip_host].active = 1;
            g_clients[ip_host].type = CLIENT_TYPE_TCP;
            g_clients[ip_host].ip_host = ip_host;
            g_clients[ip_host].num_conns = 1;
            g_clients[ip_host].socks[0] = sock;
            memcpy(g_clients[ip_host].c_nonce, c_nonce, AUTH_NONCE_SIZE);
            memcpy(g_clients[ip_host].s_nonce, s_nonce, AUTH_NONCE_SIZE);

            for (int i = 0; i < NUM_TUNNEL_CONNS; i++) {
                uint8_t lane_c_nonce[16], lane_s_nonce[16];
                memcpy(lane_c_nonce, c_nonce, 16);
                memcpy(lane_s_nonce, s_nonce, 16);
                lane_c_nonce[15] ^= (uint8_t)i;
                lane_s_nonce[15] ^= (uint8_t)i;

                lk_chacha20_init(&g_clients[ip_host].ctx_rx[i], key_c2s, lane_c_nonce, 1);
                lk_chacha20_init(&g_clients[ip_host].ctx_tx[i], key_s2c, lane_s_nonce, 1);
            }

            snprintf(g_clients[ip_host].client_version, sizeof(g_clients[ip_host].client_version), "%s", client_version);
            snprintf(g_clients[ip_host].remote_ip, sizeof(g_clients[ip_host].remote_ip), "%s", inet_ntoa(client_addr.sin_addr));
            g_clients[ip_host].remote_port = ntohs(client_addr.sin_port);
            g_clients[ip_host].last_seen = time(NULL);
            pthread_mutex_unlock(&g_sessions_lock);

            update_clients_file();

            printf("[Livekadeh VPN Server] TCP Client (v%s) authenticated from %s:%d! Assigned IP: 10.10.10.%d\n",
                   client_version, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), ip_host);

            tcp_worker_param_t *wp = (tcp_worker_param_t *)malloc(sizeof(tcp_worker_param_t));
            wp->tun_fd = tun_fd;
            wp->ip_host = ip_host;
            pthread_t c_tid;
            if (pthread_create(&c_tid, NULL, linux_tcp_client_worker, wp) == 0) {
                pthread_detach(c_tid);
            } else {
                free(wp);
                free_client_ip(ip_host);
                CLOSE_SOCK(sock);
            }
            continue;
        }

        /* Check for auxiliary multi-TCP lane attachment */
        if (read_exact(sock, init_pkt + AUTH_PACKET_SIZE, 16) == 0) {
            uint8_t req_c_nonce[AUTH_NONCE_SIZE];
            uint8_t lane_idx = 0;
            if (verify_attach_packet(g_server_master_key, init_pkt, req_c_nonce, &lane_idx) == 0 &&
                lane_idx > 0 && lane_idx < NUM_TUNNEL_CONNS) {
                pthread_mutex_lock(&g_sessions_lock);
                int found_host = -1;
                for (int h = CLIENT_IP_START; h <= CLIENT_IP_END; h++) {
                    if (g_clients[h].active && g_clients[h].type == CLIENT_TYPE_TCP &&
                        memcmp(g_clients[h].c_nonce, req_c_nonce, AUTH_NONCE_SIZE) == 0) {
                        found_host = h;
                        break;
                    }
                }
                if (found_host != -1) {
                    uint8_t ack_pkt[ATTACH_PACKET_SIZE];
                    memset(ack_pkt, 0, sizeof(ack_pkt));
                    memcpy(ack_pkt, g_clients[found_host].s_nonce, AUTH_NONCE_SIZE);
                    ack_pkt[AUTH_NONCE_SIZE] = lane_idx;
                    compute_auth_tag(g_server_master_key, "LK-ATTACH-OK", ack_pkt, ack_pkt + AUTH_NONCE_SIZE + 16);
                    write_exact(sock, ack_pkt, ATTACH_PACKET_SIZE);

                    struct timeval tv_zero = { 0, 0 };
                    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv_zero, sizeof(tv_zero));
                    tune_tunnel_socket(sock);

                    g_clients[found_host].socks[lane_idx] = sock;
                    if (lane_idx + 1 > g_clients[found_host].num_conns) {
                        g_clients[found_host].num_conns = lane_idx + 1;
                    }
                    printf("[Livekadeh VPN Server] TCP Client 10.10.10.%d: Attached Lane %d (Total Lanes: %d)\n",
                           found_host, lane_idx, g_clients[found_host].num_conns);
                    pthread_mutex_unlock(&g_sessions_lock);
                    update_clients_file();
                    continue;
                }
                pthread_mutex_unlock(&g_sessions_lock);
            }
        }

        printf("[Livekadeh VPN Server] Unauthorized probe or invalid packet from %s (Rejected)\n",
               inet_ntoa(client_addr.sin_addr));
        CLOSE_SOCK(sock);
    }

    if (IS_VALIDSOCK(udp_sock)) CLOSE_SOCK(udp_sock);
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
    int is_udp;
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

    char assigned_ip[64] = "10.10.10.2";
    char *at = strchr(server_version, '@');
    if (at) {
        *at = '\0';
        snprintf(assigned_ip, sizeof(assigned_ip), "%s", at + 1);
    }

    log_append(1 /* INFO */, "Connected to Livekadeh Tunnel Server v%s! Assigned IP: %s", server_version, assigned_ip);

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

    /* Configure assigned IP and default internet routes through Wintun */
    log_append(1 /* INFO */, "Configuring adapter IP %s and routing traffic through tunnel...", assigned_ip);
    wintun_configure_ip("LivekadehAdapter", assigned_ip, "255.255.255.0", p->server_host);

    /* Setup WFP Per-App if requested */
    if (p->is_per_app && p->num_apps > 0) {
        log_append(1 /* INFO */, "Configuring WFP Per-App routing for %d applications...", p->num_apps);
        for (int i = 0; i < p->num_apps; i++) {
            log_append(0 /* DEBUG */, "  -> App: %s", p->app_paths[i]);
        }
        wfp_setup_per_apps((const char (*)[MAX_PATH])p->app_paths, p->num_apps, assigned_ip);
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

/* Windows UDP Datagram Worker */
typedef struct {
    WINTUN_SESSION_HANDLE session;
    socket_t sock;
    uint8_t master_key[32];
    volatile int running;
} win_udp_rx_worker_t;

static DWORD WINAPI win_udp_rx_thread(LPVOID arg) {
    win_udp_rx_worker_t *w = (win_udp_rx_worker_t *)arg;
    uint8_t buf[MAX_PACKET_SIZE + UDP_HDR_SIZE];

    while (w->running && g_tunnel_running) {
        int n = recvfrom(w->sock, (char *)buf, sizeof(buf), 0, NULL, NULL);
        if (n <= (int)UDP_HDR_SIZE) continue;

        uint8_t nonce[12];
        memcpy(nonce, buf, 12);
        size_t cipher_len = (size_t)(n - UDP_HDR_SIZE);

        BYTE *tun_pkt = pWintunAllocateSendPacket(w->session, (DWORD)cipher_len);
        if (tun_pkt) {
            lk_chacha20_crypt_packet(w->master_key, nonce, 0, buf + UDP_HDR_SIZE, tun_pkt, cipher_len);
            pWintunSendPacket(w->session, tun_pkt);
            g_traffic_rx_bytes += cipher_len;
        }
    }
    return 0;
}

static DWORD WINAPI win_tun_udp_client_thread(LPVOID arg) {
    win_tun_client_params_t *p = (win_tun_client_params_t *)arg;
    g_tunnel_running = 1;
    g_traffic_tx_bytes = 0;
    g_traffic_rx_bytes = 0;

    log_append(1 /* INFO */, "Starting Livekadeh Tunnel in UDP Datagram Mode (Fast & Low Latency)...");

    socket_t s = create_udp_socket();
    if (!IS_VALIDSOCK(s)) {
        log_append(3 /* ERROR */, "Failed to create UDP socket.");
        free(p);
        return 1;
    }
    tune_udp_socket(s);

    struct hostent *he = gethostbyname(p->server_host);
    if (!he) {
        log_append(3 /* ERROR */, "Cannot resolve server address: %s", p->server_host);
        CLOSE_SOCK(s);
        free(p);
        return 1;
    }

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons((uint16_t)p->server_port);
    memcpy(&srv_addr.sin_addr, he->h_addr_list[0], sizeof(srv_addr.sin_addr));

    uint8_t master_key[32];
    derive_master_key(p->key, master_key);

    log_append(1 /* INFO */, "Sending UDP Handshake to %s:%d...", p->server_host, p->server_port);

    uint8_t c_nonce[16];
    lk_random_bytes(c_nonce, 16);

    uint8_t req[UDP_REQ_LEN];
    memcpy(req, UDP_MAGIC_REQ, 10);
    memcpy(req + 10, c_nonce, 16);
    compute_auth_tag(master_key, "LK-UDP-AUTH", c_nonce, req + 26);

    DWORD to = 1500;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof(to));

    int ack_received = 0;
    char server_version[64] = "unknown";
    char assigned_ip[64] = "10.10.10.2";

    for (int attempt = 1; attempt <= 4; attempt++) {
        sendto(s, (const char *)req, UDP_REQ_LEN, 0, (struct sockaddr *)&srv_addr, sizeof(srv_addr));

        uint8_t ack[UDP_ACK_LEN + 32];
        struct sockaddr_in from;
        int from_len = sizeof(from);
        int r = recvfrom(s, (char *)ack, sizeof(ack), 0, (struct sockaddr *)&from, &from_len);
        if (r >= UDP_ACK_LEN && memcmp(ack, UDP_MAGIC_ACK, 10) == 0) {
            uint8_t *s_nonce = ack + 10;
            uint8_t *tag = ack + 26;
            uint8_t exp_tag[32];
            compute_auth_tag(master_key, "LK-UDP-ACK", s_nonce, exp_tag);
            if (memcmp(tag, exp_tag, 32) == 0) {
                snprintf(server_version, sizeof(server_version), "%s", (char *)(ack + 58));
                char *at = strchr(server_version, '@');
                if (at) {
                    *at = '\0';
                    snprintf(assigned_ip, sizeof(assigned_ip), "%s", at + 1);
                }
                ack_received = 1;
                break;
            } else {
                log_append(3 /* ERROR */, "AUTHENTICATION FAILED: INVALID ENCRYPTION KEY!");
                CLOSE_SOCK(s);
                free(p);
                return 1;
            }
        }
        log_append(2 /* WARN */, "UDP Handshake attempt %d timed out, retrying...", attempt);
    }

    if (!ack_received) {
        log_append(3 /* ERROR */, "Server %s:%d did not respond on UDP.", p->server_host, p->server_port);
        CLOSE_SOCK(s);
        free(p);
        return 1;
    }

    log_append(1 /* INFO */, "Connected to Livekadeh Tunnel Server (UDP Mode v%s)! Assigned IP: %s", server_version, assigned_ip);

    DWORD to_zero = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to_zero, sizeof(to_zero));

    if (wintun_load_dll() != 0) {
        log_append(3 /* ERROR */, "wintun.dll not found or failed to load.");
        CLOSE_SOCK(s);
        free(p);
        return 1;
    }

    WINTUN_ADAPTER_HANDLE adapter = pWintunCreateAdapter(L"LivekadehAdapter", L"Livekadeh", NULL);
    if (!adapter) {
        adapter = pWintunOpenAdapter(L"LivekadehAdapter");
        if (!adapter) {
            log_append(3 /* ERROR */, "Cannot create or open Wintun adapter. Ensure running as Administrator!");
            CLOSE_SOCK(s);
            free(p);
            return 1;
        }
    }

    /* Configure assigned IP and default internet routes through Wintun */
    log_append(1 /* INFO */, "Configuring adapter IP %s and routing traffic through tunnel...", assigned_ip);
    wintun_configure_ip("LivekadehAdapter", assigned_ip, "255.255.255.0", p->server_host);

    /* Setup WFP Per-App if requested */
    if (p->is_per_app && p->num_apps > 0) {
        log_append(1 /* INFO */, "Configuring WFP Per-App routing for %d applications...", p->num_apps);
        for (int i = 0; i < p->num_apps; i++) {
            log_append(0 /* DEBUG */, "  -> App: %s", p->app_paths[i]);
        }
        wfp_setup_per_apps((const char (*)[MAX_PATH])p->app_paths, p->num_apps, assigned_ip);
    }

    WINTUN_SESSION_HANDLE session = pWintunStartSession(adapter, 0x400000);
    if (!session) {
        log_append(3 /* ERROR */, "Failed to start Wintun session.");
        wintun_cleanup_routes("LivekadehAdapter", p->server_host);
        pWintunCloseAdapter(adapter);
        CLOSE_SOCK(s);
        free(p);
        return 1;
    }

    log_append(1 /* INFO */, "UDP Tunnel is ACTIVE! All traffic encrypted and routed via 10.10.10.1.");

    win_udp_rx_worker_t rx_w;
    rx_w.session = session;
    rx_w.sock = s;
    memcpy(rx_w.master_key, master_key, 32);
    rx_w.running = 1;

    HANDLE h_rx = CreateThread(NULL, 0, win_udp_rx_thread, &rx_w, 0, NULL);

    HANDLE read_wait = pWintunGetReadWaitEvent(session);
    uint32_t tx_salt = 0;
    lk_random_bytes((uint8_t *)&tx_salt, sizeof(tx_salt));
    uint64_t tx_seq = 0;
    DWORD last_send_time = GetTickCount();

    uint8_t out[MAX_PACKET_SIZE + UDP_HDR_SIZE];

    while (g_tunnel_running) {
        DWORD packet_size = 0;
        BYTE *packet = pWintunReceivePacket(session, &packet_size);
        if (packet) {
            if (packet_size <= MAX_PACKET_SIZE) {
                uint64_t seq = ++tx_seq;
                memcpy(out, &tx_salt, 4);
                memcpy(out + 4, &seq, 8);
                uint8_t nonce[12];
                memcpy(nonce, out, 12);

                lk_chacha20_crypt_packet(master_key, nonce, 0, packet, out + UDP_HDR_SIZE, (size_t)packet_size);
                sendto(s, (const char *)out, (int)(packet_size + UDP_HDR_SIZE), 0, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
                g_traffic_tx_bytes += packet_size;
                last_send_time = GetTickCount();
            }
            pWintunReleaseReceivePacket(session, packet);
        } else {
            /* Keepalive ping every 15s to keep NAT mapping alive */
            if (GetTickCount() - last_send_time > 15000) {
                uint64_t seq = ++tx_seq;
                memcpy(out, &tx_salt, 4);
                memcpy(out + 4, &seq, 8);
                uint8_t nonce[12];
                memcpy(nonce, out, 12);
                uint32_t ping_magic = UDP_PING_MAGIC;
                lk_chacha20_crypt_packet(master_key, nonce, 0, (const uint8_t *)&ping_magic, out + UDP_HDR_SIZE, 4);
                sendto(s, (const char *)out, (int)(4 + UDP_HDR_SIZE), 0, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
                last_send_time = GetTickCount();
            }
            WaitForSingleObject(read_wait, 10);
        }
    }

    log_append(1 /* INFO */, "UDP Tunnel disconnected.");
    rx_w.running = 0;
    CLOSE_SOCK(s);
    if (h_rx) {
        WaitForSingleObject(h_rx, 1000);
        CloseHandle(h_rx);
    }

    wintun_cleanup_routes("LivekadehAdapter", p->server_host);
    wfp_cleanup();
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
