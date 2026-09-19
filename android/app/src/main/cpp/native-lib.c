#include <jni.h>
#include <android/log.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>

static volatile int g_debug_mode = 0;

#define LOGI(...) do { \
    __android_log_print(ANDROID_LOG_INFO, "TunnelNative", __VA_ARGS__); \
    char __tmp[512]; \
    snprintf(__tmp, sizeof(__tmp), __VA_ARGS__); \
    append_log("INFO", __tmp); \
} while(0)

#define LOGE(...) do { \
    __android_log_print(ANDROID_LOG_ERROR, "TunnelNative", __VA_ARGS__); \
    char __tmp[512]; \
    snprintf(__tmp, sizeof(__tmp), __VA_ARGS__); \
    append_log("ERROR", __tmp); \
} while(0)

#define LOGW(...) do { \
    __android_log_print(ANDROID_LOG_WARN, "TunnelNative", __VA_ARGS__); \
    char __tmp[512]; \
    snprintf(__tmp, sizeof(__tmp), __VA_ARGS__); \
    append_log("WARN", __tmp); \
} while(0)

#define LOGD(...) do { \
    if (g_debug_mode) { \
        __android_log_print(ANDROID_LOG_DEBUG, "TunnelNative", __VA_ARGS__); \
        char __tmp[512]; \
        snprintf(__tmp, sizeof(__tmp), __VA_ARGS__); \
        append_log("DEBUG", __tmp); \
    } \
} while(0)

#include "tunnel_common.h"
#include "crypto.h"

#define MAX_PACKET_SIZE 2048
#define UDP_MAGIC_REQ "LK-UDP-REQ"
#define UDP_MAGIC_ACK "LK-UDP-ACK"
#define UDP_REQ_LEN   (10 + 16 + 32)
#define UDP_ACK_LEN   (10 + 16 + 32 + 32)
#define UDP_SALT_SIZE 4
#define UDP_SEQ_SIZE  8
#define UDP_HDR_SIZE  (UDP_SALT_SIZE + UDP_SEQ_SIZE)
#define UDP_PING_MAGIC 0xFFFFFFFD

static inline int send_tun_packet(socket_t sock, lk_chacha20_ctx *ctx, const uint8_t *packet, uint16_t len) {
    if (len == 0 || len > MAX_PACKET_SIZE) return -1;
    uint8_t buffer[MAX_PACKET_SIZE + 2];
    buffer[0] = (uint8_t)(len >> 8);
    buffer[1] = (uint8_t)(len & 0xFF);
    lk_chacha20_xor(ctx, packet, buffer + 2, len);
    return write_exact(sock, buffer, (size_t)len + 2);
}

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

typedef struct {
    int tun_fd;
    socket_t sock;
    uint8_t master_key[32];
    volatile int running;
} android_udp_rx_worker_t;

static volatile uint64_t g_traffic_tx = 0;
static volatile uint64_t g_traffic_rx = 0;
static char g_log_buf[65536] = {0};
static int g_log_len = 0;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static void append_log(const char* level, const char* msg) {
    pthread_mutex_lock(&g_log_mutex);
    time_t now = time(NULL);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    char time_str[16];
    snprintf(time_str, sizeof(time_str), "%02d:%02d:%02d", tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec);

    int len = snprintf(NULL, 0, "[%s] [%s] %s\n", time_str, level, msg);
    if (len > 0) {
        if (g_log_len + len >= (int)sizeof(g_log_buf)) {
            int shift = (g_log_len + len) - (int)sizeof(g_log_buf) + 4096;
            if (shift < g_log_len) {
                memmove(g_log_buf, g_log_buf + shift, g_log_len - shift);
                g_log_len -= shift;
            } else {
                g_log_len = 0;
            }
        }
        g_log_len += snprintf(g_log_buf + g_log_len, sizeof(g_log_buf) - g_log_len, "[%s] [%s] %s\n", time_str, level, msg);
    }
    pthread_mutex_unlock(&g_log_mutex);
}

static volatile int g_android_tunnel_running = 0;
static int g_tun_fd = -1;
static socket_t g_udp_sock = -1;
static socket_t g_tcp_socks[NUM_TUNNEL_CONNS];
static int g_num_tcp_socks = 0;

static void protect_socket_via_jvm(JNIEnv* env, int sock) {
    if (sock < 0 || !env) return;
    jclass cls = (*env)->FindClass(env, "com/example/livekadehtunnel/TunnelVpnService");
    if (cls) {
        jmethodID mid = (*env)->GetStaticMethodID(env, cls, "protectSocket", "(I)Z");
        if (mid) {
            jboolean res = (*env)->CallStaticBooleanMethod(env, cls, mid, (jint)sock);
            LOGD("VpnService.protect(socket=%d) returned %s", sock, res ? "TRUE" : "FALSE");
        }
        (*env)->DeleteLocalRef(env, cls);
    }
}

static int establish_vpn_via_jvm(JNIEnv* env, const char* assigned_ip) {
    if (!env || !assigned_ip) return -1;
    jclass cls = (*env)->FindClass(env, "com/example/livekadehtunnel/TunnelVpnService");
    if (!cls) return -1;
    jmethodID mid = (*env)->GetStaticMethodID(env, cls, "establishVpnInterface", "(Ljava/lang/String;)I");
    if (!mid) {
        (*env)->DeleteLocalRef(env, cls);
        return -1;
    }
    jstring j_ip = (*env)->NewStringUTF(env, assigned_ip);
    jint fd = (*env)->CallStaticIntMethod(env, cls, mid, j_ip);
    (*env)->DeleteLocalRef(env, j_ip);
    (*env)->DeleteLocalRef(env, cls);
    return (int)fd;
}

/* UDP RX worker thread */
static void* android_udp_rx_thread(void* arg) {
    android_udp_rx_worker_t* w = (android_udp_rx_worker_t*)arg;
    uint8_t buf[MAX_PACKET_SIZE + UDP_HDR_SIZE];

    LOGD("UDP RX thread started on socket fd=%d", w->sock);

    while (w->running && g_android_tunnel_running) {
        int n = recvfrom(w->sock, (char*)buf, sizeof(buf), 0, NULL, NULL);
        if (n <= (int)UDP_HDR_SIZE) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                continue;
            }
            if (n < 0) {
                usleep(5000);
            }
            continue;
        }

        uint8_t nonce[12];
        memcpy(nonce, buf, 12);
        size_t cipher_len = (size_t)(n - UDP_HDR_SIZE);

        uint8_t* tun_pkt = (uint8_t*)malloc(cipher_len);
        if (tun_pkt) {
            lk_chacha20_crypt_packet(w->master_key, nonce, 0, buf + UDP_HDR_SIZE, tun_pkt, cipher_len);
            if (w->tun_fd >= 0) {
                write(w->tun_fd, tun_pkt, cipher_len);
                g_traffic_rx += cipher_len;
            }
            free(tun_pkt);
        }
    }
    LOGD("UDP RX thread exiting");
    return NULL;
}

/* Run UDP tunnel */
static int run_udp_client(JNIEnv* env, const char* srv_addr_cstr, int port, const char* key_cstr) {
    LOGI("Starting UDP Datagram Tunnel to %s:%d...", srv_addr_cstr, port);

    g_udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_udp_sock < 0) {
        LOGE("Failed to create UDP socket: %s", strerror(errno));
        return -1;
    }

    protect_socket_via_jvm(env, g_udp_sock);

    struct sockaddr_in srv_addr_in;
    memset(&srv_addr_in, 0, sizeof(srv_addr_in));
    srv_addr_in.sin_family = AF_INET;
    srv_addr_in.sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, srv_addr_cstr, &srv_addr_in.sin_addr) <= 0) {
        LOGD("Resolving domain %s via gethostbyname...", srv_addr_cstr);
        struct hostent *he = gethostbyname(srv_addr_cstr);
        if (!he) {
            LOGE("Cannot resolve server address: %s (errno=%s)", srv_addr_cstr, strerror(errno));
            close(g_udp_sock);
            g_udp_sock = -1;
            return -1;
        }
        memcpy(&srv_addr_in.sin_addr, he->h_addr_list[0], sizeof(srv_addr_in.sin_addr));
    }

    LOGD("Resolved server address: %s:%d", inet_ntoa(srv_addr_in.sin_addr), port);

    uint8_t master_key[32];
    derive_master_key(key_cstr, master_key);

    LOGI("Preparing UDP Handshake to %s:%d...", srv_addr_cstr, port);

    uint8_t c_nonce[16];
    lk_random_bytes(c_nonce, 16);

    uint8_t req[UDP_REQ_LEN];
    memcpy(req, UDP_MAGIC_REQ, 10);
    memcpy(req + 10, c_nonce, 16);
    compute_auth_tag(master_key, "LK-UDP-AUTH", c_nonce, req + 26);

    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(g_udp_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int ack_received = 0;
    char server_version[64] = "unknown";
    char assigned_ip[64] = "10.10.10.2";

    for (int attempt = 1; attempt <= 6 && g_android_tunnel_running; attempt++) {
        LOGI("Sending UDP Handshake attempt %d/6 (%d bytes)...", attempt, UDP_REQ_LEN);
        ssize_t st = sendto(g_udp_sock, (char*)req, UDP_REQ_LEN, 0, (struct sockaddr *)&srv_addr_in, sizeof(srv_addr_in));
        if (st < 0) {
            LOGE("sendto failed: %s (errno=%d)", strerror(errno), errno);
        }
        
        uint8_t ack_buf[UDP_ACK_LEN + 32];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        int n = recvfrom(g_udp_sock, (char*)ack_buf, sizeof(ack_buf), 0, (struct sockaddr *)&from, &from_len);
        
        if (n >= UDP_ACK_LEN && memcmp(ack_buf, UDP_MAGIC_ACK, 10) == 0) {
            uint8_t *s_nonce = ack_buf + 10;
            uint8_t *tag = ack_buf + 26;
            uint8_t exp_tag[32];
            compute_auth_tag(master_key, "LK-UDP-ACK", s_nonce, exp_tag);
            if (memcmp(tag, exp_tag, 32) == 0) {
                snprintf(server_version, sizeof(server_version), "%s", (char *)(ack_buf + 58));
                char *at = strchr(server_version, '@');
                if (at) {
                    *at = '\0';
                    snprintf(assigned_ip, sizeof(assigned_ip), "%s", at + 1);
                }
                ack_received = 1;
                LOGI("Connected to Server v%s! Assigned IP: %s (from %s:%d)",
                     server_version, assigned_ip, inet_ntoa(from.sin_addr), ntohs(from.sin_port));
                break;
            } else {
                LOGE("AUTHENTICATION FAILED: INVALID ENCRYPTION KEY! Server rejected connection.");
                close(g_udp_sock);
                g_udp_sock = -1;
                return -1;
            }
        } else if (n < 0) {
            LOGW("Attempt %d/6 timed out or error: %s (errno=%d)", attempt, strerror(errno), errno);
        } else {
            LOGW("Attempt %d/6 received unexpected packet (%d bytes)", attempt, n);
        }
    }

    if (!ack_received) {
        LOGE("UDP Handshake failed after 6 attempts to %s:%d.", srv_addr_cstr, port);
        LOGE("Carrier mobile data might be filtering UDP traffic. Switch to Multi-TCP (8 Lanes) mode.");
        close(g_udp_sock);
        g_udp_sock = -1;
        return -1;
    }

    /* Reset socket receive timeout for continuous traffic */
    struct timeval tv_zero = { 0, 0 };
    setsockopt(g_udp_sock, SOL_SOCKET, SO_RCVTIMEO, &tv_zero, sizeof(tv_zero));

    /* Dynamically establish Android TUN interface with the server assigned IP */
    LOGI("Configuring Android VPN adapter with IP %s...", assigned_ip);
    int fd = establish_vpn_via_jvm(env, assigned_ip);
    if (fd < 0) {
        LOGE("Failed to establish Android VPN interface");
        close(g_udp_sock);
        g_udp_sock = -1;
        return -1;
    }
    g_tun_fd = fd;
    LOGI("VPN adapter configured! Tunnel is ACTIVE.");

    android_udp_rx_worker_t rx_worker;
    rx_worker.tun_fd = fd;
    rx_worker.sock = g_udp_sock;
    memcpy(rx_worker.master_key, master_key, 32);
    rx_worker.running = 1;

    pthread_t rx_tid;
    pthread_create(&rx_tid, NULL, android_udp_rx_thread, &rx_worker);

    uint32_t tx_salt = 0;
    lk_random_bytes((uint8_t *)&tx_salt, sizeof(tx_salt));
    uint64_t tx_seq = 0;
    time_t last_send_time = time(NULL);

    uint8_t packet[MAX_PACKET_SIZE];
    uint8_t udp_buf[MAX_PACKET_SIZE + UDP_HDR_SIZE];

    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;

    while (g_android_tunnel_running) {
        int pr = poll(&pfd, 1, 100);
        if (pr > 0 && (pfd.revents & POLLIN)) {
            int packet_size = read(fd, packet, sizeof(packet));
            if (packet_size > 0 && packet_size <= MAX_PACKET_SIZE) {
                uint64_t seq = ++tx_seq;
                memcpy(udp_buf, &tx_salt, 4);
                memcpy(udp_buf + 4, &seq, 8);
                uint8_t nonce[12];
                memcpy(nonce, udp_buf, 12);

                lk_chacha20_crypt_packet(master_key, nonce, 0, packet, udp_buf + UDP_HDR_SIZE, (size_t)packet_size);
                sendto(g_udp_sock, (char*)udp_buf, packet_size + UDP_HDR_SIZE, 0, (struct sockaddr *)&srv_addr_in, sizeof(srv_addr_in));
                g_traffic_tx += packet_size;
                last_send_time = time(NULL);
            }
        } else {
            /* Keepalive ping every 15s to keep NAT mapping alive */
            if (time(NULL) - last_send_time > 15) {
                uint64_t seq = ++tx_seq;
                memcpy(udp_buf, &tx_salt, 4);
                memcpy(udp_buf + 4, &seq, 8);
                uint8_t nonce[12];
                memcpy(nonce, udp_buf, 12);
                uint32_t ping_magic = UDP_PING_MAGIC;
                lk_chacha20_crypt_packet(master_key, nonce, 0, (const uint8_t *)&ping_magic, udp_buf + UDP_HDR_SIZE, 4);
                sendto(g_udp_sock, (char*)udp_buf, 4 + UDP_HDR_SIZE, 0, (struct sockaddr *)&srv_addr_in, sizeof(srv_addr_in));
                last_send_time = time(NULL);
                LOGD("Sent UDP keepalive ping");
            }
        }
    }

    rx_worker.running = 0;
    pthread_join(rx_tid, NULL);
    close(g_udp_sock);
    g_udp_sock = -1;
    LOGI("UDP Tunnel closed.");
    return 0;
}

/* Run TCP tunnel (Single or Multi-lane) */
static int run_tcp_client(JNIEnv* env, const char* srv_addr_cstr, int port, const char* key_cstr, int lanes) {
    LOGI("Starting TCP Tunnel (%d Lanes) to %s:%d...", lanes, srv_addr_cstr, port);

    socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (!IS_VALIDSOCK(sock)) {
        LOGE("Failed to create TCP socket: %s", strerror(errno));
        return -1;
    }

    protect_socket_via_jvm(env, sock);

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, srv_addr_cstr, &srv_addr.sin_addr) <= 0) {
        LOGD("Resolving domain %s via gethostbyname...", srv_addr_cstr);
        struct hostent *he = gethostbyname(srv_addr_cstr);
        if (!he) {
            LOGE("Cannot resolve server address: %s (errno=%s)", srv_addr_cstr, strerror(errno));
            CLOSE_SOCK(sock);
            return -1;
        }
        memcpy(&srv_addr.sin_addr, he->h_addr_list[0], sizeof(srv_addr.sin_addr));
    }

    LOGD("Connecting TCP to %s:%d...", inet_ntoa(srv_addr.sin_addr), port);
    if (connect(sock, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) != 0) {
        LOGE("Cannot connect to server %s:%d (%s). Verify IP, port, and firewall.", srv_addr_cstr, port, strerror(errno));
        CLOSE_SOCK(sock);
        return -1;
    }

    uint8_t master_key[32];
    derive_master_key(key_cstr, master_key);

    struct timeval to = { 4, 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &to, sizeof(to));

    LOGI("Sending challenge authentication probe via TCP...");
    uint8_t c_nonce[AUTH_NONCE_SIZE], s_nonce[AUTH_NONCE_SIZE];
    char server_version[64] = "unknown";
    int auth_res = client_authenticate(sock, master_key, c_nonce, s_nonce, server_version, sizeof(server_version));

    if (auth_res == -2) {
        LOGE("AUTHENTICATION FAILED: INVALID ENCRYPTION KEY! Server rejected connection.");
        CLOSE_SOCK(sock);
        return -1;
    } else if (auth_res != 0) {
        LOGE("Handshake timed out or connection dropped by server.");
        CLOSE_SOCK(sock);
        return -1;
    }

    char assigned_ip[64] = "10.10.10.2";
    char *at = strchr(server_version, '@');
    if (at) {
        *at = '\0';
        snprintf(assigned_ip, sizeof(assigned_ip), "%s", at + 1);
    }

    LOGI("Connected to Livekadeh Tunnel Server v%s! Assigned IP: %s", server_version, assigned_ip);

    tune_tunnel_socket(sock);
    socket_t socks[NUM_TUNNEL_CONNS];
    socks[0] = sock;
    int num_conns = 1;

    int target_conns = (lanes > 0) ? lanes : 1;
    if (target_conns > NUM_TUNNEL_CONNS) target_conns = NUM_TUNNEL_CONNS;

    if (target_conns > 1) {
        LOGI("Establishing %d-Lane Multi-TCP connection pool...", target_conns);

        for (int i = 1; i < target_conns && g_android_tunnel_running; i++) {
            socket_t s_aux = socket(AF_INET, SOCK_STREAM, 0);
            if (!IS_VALIDSOCK(s_aux)) break;

            protect_socket_via_jvm(env, s_aux);

            if (connect(s_aux, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) != 0) {
                CLOSE_SOCK(s_aux);
                break;
            }

            struct timeval to = { 2, 0 };
            setsockopt(s_aux, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));

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

            struct timeval to_zero = { 0, 0 };
            setsockopt(s_aux, SOL_SOCKET, SO_RCVTIMEO, &to_zero, sizeof(to_zero));
            tune_tunnel_socket(s_aux);

            socks[num_conns++] = s_aux;
        }

        LOGI("Multi-TCP active! %d parallel lanes connected.", num_conns);
    } else {
        LOGI("Single-TCP mode active (1 connection).");
    }

    g_num_tcp_socks = num_conns;
    for (int i = 0; i < num_conns; i++) {
        g_tcp_socks[i] = socks[i];
    }

    /* Dynamically establish Android TUN interface with the server assigned IP */
    LOGI("Configuring Android VPN adapter with IP %s...", assigned_ip);
    int fd = establish_vpn_via_jvm(env, assigned_ip);
    if (fd < 0) {
        LOGE("Failed to establish Android VPN interface");
        for (int i = 0; i < num_conns; i++) CLOSE_SOCK(socks[i]);
        g_num_tcp_socks = 0;
        return -1;
    }
    g_tun_fd = fd;
    LOGI("VPN adapter configured! Tunnel is ACTIVE.");

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

    /* Set TUN FD non-blocking */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    uint8_t recv_buf[MAX_PACKET_SIZE];
    uint8_t send_buf[MAX_PACKET_SIZE];

    while (g_android_tunnel_running) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        int max_fd = fd;
        FD_SET(fd, &read_fds);

        for (int i = 0; i < num_conns; i++) {
            FD_SET(socks[i], &read_fds);
            if ((int)socks[i] > max_fd) max_fd = (int)socks[i];
        }

        struct timeval tv = { 0, 10000 }; /* 10ms timeout */
        int act = select(max_fd + 1, &read_fds, NULL, NULL, &tv);

        if (act > 0) {
            /* Check Inbound from Sockets */
            int conn_drop = 0;
            for (int i = 0; i < num_conns; i++) {
                if (FD_ISSET(socks[i], &read_fds)) {
                    uint16_t plen = 0;
                    if (recv_tun_packet(socks[i], &ctx_rx[i], recv_buf, &plen) != 0) {
                        conn_drop = 1;
                        break;
                    }
                    if (plen > 0) {
                        write(fd, recv_buf, plen);
                        g_traffic_rx += plen;
                    }
                }
            }
            if (conn_drop) {
                LOGW("Server stream interrupted or connection dropped.");
                break;
            }

            /* Check Outbound from TUN */
            if (FD_ISSET(fd, &read_fds)) {
                int n = read(fd, send_buf, sizeof(send_buf));
                if (n > 0) {
                    int lane = (int)(flow_hash_packet(send_buf, (size_t)n) % (uint32_t)num_conns);
                    send_tun_packet(socks[lane], &ctx_tx[lane], send_buf, (uint16_t)n);
                    g_traffic_tx += n;
                }
            }
        }
    }

    LOGI("Cleaning up TCP connections...");
    for (int i = 0; i < num_conns; i++) {
        CLOSE_SOCK(socks[i]);
    }
    g_num_tcp_socks = 0;
    LOGI("TCP Tunnel closed.");
    return 0;
}

static jint internal_startNativeTunnel(
        JNIEnv* env,
        jstring serverAddr,
        jint port,
        jstring key,
        jint mode) {
        
    if (!serverAddr || !key) {
        LOGE("Invalid arguments passed to startNativeTunnel");
        return -1;
    }

    g_android_tunnel_running = 1;
    g_traffic_tx = 0;
    g_traffic_rx = 0;

    const char *srv_addr_cstr = (*env)->GetStringUTFChars(env, serverAddr, 0);
    const char *key_cstr = (*env)->GetStringUTFChars(env, key, 0);

    int res = 0;
    if (mode == -1) {
        /* Auto Mode: Try UDP first, if fails fallback to 8-Lane Multi-TCP */
        LOGI("Auto Mode: Trying UDP Datagram first...");
        res = run_udp_client(env, srv_addr_cstr, port, key_cstr);
        if (res != 0 && g_android_tunnel_running) {
            LOGW("UDP connection dropped or filtered. Falling back to 8-Lane Multi-TCP...");
            res = run_tcp_client(env, srv_addr_cstr, port, key_cstr, 8);
        }
    } else if (mode == 0) {
        /* UDP Datagram */
        res = run_udp_client(env, srv_addr_cstr, port, key_cstr);
    } else {
        /* TCP Mode: mode is the number of lanes (1, 4, 8) */
        res = run_tcp_client(env, srv_addr_cstr, port, key_cstr, mode);
    }

    (*env)->ReleaseStringUTFChars(env, serverAddr, srv_addr_cstr);
    (*env)->ReleaseStringUTFChars(env, key, key_cstr);
    return res;
}

static void internal_stopNativeTunnel(void) {
    g_android_tunnel_running = 0;

    if (g_udp_sock >= 0) {
        close(g_udp_sock);
        g_udp_sock = -1;
    }
    for (int i = 0; i < g_num_tcp_socks; i++) {
        CLOSE_SOCK(g_tcp_socks[i]);
    }
    g_num_tcp_socks = 0;
}

/* JNI Bindings for TunnelVpnService (direct and Companion) */
JNIEXPORT jint JNICALL
Java_com_example_livekadehtunnel_TunnelVpnService_startNativeTunnel(
        JNIEnv* env, jobject thiz, jstring serverAddr, jint port, jstring key, jint mode) {
    (void)thiz;
    return internal_startNativeTunnel(env, serverAddr, port, key, mode);
}

JNIEXPORT jint JNICALL
Java_com_example_livekadehtunnel_TunnelVpnService_00024Companion_startNativeTunnel(
        JNIEnv* env, jobject thiz, jstring serverAddr, jint port, jstring key, jint mode) {
    (void)thiz;
    return internal_startNativeTunnel(env, serverAddr, port, key, mode);
}

JNIEXPORT void JNICALL
Java_com_example_livekadehtunnel_TunnelVpnService_stopNativeTunnel(JNIEnv* env, jobject thiz) {
    (void)env;
    (void)thiz;
    internal_stopNativeTunnel();
}

JNIEXPORT void JNICALL
Java_com_example_livekadehtunnel_TunnelVpnService_00024Companion_stopNativeTunnel(JNIEnv* env, jobject thiz) {
    (void)env;
    (void)thiz;
    internal_stopNativeTunnel();
}

JNIEXPORT jlong JNICALL
Java_com_example_livekadehtunnel_TunnelVpnService_getTxBytes(JNIEnv* env, jobject obj) {
    (void)env;
    (void)obj;
    return (jlong)g_traffic_tx;
}

JNIEXPORT jlong JNICALL
Java_com_example_livekadehtunnel_TunnelVpnService_00024Companion_getTxBytes(JNIEnv* env, jobject obj) {
    (void)env;
    (void)obj;
    return (jlong)g_traffic_tx;
}

JNIEXPORT jlong JNICALL
Java_com_example_livekadehtunnel_TunnelVpnService_getRxBytes(JNIEnv* env, jobject obj) {
    (void)env;
    (void)obj;
    return (jlong)g_traffic_rx;
}

JNIEXPORT jlong JNICALL
Java_com_example_livekadehtunnel_TunnelVpnService_00024Companion_getRxBytes(JNIEnv* env, jobject obj) {
    (void)env;
    (void)obj;
    return (jlong)g_traffic_rx;
}

JNIEXPORT jstring JNICALL
Java_com_example_livekadehtunnel_TunnelVpnService_getNativeLogs(JNIEnv* env, jobject obj) {
    (void)obj;
    pthread_mutex_lock(&g_log_mutex);
    jstring result = (*env)->NewStringUTF(env, g_log_buf);
    pthread_mutex_unlock(&g_log_mutex);
    return result;
}

JNIEXPORT jstring JNICALL
Java_com_example_livekadehtunnel_TunnelVpnService_00024Companion_getNativeLogs(JNIEnv* env, jobject obj) {
    (void)obj;
    pthread_mutex_lock(&g_log_mutex);
    jstring result = (*env)->NewStringUTF(env, g_log_buf);
    pthread_mutex_unlock(&g_log_mutex);
    return result;
}

JNIEXPORT void JNICALL
Java_com_example_livekadehtunnel_TunnelVpnService_clearNativeLogs(JNIEnv* env, jobject obj) {
    (void)env;
    (void)obj;
    pthread_mutex_lock(&g_log_mutex);
    g_log_buf[0] = '\0';
    g_log_len = 0;
    pthread_mutex_unlock(&g_log_mutex);
}

JNIEXPORT void JNICALL
Java_com_example_livekadehtunnel_TunnelVpnService_00024Companion_clearNativeLogs(JNIEnv* env, jobject obj) {
    (void)env;
    (void)obj;
    pthread_mutex_lock(&g_log_mutex);
    g_log_buf[0] = '\0';
    g_log_len = 0;
    pthread_mutex_unlock(&g_log_mutex);
}

JNIEXPORT void JNICALL
Java_com_example_livekadehtunnel_TunnelVpnService_setDebugMode(JNIEnv* env, jobject obj, jboolean enable) {
    (void)env;
    (void)obj;
    g_debug_mode = enable ? 1 : 0;
    LOGI("Verbose debug logging %s", g_debug_mode ? "ENABLED" : "DISABLED");
}

JNIEXPORT void JNICALL
Java_com_example_livekadehtunnel_TunnelVpnService_00024Companion_setDebugMode(JNIEnv* env, jobject obj, jboolean enable) {
    (void)env;
    (void)obj;
    g_debug_mode = enable ? 1 : 0;
    LOGI("Verbose debug logging %s", g_debug_mode ? "ENABLED" : "DISABLED");
}
