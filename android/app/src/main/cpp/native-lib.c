#include <jni.h>
#include <android/log.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "TunnelNative", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "TunnelNative", __VA_ARGS__)


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
typedef struct {
    int tun_fd;
    socket_t sock;
    uint8_t master_key[32];
    volatile int running;
} android_udp_rx_worker_t;


static volatile int g_android_tunnel_running = 0;
static int g_tun_fd = -1;
static socket_t g_udp_sock = -1;


static void* android_udp_rx_thread(void* arg) {
    android_udp_rx_worker_t* w = (android_udp_rx_worker_t*)arg;
    uint8_t buf[MAX_PACKET_SIZE + UDP_HDR_SIZE];

    while (w->running && g_android_tunnel_running) {
        int n = recvfrom(w->sock, (char*)buf, sizeof(buf), 0, NULL, NULL);
        if (n <= (int)UDP_HDR_SIZE) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                // Timeout, continue
                continue;
            }
            if (n < 0) {
                // Sleep slightly on other errors
                usleep(10000);
            }
            continue;
        }

        uint8_t nonce[12];
        memcpy(nonce, buf, 12);
        size_t cipher_len = (size_t)(n - UDP_HDR_SIZE);

        uint8_t* tun_pkt = (uint8_t*)malloc(cipher_len);
        if (tun_pkt) {
            lk_chacha20_crypt_packet(w->master_key, nonce, 0, buf + UDP_HDR_SIZE, tun_pkt, cipher_len);
            write(w->tun_fd, tun_pkt, cipher_len);
            free(tun_pkt);
        }
    }
    return NULL;
}

JNIEXPORT jint JNICALL
Java_com_example_livekadehtunnel_TunnelVpnService_startNativeTunnel(
        JNIEnv* env,
        jobject /* this */,
        jint fd,
        jstring serverAddr,
        jint port,
        jstring key) {
        
    g_tun_fd = fd;
    g_android_tunnel_running = 1;

    const char *srv_addr_cstr = (*env)->GetStringUTFChars(env, serverAddr, 0);
    const char *key_cstr = (*env)->GetStringUTFChars(env, key, 0);
    
    LOGI("Starting native tunnel to %s:%d", srv_addr_cstr, port);

    g_udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_udp_sock < 0) {
        LOGE("Failed to create UDP socket");
        (*env)->ReleaseStringUTFChars(env, serverAddr, srv_addr_cstr);
        (*env)->ReleaseStringUTFChars(env, key, key_cstr);
        return -1;
    }

    struct hostent *he = gethostbyname(srv_addr_cstr);
    if (!he) {
        LOGE("Cannot resolve server address: %s", srv_addr_cstr);
        close(g_udp_sock);
        (*env)->ReleaseStringUTFChars(env, serverAddr, srv_addr_cstr);
        (*env)->ReleaseStringUTFChars(env, key, key_cstr);
        return -1;
    }

    struct sockaddr_in srv_addr_in;
    memset(&srv_addr_in, 0, sizeof(srv_addr_in));
    srv_addr_in.sin_family = AF_INET;
    srv_addr_in.sin_port = htons((uint16_t)port);
    memcpy(&srv_addr_in.sin_addr, he->h_addr_list[0], sizeof(srv_addr_in.sin_addr));

    uint8_t master_key[32];
    derive_master_key(key_cstr, master_key);

    LOGI("Sending UDP Handshake to %s:%d...", srv_addr_cstr, port);

    uint8_t c_nonce[16];
    lk_random_bytes(c_nonce, 16);

    uint8_t req[UDP_REQ_LEN];
    memcpy(req, UDP_MAGIC_REQ, 10);
    memcpy(req + 10, c_nonce, 16);
    compute_auth_tag(master_key, "LK-UDP-AUTH", c_nonce, req + 26);

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 500000;
    setsockopt(g_udp_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int ack_received = 0;
    for (int attempt = 1; attempt <= 4; attempt++) {
        sendto(g_udp_sock, (char*)req, UDP_REQ_LEN, 0, (struct sockaddr *)&srv_addr_in, sizeof(srv_addr_in));
        
        uint8_t ack_buf[UDP_ACK_LEN];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        int n = recvfrom(g_udp_sock, (char*)ack_buf, UDP_ACK_LEN, 0, (struct sockaddr *)&from, &from_len);
        
        if (n == UDP_ACK_LEN && memcmp(ack_buf, UDP_MAGIC_ACK, 10) == 0) {
            uint8_t exp_tag[16];
            compute_auth_tag(master_key, "LK-UDP-ACK", ack_buf + 10, exp_tag);
            if (memcmp(exp_tag, ack_buf + 26, 16) == 0) {
                ack_received = 1;
                LOGI("Authentication successful!");
                break;
            }
        }
    }

    if (!ack_received) {
        LOGE("Failed to connect or authenticate to server!");
        close(g_udp_sock);
        (*env)->ReleaseStringUTFChars(env, serverAddr, srv_addr_cstr);
        (*env)->ReleaseStringUTFChars(env, key, key_cstr);
        return -1;
    }

    android_udp_rx_worker_t rx_worker;
    rx_worker.tun_fd = g_tun_fd;
    rx_worker.sock = g_udp_sock;
    memcpy(rx_worker.master_key, master_key, 32);
    rx_worker.running = 1;

    pthread_t rx_tid;
    pthread_create(&rx_tid, NULL, android_udp_rx_thread, &rx_worker);

    uint32_t counter = 0;
    uint8_t packet[MAX_PACKET_SIZE];
    uint8_t udp_buf[MAX_PACKET_SIZE + UDP_HDR_SIZE];

    while (g_android_tunnel_running) {
        int packet_size = read(g_tun_fd, packet, sizeof(packet));
        if (packet_size > 0) {
            counter++;
            uint8_t nonce[12];
            memset(nonce, 0, 12);
            nonce[0] = (counter >> 24) & 0xFF;
            nonce[1] = (counter >> 16) & 0xFF;
            nonce[2] = (counter >> 8) & 0xFF;
            nonce[3] = counter & 0xFF;

            memcpy(udp_buf, nonce, 12);
            lk_chacha20_crypt_packet(master_key, nonce, 0, packet, udp_buf + UDP_HDR_SIZE, packet_size);
            
            sendto(g_udp_sock, (char*)udp_buf, packet_size + UDP_HDR_SIZE, 0, (struct sockaddr *)&srv_addr_in, sizeof(srv_addr_in));
        } else if (packet_size < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue;
            } else {
                LOGE("TUN read error: %s", strerror(errno));
                break;
            }
        }
    }

    rx_worker.running = 0;
    pthread_join(rx_tid, NULL);

    close(g_udp_sock);
    (*env)->ReleaseStringUTFChars(env, serverAddr, srv_addr_cstr);
    (*env)->ReleaseStringUTFChars(env, key, key_cstr);
    return 0;
}

JNIEXPORT void JNICALL
Java_com_example_livekadehtunnel_TunnelVpnService_stopNativeTunnel(
        JNIEnv* env,
        jobject /* this */) {
    g_android_tunnel_running = 0;
    if (g_tun_fd >= 0) {
        close(g_tun_fd);
        g_tun_fd = -1;
    }
}
