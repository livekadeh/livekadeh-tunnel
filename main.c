#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tunnel_common.h"
#include "menu_cli.h"
#include "tun_proto.h"

#ifdef _WIN32
#include "gui_win32.h"
#endif

static void print_status(void) {
    printf("\n==================================================================\n");
    printf("       Livekadeh Tunnel Status (v%s)\n", LIVEKADEH_VERSION);
    printf("==================================================================\n");
#ifndef _WIN32
    int is_running = (system("pgrep -f 'livekadeh_tunnel server|livekadeh server' >/dev/null 2>&1") == 0);
    printf(" Service/Process: %s\n", is_running ? "RUNNING (Active)" : "STOPPED (Inactive)");

    char saved_key[512] = "";
    FILE *fk = fopen("/etc/livekadeh_tunnel.key", "r");
    if (!fk) fk = fopen("/tmp/livekadeh_tunnel.key", "r");
    if (fk) {
        if (fgets(saved_key, sizeof(saved_key), fk)) {
            char *p = strchr(saved_key, '\n'); if (p) *p = 0;
            p = strchr(saved_key, '\r'); if (p) *p = 0;
        }
        fclose(fk);
    }
    if (strlen(saved_key) == 0) {
        FILE *fs = popen("grep -oP '(?<=-k )[a-f0-9]+' /etc/systemd/system/livekadeh-tunnel.service 2>/dev/null", "r");
        if (fs) {
            if (fgets(saved_key, sizeof(saved_key), fs)) {
                char *p = strchr(saved_key, '\n'); if (p) *p = 0;
                p = strchr(saved_key, '\r'); if (p) *p = 0;
            }
            pclose(fs);
        }
    }
    if (strlen(saved_key) > 0) {
        printf(" Encryption Key:  %s\n", saved_key);
    } else {
        printf(" Encryption Key:  [Not found / Not configured]\n");
    }

    if (access("/sys/class/net/tun0", F_OK) == 0) {
        printf(" TUN Interface:   tun0 (10.10.10.1) [ONLINE]\n");
        unsigned long long rx = 0, tx = 0;
        FILE *frx = fopen("/sys/class/net/tun0/statistics/rx_bytes", "r");
        if (frx) { if (fscanf(frx, "%llu", &rx) != 1) rx = 0; fclose(frx); }
        FILE *ftx = fopen("/sys/class/net/tun0/statistics/tx_bytes", "r");
        if (ftx) { if (fscanf(ftx, "%llu", &tx) != 1) tx = 0; fclose(ftx); }
        printf(" Traffic Stats:   Sent: %.2f MB | Recv: %.2f MB\n",
               (double)tx / (1024.0 * 1024.0), (double)rx / (1024.0 * 1024.0));
    } else {
        printf(" TUN Interface:   tun0 [OFFLINE]\n");
    }
#else
    printf(" Platform:        Windows x86_64\n");
    printf(" Adapter:         LivekadehAdapter (Wintun)\n");
    printf(" Default Subnet:  10.10.10.2 <-> 10.10.10.1\n");
#endif
    printf("==================================================================\n\n");
}

static void print_main_help(const char *prog) {
    printf("Livekadeh Tunnel v%s - Unified Transport & Wintun VPN Adapter\n\n", LIVEKADEH_VERSION);
    printf("Usage:\n");
    printf("  %s <command> [options]\n\n", prog);
    printf("Commands:\n");
    printf("  server                Run in server mode\n");
    printf("  client                Run in client mode (defaults to Wintun adapter on Windows)\n");
    printf("  speedtest             Run in-tunnel performance benchmark (default: 10.10.10.1:9090)\n");
    printf("  status, -status       Show service status, active key, and interface traffic\n");
    printf("  genkey                Generate a fresh 256-bit encryption key\n");
    printf("  --menu                Launch interactive terminal menu\n");
#ifdef _WIN32
    printf("  --gui                 Launch graphical Windows interface\n");
#endif
    printf("  -v, --version         Show version information\n");
    printf("  -h, --help            Show this help message\n\n");

    printf("Server Options:\n");
    printf("  -l, --listen <addr>   Listen address (default: 0.0.0.0:8443)\n");
    printf("  -t, --target <addr>   Target service (default: 127.0.0.1:22, ignored in --tun mode)\n");
    printf("  -k, --key <key>       Shared secret key (auto-generated if omitted)\n");
    printf("      --tun             Enable L3 VPN mode (all server ports accessible at 10.10.10.1)\n\n");

    printf("Client Options:\n");
    printf("  -s, --server <addr>   Remote tunnel server address (required)\n");
    printf("  -k, --key <key>       Shared secret key (required)\n");
    printf("  -c, --conns <1|4|8>   Number of TCP lanes (default: 8, set 1 for single-TCP)\n");
    printf("  -u, --udp             Use UDP datagram transport (fast, low-latency, stateless)\n");
    printf("  -l, --listen <addr>   Local listen address (port-forward mode only, default: 127.0.0.1:2222)\n");
    printf("      --port-forward    Use single port forwarding instead of virtual adapter\n");
    printf("      --app <path>      Route only this app through tunnel (WFP Per-App)\n\n");

    printf("Examples:\n");
    printf("  %s -status\n", prog);
    printf("  %s genkey\n", prog);
    printf("  %s server --tun -l 0.0.0.0:8443 -k <key>\n", prog);
    printf("  %s client -s 2.59.170.232:8443 -k <key> -c 8\n", prog);
    printf("  %s client -s 2.59.170.232:8443 --app \"C:\\Program Files\\App\\app.exe\" -k <key>\n", prog);
    printf("  %s speedtest -s 10.10.10.1 -c 8\n", prog);
}

typedef struct {
    char host[256];
    int port;
    uint64_t bytes;
    volatile int stop;
} cli_st_worker_t;

#ifndef _WIN32
static void *cli_dl_thread_fn(void *arg) {
    cli_st_worker_t *w = (cli_st_worker_t *)arg;
    w->bytes = 0;
    socket_t s = connect_remote(w->host, w->port);
    if (!IS_VALIDSOCK(s)) return NULL;
    tune_tunnel_socket(s);

    if (send(s, "DOWNLOAD\n", 9, 0) != 9) {
        CLOSE_SOCK(s);
        return NULL;
    }

    char buf[65536];
    while (!w->stop) {
        int r = recv(s, buf, sizeof(buf), 0);
        if (r <= 0) break;
        w->bytes += r;
    }
    CLOSE_SOCK(s);
    return NULL;
}

static void *cli_ul_thread_fn(void *arg) {
    cli_st_worker_t *w = (cli_st_worker_t *)arg;
    w->bytes = 0;
    socket_t s = connect_remote(w->host, w->port);
    if (!IS_VALIDSOCK(s)) return NULL;
    tune_tunnel_socket(s);

    if (send(s, "UPLOAD\n", 7, 0) != 7) {
        CLOSE_SOCK(s);
        return NULL;
    }

    char buf[65536];
    memset(buf, 0x5A, sizeof(buf));
    while (!w->stop) {
        int r = send(s, buf, sizeof(buf), 0);
        if (r <= 0) break;
        w->bytes += r;
    }
    CLOSE_SOCK(s);
    return NULL;
}

static void run_speedtest_cli(const char *target_host, int target_port, int streams) {
    printf("\n==================================================================\n");
    printf("         Livekadeh Tunnel Speed Test Benchmark (v%s)\n", LIVEKADEH_VERSION);
    printf("==================================================================\n");
    printf(" Target Server: %s:%d\n", target_host, target_port);
    printf(" Streams:       %d parallel stream(s)\n", streams);
    printf("==================================================================\n\n");

    printf("[1/3] Measuring Latency (4 probes)...\n");
    double pings[4];
    int p_ok = 0;
    for (int i = 0; i < 4; i++) {
        struct timespec ts0, ts1;
        clock_gettime(CLOCK_MONOTONIC, &ts0);
        socket_t s = connect_remote(target_host, target_port);
        if (IS_VALIDSOCK(s)) {
            tune_tunnel_socket(s);
            if (send(s, "PING\n", 5, 0) == 5) {
                char resp[32];
                int r = recv(s, resp, sizeof(resp) - 1, 0);
                if (r > 0 && strncmp(resp, "PONG", 4) == 0) {
                    clock_gettime(CLOCK_MONOTONIC, &ts1);
                    double ms = (ts1.tv_sec - ts0.tv_sec) * 1000.0 + (ts1.tv_nsec - ts0.tv_nsec) / 1000000.0;
                    pings[p_ok++] = ms;
                    printf("      Probe %d: %.1f ms\n", i + 1, ms);
                }
            }
            CLOSE_SOCK(s);
        }
        usleep(50000);
    }

    if (p_ok == 0) {
        fprintf(stderr, "\n[-] ERROR: Failed to reach speedtest server at %s:%d.\n", target_host, target_port);
        fprintf(stderr, "    Verify tunnel connection and ensure livekadeh-tunnel is running.\n\n");
        return;
    }

    double sum_p = 0, min_p = 999999.0;
    for (int i = 0; i < p_ok; i++) {
        sum_p += pings[i];
        if (pings[i] < min_p) min_p = pings[i];
    }
    double avg_p = sum_p / p_ok;
    printf("  --> Latency: Avg %.1f ms | Min %.1f ms\n\n", avg_p, min_p);

    printf("[2/3] Running Download throughput test (%d streams)...\n", streams);
    pthread_t dl_tids[8];
    cli_st_worker_t dl_workers[8];
    struct timespec dl_t0, dl_t1;
    clock_gettime(CLOCK_MONOTONIC, &dl_t0);

    for (int i = 0; i < streams; i++) {
        snprintf(dl_workers[i].host, sizeof(dl_workers[i].host), "%s", target_host);
        dl_workers[i].port = target_port;
        dl_workers[i].bytes = 0;
        dl_workers[i].stop = 0;
        pthread_create(&dl_tids[i], NULL, cli_dl_thread_fn, &dl_workers[i]);
    }

    for (int i = 0; i < streams; i++) {
        pthread_join(dl_tids[i], NULL);
    }
    clock_gettime(CLOCK_MONOTONIC, &dl_t1);

    uint64_t total_dl = 0;
    for (int i = 0; i < streams; i++) total_dl += dl_workers[i].bytes;

    double dl_sec = (dl_t1.tv_sec - dl_t0.tv_sec) + (dl_t1.tv_nsec - dl_t0.tv_nsec) / 1000000000.0;
    if (dl_sec < 0.5) dl_sec = 0.5;
    double dl_mbps = ((double)total_dl * 8.0) / (dl_sec * 1000000.0);
    double dl_mbs = (double)total_dl / (dl_sec * 1024.0 * 1024.0);
    printf("  --> Download Speed: %.2f Mbps (%.2f MB/s) [%.2f MB in %.1fs]\n\n",
           dl_mbps, dl_mbs, (double)total_dl / (1024.0 * 1024.0), dl_sec);

    printf("[3/3] Running Upload throughput test (%d streams)...\n", streams);
    pthread_t ul_tids[8];
    cli_st_worker_t ul_workers[8];
    struct timespec ul_t0, ul_t1;
    clock_gettime(CLOCK_MONOTONIC, &ul_t0);

    for (int i = 0; i < streams; i++) {
        snprintf(ul_workers[i].host, sizeof(ul_workers[i].host), "%s", target_host);
        ul_workers[i].port = target_port;
        ul_workers[i].bytes = 0;
        ul_workers[i].stop = 0;
        pthread_create(&ul_tids[i], NULL, cli_ul_thread_fn, &ul_workers[i]);
    }

    usleep(3500000);
    for (int i = 0; i < streams; i++) ul_workers[i].stop = 1;

    for (int i = 0; i < streams; i++) {
        pthread_join(ul_tids[i], NULL);
    }
    clock_gettime(CLOCK_MONOTONIC, &ul_t1);

    uint64_t total_ul = 0;
    for (int i = 0; i < streams; i++) total_ul += ul_workers[i].bytes;

    double ul_sec = (ul_t1.tv_sec - ul_t0.tv_sec) + (ul_t1.tv_nsec - ul_t0.tv_nsec) / 1000000000.0;
    if (ul_sec < 0.5) ul_sec = 0.5;
    double ul_mbps = ((double)total_ul * 8.0) / (ul_sec * 1000000.0);
    double ul_mbs = (double)total_ul / (ul_sec * 1024.0 * 1024.0);
    printf("  --> Upload Speed:   %.2f Mbps (%.2f MB/s) [%.2f MB in %.1fs]\n\n",
           ul_mbps, ul_mbs, (double)total_ul / (1024.0 * 1024.0), ul_sec);

    printf("==================================================================\n");
    printf(" Benchmark Summary: Ping: %.1f ms | Down: %.2f Mbps | Up: %.2f Mbps\n",
           avg_p, dl_mbps, ul_mbps);
    printf("==================================================================\n\n");
}
#else
static DWORD WINAPI win_cli_dl_thread_fn(LPVOID arg) {
    cli_st_worker_t *w = (cli_st_worker_t *)arg;
    w->bytes = 0;
    socket_t s = connect_remote(w->host, w->port);
    if (!IS_VALIDSOCK(s)) return 0;
    tune_tunnel_socket(s);

    if (send(s, "DOWNLOAD\n", 9, 0) != 9) {
        CLOSE_SOCK(s);
        return 0;
    }

    char buf[65536];
    while (!w->stop) {
        int r = recv(s, buf, sizeof(buf), 0);
        if (r <= 0) break;
        w->bytes += r;
    }
    CLOSE_SOCK(s);
    return 0;
}

static DWORD WINAPI win_cli_ul_thread_fn(LPVOID arg) {
    cli_st_worker_t *w = (cli_st_worker_t *)arg;
    w->bytes = 0;
    socket_t s = connect_remote(w->host, w->port);
    if (!IS_VALIDSOCK(s)) return 0;
    tune_tunnel_socket(s);

    if (send(s, "UPLOAD\n", 7, 0) != 7) {
        CLOSE_SOCK(s);
        return 0;
    }

    char buf[65536];
    memset(buf, 0x5A, sizeof(buf));
    while (!w->stop) {
        int r = send(s, buf, sizeof(buf), 0);
        if (r <= 0) break;
        w->bytes += r;
    }
    CLOSE_SOCK(s);
    return 0;
}

static void run_speedtest_cli(const char *target_host, int target_port, int streams) {
    printf("\n==================================================================\n");
    printf("         Livekadeh Tunnel Speed Test Benchmark (v%s)\n", LIVEKADEH_VERSION);
    printf("==================================================================\n");
    printf(" Target Server: %s:%d\n", target_host, target_port);
    printf(" Streams:       %d parallel stream(s)\n", streams);
    printf("==================================================================\n\n");

    printf("[1/3] Measuring Latency (4 probes)...\n");
    double pings[4];
    int p_ok = 0;
    for (int i = 0; i < 4; i++) {
        DWORD t0 = GetTickCount();
        socket_t s = connect_remote(target_host, target_port);
        if (IS_VALIDSOCK(s)) {
            tune_tunnel_socket(s);
            if (send(s, "PING\n", 5, 0) == 5) {
                char resp[32];
                int r = recv(s, resp, sizeof(resp) - 1, 0);
                if (r > 0 && strncmp(resp, "PONG", 4) == 0) {
                    DWORD elapsed = GetTickCount() - t0;
                    pings[p_ok++] = (double)elapsed;
                    printf("      Probe %d: %lu ms\n", i + 1, elapsed);
                }
            }
            CLOSE_SOCK(s);
        }
        Sleep(50);
    }

    if (p_ok == 0) {
        fprintf(stderr, "\n[-] ERROR: Failed to reach speedtest server at %s:%d.\n", target_host, target_port);
        fprintf(stderr, "    Verify tunnel connection and ensure livekadeh-tunnel is running.\n\n");
        return;
    }

    double sum_p = 0, min_p = 999999.0;
    for (int i = 0; i < p_ok; i++) {
        sum_p += pings[i];
        if (pings[i] < min_p) min_p = pings[i];
    }
    double avg_p = sum_p / p_ok;
    printf("  --> Latency: Avg %.1f ms | Min %.1f ms\n\n", avg_p, min_p);

    printf("[2/3] Running Download throughput test (%d streams)...\n", streams);
    HANDLE dl_threads[8];
    cli_st_worker_t dl_workers[8];
    DWORD dl_t0 = GetTickCount();

    for (int i = 0; i < streams; i++) {
        snprintf(dl_workers[i].host, sizeof(dl_workers[i].host), "%s", target_host);
        dl_workers[i].port = target_port;
        dl_workers[i].bytes = 0;
        dl_workers[i].stop = 0;
        dl_threads[i] = CreateThread(NULL, 0, win_cli_dl_thread_fn, &dl_workers[i], 0, NULL);
    }

    WaitForMultipleObjects(streams, dl_threads, TRUE, 6000);
    DWORD dl_elapsed = GetTickCount() - dl_t0;
    for (int i = 0; i < streams; i++) {
        dl_workers[i].stop = 1;
        if (dl_threads[i]) CloseHandle(dl_threads[i]);
    }

    uint64_t total_dl = 0;
    for (int i = 0; i < streams; i++) total_dl += dl_workers[i].bytes;

    double dl_sec = (double)dl_elapsed / 1000.0;
    if (dl_sec < 0.5) dl_sec = 0.5;
    double dl_mbps = ((double)total_dl * 8.0) / (dl_sec * 1000000.0);
    double dl_mbs = (double)total_dl / (dl_sec * 1024.0 * 1024.0);
    printf("  --> Download Speed: %.2f Mbps (%.2f MB/s) [%.2f MB in %.1fs]\n\n",
           dl_mbps, dl_mbs, (double)total_dl / (1024.0 * 1024.0), dl_sec);

    printf("[3/3] Running Upload throughput test (%d streams)...\n", streams);
    HANDLE ul_threads[8];
    cli_st_worker_t ul_workers[8];
    DWORD ul_t0 = GetTickCount();

    for (int i = 0; i < streams; i++) {
        snprintf(ul_workers[i].host, sizeof(ul_workers[i].host), "%s", target_host);
        ul_workers[i].port = target_port;
        ul_workers[i].bytes = 0;
        ul_workers[i].stop = 0;
        ul_threads[i] = CreateThread(NULL, 0, win_cli_ul_thread_fn, &ul_workers[i], 0, NULL);
    }

    Sleep(3500);
    for (int i = 0; i < streams; i++) ul_workers[i].stop = 1;

    WaitForMultipleObjects(streams, ul_threads, TRUE, 2000);
    DWORD ul_elapsed = GetTickCount() - ul_t0;
    for (int i = 0; i < streams; i++) {
        if (ul_threads[i]) CloseHandle(ul_threads[i]);
    }

    uint64_t total_ul = 0;
    for (int i = 0; i < streams; i++) total_ul += ul_workers[i].bytes;

    double ul_sec = (double)ul_elapsed / 1000.0;
    if (ul_sec < 0.5) ul_sec = 0.5;
    double ul_mbps = ((double)total_ul * 8.0) / (ul_sec * 1000000.0);
    double ul_mbs = (double)total_ul / (ul_sec * 1024.0 * 1024.0);
    printf("  --> Upload Speed:   %.2f Mbps (%.2f MB/s) [%.2f MB in %.1fs]\n\n",
           ul_mbps, ul_mbs, (double)total_ul / (1024.0 * 1024.0), ul_sec);

    printf("==================================================================\n");
    printf(" Benchmark Summary: Ping: %.1f ms | Down: %.2f Mbps | Up: %.2f Mbps\n",
           avg_p, dl_mbps, ul_mbps);
    printf("==================================================================\n\n");
}
#endif

int main(int argc, char **argv) {
    net_init();

#ifdef _WIN32
    /* If run without arguments, check if we should launch GUI */
    if (argc <= 1) {
        return run_win32_gui(GetModuleHandle(NULL), SW_SHOW);
    }
    if (strcmp(argv[1], "--gui") == 0) {
        return run_win32_gui(GetModuleHandle(NULL), SW_SHOW);
    }
#else
    if (argc <= 1) {
        run_interactive_cli_menu();
        net_cleanup();
        return 0;
    }
#endif

    if (strcmp(argv[1], "--menu") == 0) {
        run_interactive_cli_menu();
        net_cleanup();
        return 0;
    }

    if (strcmp(argv[1], "status") == 0 || strcmp(argv[1], "-status") == 0 || strcmp(argv[1], "--status") == 0) {
        print_status();
        net_cleanup();
        return 0;
    }

    if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-version") == 0 || strcmp(argv[1], "version") == 0) {
        printf("Livekadeh Tunnel v%s\n", LIVEKADEH_VERSION);
        net_cleanup();
        return 0;
    }

    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "help") == 0) {
        print_main_help(argv[0]);
        net_cleanup();
        return 0;
    }

    if (strcmp(argv[1], "genkey") == 0) {
        char key_hex[128];
        if (generate_random_key_hex(key_hex, sizeof(key_hex)) == 0) {
            printf("\n-------------------------------------------------------\n");
            printf("[+] Generated 256-Bit Cryptographic Key:\n");
            printf("    %s\n", key_hex);
            printf("-------------------------------------------------------\n\n");
        } else {
            fprintf(stderr, "Failed to generate key.\n");
        }
        net_cleanup();
        return 0;
    }

    /* Subcommand: server */
    if (strcmp(argv[1], "server") == 0) {
        char listen_host[256] = "0.0.0.0";
        int listen_port = 8443;
        char target_host[256] = "127.0.0.1";
        int target_port = 22;
        char key[512] = "";
        int tun_mode = 0;

        for (int i = 2; i < argc; ++i) {
            if ((strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--listen") == 0) && i + 1 < argc) {
                parse_host_port(argv[++i], listen_host, sizeof(listen_host), &listen_port);
            } else if ((strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--target") == 0) && i + 1 < argc) {
                parse_host_port(argv[++i], target_host, sizeof(target_host), &target_port);
            } else if ((strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--key") == 0) && i + 1 < argc) {
                snprintf(key, sizeof(key), "%s", argv[++i]);
            } else if (strcmp(argv[i], "--tun") == 0) {
                tun_mode = 1;
            } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                print_main_help(argv[0]);
                net_cleanup();
                return 0;
            }
        }

        if (strlen(key) == 0) {
            generate_random_key_hex(key, sizeof(key));
            printf("\n=======================================================\n");
            printf("[+] Auto-Generated Encryption Key:\n");
            printf("    %s\n", key);
            printf("    (Share this exact key with the client!)\n");
            printf("=======================================================\n\n");
        }

        if (tun_mode) {
#ifndef _WIN32
            int res = run_linux_tun_server(listen_port, key);
            net_cleanup();
            return res;
#else
            fprintf(stderr, "[Error] TUN server mode is only supported on Linux host.\n");
            net_cleanup();
            return 1;
#endif
        } else {
            int res = run_tunnel_server(listen_host, listen_port, target_host, target_port, key);
            net_cleanup();
            return res;
        }
    }

    /* Subcommand: speedtest */
    if (strcmp(argv[1], "speedtest") == 0) {
        char target_host[256] = "10.10.10.1";
        int target_port = SPEEDTEST_PORT;
        int streams = 8;
        for (int i = 2; i < argc; ++i) {
            if ((strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--server") == 0) && i + 1 < argc) {
                parse_host_port(argv[++i], target_host, sizeof(target_host), &target_port);
            } else if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) && i + 1 < argc) {
                target_port = atoi(argv[++i]);
            } else if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--conns") == 0) && i + 1 < argc) {
                streams = atoi(argv[++i]);
                if (streams < 1) streams = 1;
                if (streams > 8) streams = 8;
            } else if (argv[i][0] != '-') {
                parse_host_port(argv[i], target_host, sizeof(target_host), &target_port);
            }
        }
        run_speedtest_cli(target_host, target_port, streams);
        net_cleanup();
        return 0;
    }

    /* Subcommand: client */
    if (strcmp(argv[1], "client") == 0) {
        char listen_host[256] = "127.0.0.1";
        int listen_port = 2222;
        char server_host[256] = "";
        int server_port = 8443;
        char key[512] = "";
        char app_path[MAX_PATH] = "";
        int max_conns = NUM_TUNNEL_CONNS;
        int is_udp = 0;
#ifdef _WIN32
        int tun_mode = 1;
#else
        int tun_mode = 0;
#endif

        for (int i = 2; i < argc; ++i) {
            if ((strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--server") == 0) && i + 1 < argc) {
                parse_host_port(argv[++i], server_host, sizeof(server_host), &server_port);
            } else if ((strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--listen") == 0) && i + 1 < argc) {
                parse_host_port(argv[++i], listen_host, sizeof(listen_host), &listen_port);
            } else if ((strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--key") == 0) && i + 1 < argc) {
                snprintf(key, sizeof(key), "%s", argv[++i]);
            } else if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--conns") == 0) && i + 1 < argc) {
                max_conns = atoi(argv[++i]);
                if (max_conns < 1) max_conns = 1;
                if (max_conns > NUM_TUNNEL_CONNS) max_conns = NUM_TUNNEL_CONNS;
            } else if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--udp") == 0) {
                is_udp = 1;
            } else if (strcmp(argv[i], "--app") == 0 && i + 1 < argc) {
                snprintf(app_path, sizeof(app_path), "%s", argv[++i]);
                tun_mode = 1;
            } else if (strcmp(argv[i], "--tun") == 0) {
                tun_mode = 1;
            } else if (strcmp(argv[i], "--port-forward") == 0) {
                tun_mode = 0;
            } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                print_main_help(argv[0]);
                net_cleanup();
                return 0;
            }
        }

        if (strlen(server_host) == 0) {
            fprintf(stderr, "[Error] Remote server (-s / --server) is required.\n\n");
            print_main_help(argv[0]);
            net_cleanup();
            return 1;
        }

        if (strlen(key) == 0) {
            fprintf(stderr, "[Error] Encryption key (-k / --key) is required.\n\n");
            print_main_help(argv[0]);
            net_cleanup();
            return 1;
        }

        if (tun_mode) {
#ifdef _WIN32
            win_tun_client_params_t *p = (win_tun_client_params_t *)malloc(sizeof(win_tun_client_params_t));
            memset(p, 0, sizeof(*p));
            snprintf(p->server_host, sizeof(p->server_host), "%s", server_host);
            p->server_port = server_port;
            snprintf(p->key, sizeof(p->key), "%s", key);
            p->max_conns = max_conns;
            p->is_udp = is_udp;
            if (strlen(app_path) > 0) {
                p->is_per_app = 1;
                p->num_apps = 1;
                snprintf(p->app_paths[0], sizeof(p->app_paths[0]), "%s", app_path);
            }

            HANDLE h = CreateThread(NULL, 0, is_udp ? win_tun_udp_client_thread : win_tun_client_thread, p, 0, NULL);
            if (h) WaitForSingleObject(h, INFINITE);
            net_cleanup();
            return 0;
#else
            (void)is_udp;
            fprintf(stderr, "[Error] Wintun client mode is for Windows.\n");
            net_cleanup();
            return 1;
#endif
        } else {
            int res = run_tunnel_client(listen_host, listen_port, server_host, server_port, key);
            net_cleanup();
            return res;
        }
    }

    fprintf(stderr, "Unknown command or option: %s\n\n", argv[1]);
    print_main_help(argv[0]);
    net_cleanup();
    return 1;
}

