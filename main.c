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
    printf("  -l, --listen <addr>   Local listen address (port-forward mode only, default: 127.0.0.1:2222)\n");
    printf("      --port-forward    Use single port forwarding instead of virtual adapter\n");
    printf("      --app <path>      Route only this app through tunnel (WFP Per-App)\n\n");

    printf("Examples:\n");
    printf("  %s -status\n", prog);
    printf("  %s genkey\n", prog);
    printf("  %s server --tun -l 0.0.0.0:8443 -k <key>\n", prog);
    printf("  %s client -s 2.59.170.232:8443 -k <key>\n", prog);
    printf("  %s client -s 2.59.170.232:8443 --app \"C:\\Program Files\\App\\app.exe\" -k <key>\n", prog);
}

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

    /* Subcommand: client */
    if (strcmp(argv[1], "client") == 0) {
        char listen_host[256] = "127.0.0.1";
        int listen_port = 2222;
        char server_host[256] = "";
        int server_port = 8443;
        char key[512] = "";
        char app_path[MAX_PATH] = "";
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
            if (strlen(app_path) > 0) {
                p->is_per_app = 1;
                p->num_apps = 1;
                snprintf(p->app_paths[0], sizeof(p->app_paths[0]), "%s", app_path);
            }

            HANDLE h = CreateThread(NULL, 0, win_tun_client_thread, p, 0, NULL);
            if (h) WaitForSingleObject(h, INFINITE);
            net_cleanup();
            return 0;
#else
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

