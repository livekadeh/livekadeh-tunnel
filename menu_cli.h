#ifndef LIVEKADEH_MENU_CLI_H
#define LIVEKADEH_MENU_CLI_H

#include <stdio.h>
#include <string.h>
#include "tunnel_common.h"

static inline void trim_newline(char *str) {
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == '\r' || str[len - 1] == '\n' || str[len - 1] == ' ')) {
        str[--len] = '\0';
    }
}

static inline void run_interactive_cli_menu(void) {
    char choice[32];

    while (1) {
        printf("\n===================================================\n");
        printf("       Livekadeh Tunnel (لایوکده تانل)\n");
        printf("===================================================\n");
        printf("  [1] Start Tunnel Server\n");
        printf("  [2] Start Tunnel Client\n");
        printf("  [3] Generate Secure Encryption Key\n");
        printf("  [4] Exit\n");
        printf("===================================================\n");
        printf("Select an option [1-4]: ");
        fflush(stdout);

        if (!fgets(choice, sizeof(choice), stdin)) {
            break;
        }
        trim_newline(choice);

        if (strcmp(choice, "1") == 0) {
            char listen_input[128] = "";
            char target_input[128] = "";
            char key_input[512] = "";

            char listen_host[256] = "0.0.0.0";
            int listen_port = 8443;
            char target_host[256] = "127.0.0.1";
            int target_port = 22;

            printf("\n--- Server Configuration ---\n");
            printf("Tunnel Listen Address [0.0.0.0:8443]: ");
            fflush(stdout);
            if (fgets(listen_input, sizeof(listen_input), stdin)) {
                trim_newline(listen_input);
                if (strlen(listen_input) > 0) {
                    parse_host_port(listen_input, listen_host, sizeof(listen_host), &listen_port);
                }
            }

            printf("Target Service Address (e.g. SSH) [127.0.0.1:22]: ");
            fflush(stdout);
            if (fgets(target_input, sizeof(target_input), stdin)) {
                trim_newline(target_input);
                if (strlen(target_input) > 0) {
                    parse_host_port(target_input, target_host, sizeof(target_host), &target_port);
                }
            }

            printf("Encryption Key (leave blank to auto-generate): ");
            fflush(stdout);
            if (fgets(key_input, sizeof(key_input), stdin)) {
                trim_newline(key_input);
            }

            if (strlen(key_input) == 0) {
                if (generate_random_key_hex(key_input, sizeof(key_input)) == 0) {
                    printf("\n=======================================================\n");
                    printf("[+] Auto-Generated Encryption Key:\n");
                    printf("    %s\n", key_input);
                    printf("    (Share this exact key with the client!)\n");
                    printf("=======================================================\n\n");
                } else {
                    fprintf(stderr, "Failed to generate random key.\n");
                    continue;
                }
            }

            run_tunnel_server(listen_host, listen_port, target_host, target_port, key_input);
            break;

        } else if (strcmp(choice, "2") == 0) {
            char server_input[128] = "";
            char listen_input[128] = "";
            char key_input[512] = "";

            char server_host[256] = "";
            int server_port = 8443;
            char listen_host[256] = "127.0.0.1";
            int listen_port = 2222;

            printf("\n--- Client Configuration ---\n");
            printf("Remote Tunnel Server Host:Port (e.g. 5.160.109.229:8443): ");
            fflush(stdout);
            if (fgets(server_input, sizeof(server_input), stdin)) {
                trim_newline(server_input);
                if (strlen(server_input) > 0) {
                    parse_host_port(server_input, server_host, sizeof(server_host), &server_port);
                }
            }

            if (strlen(server_host) == 0) {
                printf("[Error] Remote server address cannot be empty.\n");
                continue;
            }

            printf("Local Listen Port [127.0.0.1:2222]: ");
            fflush(stdout);
            if (fgets(listen_input, sizeof(listen_input), stdin)) {
                trim_newline(listen_input);
                if (strlen(listen_input) > 0) {
                    parse_host_port(listen_input, listen_host, sizeof(listen_host), &listen_port);
                }
            }

            printf("Encryption Key: ");
            fflush(stdout);
            if (fgets(key_input, sizeof(key_input), stdin)) {
                trim_newline(key_input);
            }

            if (strlen(key_input) == 0) {
                printf("[Error] Encryption key cannot be empty.\n");
                continue;
            }

            run_tunnel_client(listen_host, listen_port, server_host, server_port, key_input);
            break;

        } else if (strcmp(choice, "3") == 0) {
            char new_key[128];
            if (generate_random_key_hex(new_key, sizeof(new_key)) == 0) {
                printf("\n---------------------------------------------------\n");
                printf("Fresh 256-Bit Encryption Key:\n");
                printf("%s\n", new_key);
                printf("---------------------------------------------------\n");
            } else {
                printf("[Error] Could not generate random key.\n");
            }
            printf("Press Enter to return to menu...");
            fflush(stdout);
            getchar();

        } else if (strcmp(choice, "4") == 0 || strcmp(choice, "q") == 0) {
            printf("Exiting Livekadeh Tunnel. Goodbye!\n");
            break;
        } else {
            printf("Invalid selection. Please enter 1, 2, 3, or 4.\n");
        }
    }
}

#endif /* LIVEKADEH_MENU_CLI_H */
