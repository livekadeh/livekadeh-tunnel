#ifndef LIVEKADEH_TUN_WINTUN_H
#define LIVEKADEH_TUN_WINTUN_H

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fwpmu.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include "wintun.h"

/* Wintun dynamic function pointers */
static HMODULE g_hWintun = NULL;
static WINTUN_CREATE_ADAPTER_FUNC *pWintunCreateAdapter = NULL;
static WINTUN_OPEN_ADAPTER_FUNC *pWintunOpenAdapter = NULL;
static WINTUN_CLOSE_ADAPTER_FUNC *pWintunCloseAdapter = NULL;
static WINTUN_START_SESSION_FUNC *pWintunStartSession = NULL;
static WINTUN_END_SESSION_FUNC *pWintunEndSession = NULL;
static WINTUN_GET_READ_WAIT_EVENT_FUNC *pWintunGetReadWaitEvent = NULL;
static WINTUN_RECEIVE_PACKET_FUNC *pWintunReceivePacket = NULL;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC *pWintunReleaseReceivePacket = NULL;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC *pWintunAllocateSendPacket = NULL;
static WINTUN_SEND_PACKET_FUNC *pWintunSendPacket = NULL;
static WINTUN_GET_ADAPTER_LUID_FUNC *pWintunGetAdapterLUID = NULL;

static inline int wintun_load_dll(void) {
    if (g_hWintun) return 0;

    g_hWintun = LoadLibraryA("wintun.dll");
    if (!g_hWintun) {
        /* Try relative path in executable directory */
        g_hWintun = LoadLibraryA(".\\wintun.dll");
        if (!g_hWintun) {
            fprintf(stderr, "[Error] Failed to load wintun.dll. Please ensure wintun.dll is in the same directory.\n");
            return -1;
        }
    }

    pWintunCreateAdapter        = (WINTUN_CREATE_ADAPTER_FUNC *)GetProcAddress(g_hWintun, "WintunCreateAdapter");
    pWintunOpenAdapter          = (WINTUN_OPEN_ADAPTER_FUNC *)GetProcAddress(g_hWintun, "WintunOpenAdapter");
    pWintunCloseAdapter         = (WINTUN_CLOSE_ADAPTER_FUNC *)GetProcAddress(g_hWintun, "WintunCloseAdapter");
    pWintunStartSession         = (WINTUN_START_SESSION_FUNC *)GetProcAddress(g_hWintun, "WintunStartSession");
    pWintunEndSession           = (WINTUN_END_SESSION_FUNC *)GetProcAddress(g_hWintun, "WintunEndSession");
    pWintunGetReadWaitEvent     = (WINTUN_GET_READ_WAIT_EVENT_FUNC *)GetProcAddress(g_hWintun, "WintunGetReadWaitEvent");
    pWintunReceivePacket        = (WINTUN_RECEIVE_PACKET_FUNC *)GetProcAddress(g_hWintun, "WintunReceivePacket");
    pWintunReleaseReceivePacket = (WINTUN_RELEASE_RECEIVE_PACKET_FUNC *)GetProcAddress(g_hWintun, "WintunReleaseReceivePacket");
    pWintunAllocateSendPacket   = (WINTUN_ALLOCATE_SEND_PACKET_FUNC *)GetProcAddress(g_hWintun, "WintunAllocateSendPacket");
    pWintunSendPacket           = (WINTUN_SEND_PACKET_FUNC *)GetProcAddress(g_hWintun, "WintunSendPacket");
    pWintunGetAdapterLUID       = (WINTUN_GET_ADAPTER_LUID_FUNC *)GetProcAddress(g_hWintun, "WintunGetAdapterLUID");

    if (!pWintunCreateAdapter || !pWintunStartSession || !pWintunReceivePacket || !pWintunSendPacket) {
        fprintf(stderr, "[Error] wintun.dll is missing required exported symbols.\n");
        FreeLibrary(g_hWintun);
        g_hWintun = NULL;
        return -1;
    }

    return 0;
}

/* Execute command completely hidden in background without flashing any CMD window */
static inline int run_command_hidden(const char *cmd) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    char cmd_line[1024];
    snprintf(cmd_line, sizeof(cmd_line), "cmd.exe /c %s", cmd);

    if (CreateProcessA(NULL, cmd_line, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 0;
    }
    return -1;
}

static inline DWORD resolve_host_ipv4(const char *host) {
    DWORD ip = inet_addr(host);
    if (ip != INADDR_NONE) return ip;
    struct hostent *he = gethostbyname(host);
    if (he && he->h_addr_list && he->h_addr_list[0]) {
        return *(DWORD *)he->h_addr_list[0];
    }
    return INADDR_NONE;
}

static inline int get_default_gateway_for_host(const char *host, char *out_gw, size_t gw_len, char *out_ip, size_t ip_len) {
    DWORD dest = resolve_host_ipv4(host);
    if (dest == INADDR_NONE) return -1;

    struct in_addr resolved_addr;
    resolved_addr.s_addr = dest;
    if (out_ip && ip_len > 0) {
        snprintf(out_ip, ip_len, "%s", inet_ntoa(resolved_addr));
    }

    MIB_IPFORWARDROW row;
    memset(&row, 0, sizeof(row));
    if (GetBestRoute(dest, 0, &row) == NO_ERROR) {
        struct in_addr gw;
        gw.s_addr = row.dwForwardNextHop;
        if (gw.s_addr != 0 && out_gw && gw_len > 0) {
            snprintf(out_gw, gw_len, "%s", inet_ntoa(gw));
            return 0;
        }
    }
    return -1;
}

/* Configure IP address, internet routes, and physical gateway bypass */
static inline int wintun_configure_ip(const char *adapter_name, const char *ip, const char *netmask, const char *server_host) {
    char cmd[512];

    /* Give Windows NDIS time to finish registering the interface */
    Sleep(600);

    /* 1. Assign static IP address without gateway */
    snprintf(cmd, sizeof(cmd),
             "netsh interface ipv4 set address name=\"%s\" source=static address=%s mask=%s",
             adapter_name, ip, netmask);
    run_command_hidden(cmd);

    /* 2. Direct subnet route to 10.10.10.0/24 */
    snprintf(cmd, sizeof(cmd),
             "netsh interface ipv4 add route 10.10.10.0/24 \"%s\" 10.10.10.1 metric=1",
             adapter_name);
    run_command_hidden(cmd);

    /* 3. Add explicit host route for VPN server IP through physical gateway so tunnel bypasses Wintun */
    char phys_gw[64] = "";
    char resolved_server_ip[64] = "";
    if (server_host && strlen(server_host) > 0) {
        if (get_default_gateway_for_host(server_host, phys_gw, sizeof(phys_gw), resolved_server_ip, sizeof(resolved_server_ip)) == 0) {
            snprintf(cmd, sizeof(cmd), "route add %s mask 255.255.255.255 %s metric 1", resolved_server_ip, phys_gw);
            run_command_hidden(cmd);
        }
    }

    /* 4. Add the two /1 default routes into Wintun (0.0.0.0/1 and 128.0.0.0/1) */
    snprintf(cmd, sizeof(cmd),
             "netsh interface ipv4 add route 0.0.0.0/1 \"%s\" 10.10.10.1 metric=1",
             adapter_name);
    run_command_hidden(cmd);

    snprintf(cmd, sizeof(cmd),
             "netsh interface ipv4 add route 128.0.0.0/1 \"%s\" 10.10.10.1 metric=1",
             adapter_name);
    run_command_hidden(cmd);

    /* 5. Set DNS to Cloudflare and Google */
    snprintf(cmd, sizeof(cmd),
             "netsh interface ipv4 set dnsservers name=\"%s\" static 1.1.1.1 validate=no",
             adapter_name);
    run_command_hidden(cmd);

    snprintf(cmd, sizeof(cmd),
             "netsh interface ipv4 add dnsservers name=\"%s\" 8.8.8.8 index=2 validate=no",
             adapter_name);
    run_command_hidden(cmd);

    /* 6. Set MTU to 1420 */
    snprintf(cmd, sizeof(cmd),
             "netsh interface ipv4 set subinterface \"%s\" mtu=1420 store=persistent",
             adapter_name);
    run_command_hidden(cmd);

    return 0;
}

/* Cleanup routes when tunnel disconnects */
static inline void wintun_cleanup_routes(const char *adapter_name, const char *server_host) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "netsh interface ipv4 delete route 0.0.0.0/1 \"%s\" 10.10.10.1", adapter_name);
    run_command_hidden(cmd);
    snprintf(cmd, sizeof(cmd), "netsh interface ipv4 delete route 128.0.0.0/1 \"%s\" 10.10.10.1", adapter_name);
    run_command_hidden(cmd);

    char phys_gw[64] = "";
    char resolved_server_ip[64] = "";
    if (server_host && strlen(server_host) > 0) {
        if (get_default_gateway_for_host(server_host, phys_gw, sizeof(phys_gw), resolved_server_ip, sizeof(resolved_server_ip)) == 0) {
            snprintf(cmd, sizeof(cmd), "route delete %s", resolved_server_ip);
            run_command_hidden(cmd);
        } else {
            snprintf(cmd, sizeof(cmd), "route delete %s", server_host);
            run_command_hidden(cmd);
        }
    }
}


static const GUID GUID_FWPM_LAYER_ALE_AUTH_CONNECT_V4 =
    { 0xc38d57d1, 0x05a7, 0x4c33, { 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82 } };

static const GUID GUID_FWPM_CONDITION_ALE_APP_ID =
    { 0xd78e1e87, 0x8644, 0x4ea5, { 0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71 } };

#define MAX_PER_APPS 64

/* Structure for running processes */
typedef struct {
    char exe_name[MAX_PATH];
    char full_path[MAX_PATH];
    DWORD pid;
} running_proc_t;

/* Enumerate unique user-mode running processes */
static inline int get_running_processes(running_proc_t *out_procs, int max_procs) {
    int count = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID <= 4) continue;
            if (count >= max_procs) break;

            int duplicate = 0;
            for (int i = 0; i < count; i++) {
                if (_stricmp(out_procs[i].exe_name, pe.szExeFile) == 0) {
                    duplicate = 1;
                    break;
                }
            }
            if (duplicate) continue;

            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            char fullPath[MAX_PATH] = "";
            if (hProc) {
                GetModuleFileNameExA(hProc, NULL, fullPath, sizeof(fullPath));
                CloseHandle(hProc);
            }

            if (strlen(fullPath) == 0) {
                snprintf(fullPath, sizeof(fullPath), "%s", pe.szExeFile);
            }

            snprintf(out_procs[count].exe_name, sizeof(out_procs[count].exe_name), "%s", pe.szExeFile);
            snprintf(out_procs[count].full_path, sizeof(out_procs[count].full_path), "%s", fullPath);
            out_procs[count].pid = pe.th32ProcessID;
            count++;
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return count;
}

/* WFP Multi-App Redirection Manager */
static HANDLE g_hEngine = NULL;
static UINT64 g_filterIds[MAX_PER_APPS];
static int g_numFilterIds = 0;

static inline int wfp_setup_per_apps(const char app_paths[][MAX_PATH], int count, const char *wintun_ip) {
    (void)wintun_ip;
    if (count <= 0) return 0;

    DWORD res = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &g_hEngine);
    if (res != ERROR_SUCCESS) {
        return -1;
    }

    GUID sublayerKey = { 0x4a965768, 0x1122, 0x4f12, { 0x98, 0xaa, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 } };
    FWPM_SUBLAYER0 sublayer;
    memset(&sublayer, 0, sizeof(sublayer));
    sublayer.subLayerKey = sublayerKey;
    sublayer.displayData.name = L"Livekadeh Per-App Sublayer";
    sublayer.weight = 0x8000;
    FwpmSubLayerAdd0(g_hEngine, &sublayer, NULL);

    g_numFilterIds = 0;
    for (int i = 0; i < count; i++) {
        if (strlen(app_paths[i]) == 0) continue;
        if (g_numFilterIds >= MAX_PER_APPS) break;

        wchar_t wAppPath[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, app_paths[i], -1, wAppPath, MAX_PATH);

        FWP_BYTE_BLOB *appId = NULL;
        res = FwpmGetAppIdFromFileName0(wAppPath, &appId);
        if (res != ERROR_SUCCESS) {
            continue;
        }

        FWPM_FILTER_CONDITION0 conditions[1];
        memset(conditions, 0, sizeof(conditions));
        conditions[0].fieldKey = GUID_FWPM_CONDITION_ALE_APP_ID;
        conditions[0].matchType = FWP_MATCH_EQUAL;
        conditions[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
        conditions[0].conditionValue.byteBlob = appId;

        FWPM_FILTER0 filter;
        memset(&filter, 0, sizeof(filter));
        filter.layerKey = GUID_FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        filter.displayData.name = L"Livekadeh Per-App Tunnel Filter";
        filter.subLayerKey = sublayerKey;
        filter.weight.type = FWP_UINT8;
        filter.weight.uint8 = 0xF;
        filter.numFilterConditions = 1;
        filter.filterCondition = conditions;
        filter.action.type = FWP_ACTION_PERMIT;

        UINT64 filterId = 0;
        res = FwpmFilterAdd0(g_hEngine, &filter, NULL, &filterId);
        FwpmFreeMemory0((void **)&appId);

        if (res == ERROR_SUCCESS) {
            g_filterIds[g_numFilterIds++] = filterId;
        }
    }

    return (g_numFilterIds > 0) ? 0 : -1;
}

/* Single-app backward-compatible wrapper */
static inline int wfp_setup_per_app(const char *app_path, const char *wintun_ip) {
    if (!app_path || strlen(app_path) == 0) return 0;
    char paths[1][MAX_PATH];
    strncpy(paths[0], app_path, MAX_PATH - 1);
    paths[0][MAX_PATH - 1] = '\0';
    return wfp_setup_per_apps((const char (*)[MAX_PATH])paths, 1, wintun_ip);
}

static inline void wfp_cleanup(void) {
    if (g_hEngine) {
        for (int i = 0; i < g_numFilterIds; i++) {
            if (g_filterIds[i]) {
                FwpmFilterDeleteById0(g_hEngine, g_filterIds[i]);
                g_filterIds[i] = 0;
            }
        }
        g_numFilterIds = 0;
        FwpmEngineClose0(g_hEngine);
        g_hEngine = NULL;
    }
}

/* In-tunnel ICMP echo ping to verify real L3 encapsulation and measure RTT */
static inline int wintun_ping_tunnel(const char *target_ip, DWORD timeout_ms, DWORD *out_rtt_ms, DWORD *out_ttl) {
    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) {
        return -1;
    }

    IPAddr ip = inet_addr(target_ip);
    char sendData[] = "LivekadehTunnelPing32BytesData";
    DWORD replySize = sizeof(ICMP_ECHO_REPLY) + sizeof(sendData) + 16;
    void *replyBuffer = malloc(replySize);
    if (!replyBuffer) {
        IcmpCloseHandle(hIcmp);
        return -1;
    }

    DWORD replies = IcmpSendEcho(hIcmp, ip, sendData, (WORD)sizeof(sendData), NULL, replyBuffer, replySize, timeout_ms);
    int ret = -1;
    if (replies > 0) {
        PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)replyBuffer;
        if (pEchoReply->Status == IP_SUCCESS) {
            if (out_rtt_ms) *out_rtt_ms = pEchoReply->RoundTripTime;
            if (out_ttl) *out_ttl = pEchoReply->Options.Ttl;
            ret = 0;
        }
    }

    free(replyBuffer);
    IcmpCloseHandle(hIcmp);
    return ret;
}

#endif /* _WIN32 */

#endif /* LIVEKADEH_TUN_WINTUN_H */

