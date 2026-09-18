#ifndef LIVEKADEH_TUN_WINTUN_H
#define LIVEKADEH_TUN_WINTUN_H

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fwpmu.h>
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

/* Configure IP address and direct subnet route on the created adapter */
static inline int wintun_configure_ip(const char *adapter_name, const char *ip, const char *netmask) {
    char cmd[512];

    /* Give Windows NDIS time to finish registering the interface */
    Sleep(600);

    /* Assign static IP without default gateway to avoid disrupting physical internet */
    snprintf(cmd, sizeof(cmd),
             "netsh interface ipv4 set address name=\"%s\" source=static address=%s mask=%s",
             adapter_name, ip, netmask);
    run_command_hidden(cmd);

    /* Explicitly add on-link route to 10.10.10.0/24 through Wintun adapter */
    snprintf(cmd, sizeof(cmd),
             "netsh interface ipv4 add route 10.10.10.0/24 \"%s\" 10.10.10.1 metric=1",
             adapter_name);
    run_command_hidden(cmd);

    /* Set MTU to 1420 */
    snprintf(cmd, sizeof(cmd),
             "netsh interface ipv4 set subinterface \"%s\" mtu=1420 store=persistent",
             adapter_name);
    run_command_hidden(cmd);

    return 0;
}

static const GUID GUID_FWPM_LAYER_ALE_AUTH_CONNECT_V4 =
    { 0xc38d57d1, 0x05a7, 0x4c33, { 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82 } };

static const GUID GUID_FWPM_CONDITION_ALE_APP_ID =
    { 0xd78e1e87, 0x8644, 0x4ea5, { 0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71 } };

/* WFP Per-App Redirection Manager */
static HANDLE g_hEngine = NULL;
static UINT64 g_filterId = 0;

static inline int wfp_setup_per_app(const char *app_path, const char *wintun_ip) {
    (void)wintun_ip;
    if (!app_path || strlen(app_path) == 0) return 0;

    DWORD res = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &g_hEngine);
    if (res != ERROR_SUCCESS) {
        fprintf(stderr, "[Warning] FwpmEngineOpen failed (Error: 0x%08lx). Run as Administrator for Per-App WFP.\n", res);
        return -1;
    }

    /* Convert app path to wide char */
    wchar_t wAppPath[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, app_path, -1, wAppPath, MAX_PATH);

    FWP_BYTE_BLOB *appId = NULL;
    res = FwpmGetAppIdFromFileName0(wAppPath, &appId);
    if (res != ERROR_SUCCESS) {
        fprintf(stderr, "[Warning] Failed to retrieve AppId for %s (Error: 0x%08lx)\n", app_path, res);
        FwpmEngineClose0(g_hEngine);
        g_hEngine = NULL;
        return -1;
    }

    /* Define sublayer */
    GUID sublayerKey = { 0x4a965768, 0x1122, 0x4f12, { 0x98, 0xaa, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 } };
    FWPM_SUBLAYER0 sublayer;
    memset(&sublayer, 0, sizeof(sublayer));
    sublayer.subLayerKey = sublayerKey;
    sublayer.displayData.name = L"Livekadeh Per-App Sublayer";
    sublayer.weight = 0x8000;
    FwpmSubLayerAdd0(g_hEngine, &sublayer, NULL);

    /* Define filter for ALE Connect layer */
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

    res = FwpmFilterAdd0(g_hEngine, &filter, NULL, &g_filterId);
    FwpmFreeMemory0((void **)&appId);

    if (res != ERROR_SUCCESS) {
        fprintf(stderr, "[Warning] FwpmFilterAdd failed (Error: 0x%08lx)\n", res);
        FwpmEngineClose0(g_hEngine);
        g_hEngine = NULL;
        return -1;
    }

    printf("[Livekadeh WFP] Per-App routing active for: %s\n", app_path);
    return 0;
}

static inline void wfp_cleanup(void) {
    if (g_hEngine) {
        if (g_filterId) {
            FwpmFilterDeleteById0(g_hEngine, g_filterId);
            g_filterId = 0;
        }
        FwpmEngineClose0(g_hEngine);
        g_hEngine = NULL;
    }
}

#endif /* _WIN32 */

#endif /* LIVEKADEH_TUN_WINTUN_H */
