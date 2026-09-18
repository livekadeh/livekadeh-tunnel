#ifndef LIVEKADEH_GUI_WIN32_H
#define LIVEKADEH_GUI_WIN32_H

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlobj.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include "tunnel_common.h"
#include "tun_proto.h"
#include "tun_wintun.h"

#define IDC_RADIO_CLIENT       1001
#define IDC_RADIO_SERVER       1002
#define IDC_LABEL_ADDR         1003
#define IDC_EDIT_ADDR          1004
#define IDC_BTN_TEST           1005
#define IDC_LABEL_KEY          1006
#define IDC_EDIT_KEY           1007
#define IDC_BTN_GENKEY         1008
#define IDC_CHK_PERAPP         1009
#define IDC_LIST_APPS          1010
#define IDC_BTN_RUNNING_APPS   1011
#define IDC_BTN_BROWSE         1012
#define IDC_BTN_REMOVE_APP     1013
#define IDC_BTN_CLEAR_APPS     1014
#define IDC_BTN_TOGGLE         1015
#define IDC_COMBO_LOGLEVEL     1016
#define IDC_EDIT_LOG           1017
#define IDC_BTN_CLEARLOG       1018
#define IDC_BTN_SPEEDTEST      1025
#define IDC_COMBO_CONNS        1026

#define IDC_PICKER_SEARCH      2001
#define IDC_PICKER_LIST        2002
#define IDC_PICKER_ADD         2003
#define IDC_PICKER_REFRESH     2004
#define IDC_PICKER_CLOSE       2005

typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO  = 1,
    LOG_LEVEL_WARN  = 2,
    LOG_LEVEL_ERROR = 3
} log_level_t;

/* Selected per-app list */
typedef struct {
    char path[MAX_PATH];
    char display_name[MAX_PATH + 64];
} app_item_t;

static app_item_t g_selected_apps[MAX_PER_APPS];
static int g_num_selected_apps = 0;

/* Main GUI Controls */
HWND g_hMainWnd              = NULL;
static HWND g_hRadioClient   = NULL;
static HWND g_hRadioServer   = NULL;
static HWND g_hLabelAddr     = NULL;
static HWND g_hEditAddr      = NULL;
static HWND g_hBtnTest       = NULL;
static HWND g_hBtnSpeedTest  = NULL;
static HWND g_hLabelKey      = NULL;
static HWND g_hEditKey       = NULL;
static HWND g_hBtnGenKey     = NULL;
static HWND g_hLabelConns    = NULL;
static HWND g_hComboConns    = NULL;
static HWND g_hChkPerApp     = NULL;
static HWND g_hListApps      = NULL;
static HWND g_hBtnRunningApps = NULL;
static HWND g_hBtnBrowse     = NULL;
static HWND g_hBtnRemoveApp  = NULL;
static HWND g_hBtnClearApps  = NULL;
static HWND g_hBtnToggle     = NULL;
static HWND g_hComboLogLevel = NULL;
static HWND g_hEditLog       = NULL;
static HWND g_hBtnClearLog   = NULL;
static HWND g_hLabelTraffic  = NULL;

static HBRUSH g_hTerminalBrush = NULL;
static HFONT  g_hTerminalFont  = NULL;

static int g_is_running       = 0;
static int g_mode_server      = 0;
static int g_current_log_level = LOG_LEVEL_INFO;

/* Process Picker State */
static running_proc_t g_running_procs[256];
static int g_num_running_procs = 0;
static HWND g_hPickerDlg       = NULL;
static HWND g_hPickerSearch    = NULL;
static HWND g_hPickerList      = NULL;

void log_append(int level, const char *format, ...) {
    if (level < g_current_log_level || !g_hEditLog) return;

    const char *tag = "[INFO] ";
    if (level == LOG_LEVEL_DEBUG) tag = "[DEBUG] ";
    else if (level == LOG_LEVEL_WARN) tag = "[WARN] ";
    else if (level == LOG_LEVEL_ERROR) tag = "[ERROR] ";

    SYSTEMTIME st;
    GetLocalTime(&st);
    char time_buf[32];
    snprintf(time_buf, sizeof(time_buf), "%02d:%02d:%02d ", st.wHour, st.wMinute, st.wSecond);

    char msg_buf[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(msg_buf, sizeof(msg_buf), format, args);
    va_end(args);

    char full_line[1200];
    snprintf(full_line, sizeof(full_line), "%s%s%s\r\n", time_buf, tag, msg_buf);

    int len = GetWindowTextLengthA(g_hEditLog);
    SendMessageA(g_hEditLog, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageA(g_hEditLog, EM_REPLACESEL, FALSE, (LPARAM)full_line);
}

/* Ensure application runs with Administrator privileges */
static inline void ensure_admin_elevation(void) {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    if (!isAdmin) {
        char szPath[MAX_PATH];
        if (GetModuleFileNameA(NULL, szPath, sizeof(szPath))) {
            SHELLEXECUTEINFOA sei;
            memset(&sei, 0, sizeof(sei));
            sei.cbSize = sizeof(sei);
            sei.lpVerb = "runas";
            sei.lpFile = szPath;
            sei.hwnd = NULL;
            sei.nShow = SW_NORMAL;
            if (ShellExecuteExA(&sei)) {
                ExitProcess(0);
            }
        }
    }
}

/* Worker parameter structure for tunnel thread */
typedef struct {
    int is_server;
    int is_udp;
    int is_per_app;
    char addr[256];
    char key[512];
    int num_apps;
    char app_paths[MAX_PER_APPS][MAX_PATH];
    int max_conns;
} gui_worker_params_t;

static DWORD WINAPI gui_tunnel_thread(LPVOID arg) {
    gui_worker_params_t *p = (gui_worker_params_t *)arg;
    if (p->is_server) {
        int listen_port = 8443;
        char listen_host[256];
        parse_host_port(p->addr, listen_host, sizeof(listen_host), &listen_port);
        log_append(LOG_LEVEL_INFO, "Starting server on %s:%d...", listen_host, listen_port);
        run_tunnel_server(listen_host, listen_port, "127.0.0.1", 22, p->key);
    } else {
        win_tun_client_params_t *tp = (win_tun_client_params_t *)malloc(sizeof(win_tun_client_params_t));
        memset(tp, 0, sizeof(*tp));
        int server_port = 8443;
        parse_host_port(p->addr, tp->server_host, sizeof(tp->server_host), &server_port);
        tp->server_port = server_port;
        snprintf(tp->key, sizeof(tp->key), "%s", p->key);
        tp->is_udp = p->is_udp;
        tp->is_per_app = p->is_per_app;
        tp->num_apps = p->num_apps;
        tp->max_conns = p->max_conns;
        for (int i = 0; i < p->num_apps; i++) {
            strncpy(tp->app_paths[i], p->app_paths[i], MAX_PATH - 1);
            tp->app_paths[i][MAX_PATH - 1] = '\0';
        }

        if (tp->is_udp) {
            log_append(LOG_LEVEL_INFO, "Initializing Wintun UDP client for remote server %s:%d...", tp->server_host, tp->server_port);
            win_tun_udp_client_thread(tp);
        } else {
            log_append(LOG_LEVEL_INFO, "Initializing Wintun adapter for remote server %s:%d...", tp->server_host, tp->server_port);
            win_tun_client_thread(tp);
        }
    }
    free(p);
    return 0;
}

/* Test tunnel reachability */
static DWORD WINAPI test_connection_thread(LPVOID arg) {
    (void)arg;
    EnableWindow(g_hBtnTest, FALSE);

    if (g_is_running && !g_mode_server) {
        /* Test in-tunnel L3 connectivity to 10.10.10.1 */
        log_append(LOG_LEVEL_INFO, "[In-Tunnel Test] Pinging 10.10.10.1 through Wintun adapter...");
        DWORD rtt = 0, ttl = 0;
        int res = wintun_ping_tunnel("10.10.10.1", 3000, &rtt, &ttl);
        if (res == 0) {
            log_append(LOG_LEVEL_INFO, "[In-Tunnel Test] SUCCESS: Reply from 10.10.10.1: bytes=32 time=%lu ms TTL=%lu", rtt, ttl);
            log_append(LOG_LEVEL_INFO, "[In-Tunnel Test] Tunnel status: FULLY OPERATIONAL (L3 encapsulated packets OK)");
        } else {
            log_append(LOG_LEVEL_ERROR, "[In-Tunnel Test] TIMEOUT: 10.10.10.1 did not respond through adapter.");
            log_append(LOG_LEVEL_WARN, "Verify that livekadeh-tunnel service is running on the server.");
        }
    } else {
        /* Tunnel is idle or server mode: probe external server port and key */
        char addr[256];
        GetWindowTextA(g_hEditAddr, addr, sizeof(addr));
        char key[512];
        GetWindowTextA(g_hEditKey, key, sizeof(key));

        char host[256];
        int port = 8443;
        parse_host_port(addr, host, sizeof(host), &port);

        log_append(LOG_LEVEL_INFO, "[Server Probe] Probing external server %s:%d...", host, port);
        DWORD start = GetTickCount();
        socket_t s = connect_remote(host, port);
        if (!IS_VALIDSOCK(s)) {
            DWORD elapsed = GetTickCount() - start;
            log_append(LOG_LEVEL_ERROR, "[Server Probe] Cannot reach %s:%d (Failed after %lu ms). Check IP and port.", host, port, elapsed);
            EnableWindow(g_hBtnTest, TRUE);
            return 0;
        }

        DWORD tcp_time = GetTickCount() - start;
        log_append(LOG_LEVEL_DEBUG, "[Server Probe] TCP connected in %lu ms. Testing authentication probe...", tcp_time);

        uint8_t master_key[32];
        derive_master_key(key, master_key);
        uint8_t c_nonce[AUTH_NONCE_SIZE], s_nonce[AUTH_NONCE_SIZE];
        char server_ver[64] = "unknown";

        DWORD to = 3000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof(to));

        int auth = client_authenticate(s, master_key, c_nonce, s_nonce, server_ver, sizeof(server_ver));
        CLOSE_SOCK(s);

        DWORD total_time = GetTickCount() - start;
        if (auth == 0) {
            log_append(LOG_LEVEL_INFO, "[Server Probe] SUCCESS: Connected to Livekadeh Tunnel Server v%s! (RTT: %lu ms)", server_ver, total_time);
            log_append(LOG_LEVEL_INFO, "[Server Probe] Encryption key verified. Click 'Connect Tunnel' to start virtual adapter.");
        } else if (auth == -2) {
            log_append(LOG_LEVEL_ERROR, "[Server Probe] FAILED: Server is ONLINE but ENCRYPTION KEY IS INVALID!");
        } else {
            log_append(LOG_LEVEL_WARN, "[Server Probe] Server connected but handshake timed out.");
        }
    }

    EnableWindow(g_hBtnTest, TRUE);
    return 0;
}

/* In-Tunnel Speed Test Worker Structures and Threads */
typedef struct {
    char host[64];
    int port;
    uint64_t bytes_transferred;
    volatile int stop_signal;
} st_worker_data_t;

static DWORD WINAPI st_dl_worker(LPVOID p) {
    st_worker_data_t *d = (st_worker_data_t *)p;
    d->bytes_transferred = 0;
    socket_t s = connect_remote(d->host, d->port);
    if (!IS_VALIDSOCK(s)) return 0;
    tune_tunnel_socket(s);

    DWORD to = 5000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof(to));

    if (send(s, "DOWNLOAD\n", 9, 0) != 9) {
        CLOSE_SOCK(s);
        return 0;
    }

    char buf[65536];
    while (!d->stop_signal) {
        int r = recv(s, buf, sizeof(buf), 0);
        if (r <= 0) break;
        d->bytes_transferred += r;
    }
    CLOSE_SOCK(s);
    return 0;
}

static DWORD WINAPI st_ul_worker(LPVOID p) {
    st_worker_data_t *d = (st_worker_data_t *)p;
    d->bytes_transferred = 0;
    socket_t s = connect_remote(d->host, d->port);
    if (!IS_VALIDSOCK(s)) return 0;
    tune_tunnel_socket(s);

    DWORD to = 5000;
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&to, sizeof(to));

    if (send(s, "UPLOAD\n", 7, 0) != 7) {
        CLOSE_SOCK(s);
        return 0;
    }

    char buf[65536];
    memset(buf, 0x5A, sizeof(buf));
    while (!d->stop_signal) {
        int w = send(s, buf, sizeof(buf), 0);
        if (w <= 0) break;
        d->bytes_transferred += w;
    }
    CLOSE_SOCK(s);
    return 0;
}

static DWORD WINAPI speedtest_client_thread(LPVOID arg) {
    (void)arg;
    EnableWindow(g_hBtnSpeedTest, FALSE);

    if (!g_is_running || g_mode_server) {
        log_append(LOG_LEVEL_WARN, "[Speed Test] Tunnel is not active. Click 'Connect Tunnel' first to benchmark through Wintun.");
        EnableWindow(g_hBtnSpeedTest, TRUE);
        return 0;
    }

    int sel = (int)SendMessage(g_hComboConns, CB_GETCURSEL, 0, 0);
    int streams = (sel == 2 || sel == 3) ? 1 : ((sel == 1) ? 4 : 8);
    const char *mode_name = (sel == 3) ? "UDP Datagram (Fast & Low Latency)" :
                            ((sel == 2) ? "Single-TCP (1 Lane)" :
                            ((sel == 1) ? "Multi-TCP (4 Lanes)" : "Multi-TCP (8 Lanes)"));

    log_append(LOG_LEVEL_INFO, "[Speed Test] ================================================");
    log_append(LOG_LEVEL_INFO, "[Speed Test] Starting In-Tunnel Benchmark to 10.10.10.1:9090");
    log_append(LOG_LEVEL_INFO, "[Speed Test] Mode: %s (%d stream%s)", mode_name, streams, streams > 1 ? "s" : "");

    /* Step 1: Latency (Ping) */
    double pings[4];
    int p_ok = 0;
    for (int i = 0; i < 4; i++) {
        socket_t s = connect_remote("10.10.10.1", SPEEDTEST_PORT);
        if (IS_VALIDSOCK(s)) {
            DWORD to = 2000;
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof(to));
            DWORD t0 = GetTickCount();
            if (send(s, "PING\n", 5, 0) == 5) {
                char resp[32];
                int r = recv(s, resp, sizeof(resp) - 1, 0);
                if (r > 0 && strncmp(resp, "PONG", 4) == 0) {
                    pings[p_ok++] = (double)(GetTickCount() - t0);
                }
            }
            CLOSE_SOCK(s);
        }
        Sleep(50);
    }

    if (p_ok == 0) {
        log_append(LOG_LEVEL_ERROR, "[Speed Test] Server did not respond on in-tunnel port 10.10.10.1:9090.");
        log_append(LOG_LEVEL_WARN, "[Speed Test] Verify livekadeh-tunnel service on Linux server has port 9090 open.");
        EnableWindow(g_hBtnSpeedTest, TRUE);
        return 0;
    }

    double sum_p = 0, min_p = 999999.0;
    for (int i = 0; i < p_ok; i++) {
        sum_p += pings[i];
        if (pings[i] < min_p) min_p = pings[i];
    }
    double avg_p = sum_p / p_ok;
    log_append(LOG_LEVEL_INFO, "[Speed Test] Latency (RTT): Avg %.1f ms | Min %.1f ms", avg_p, min_p);

    /* Step 2: Download Throughput */
    log_append(LOG_LEVEL_INFO, "[Speed Test] Testing Download throughput (%d parallel stream%s)...", streams, streams > 1 ? "s" : "");
    HANDLE dl_threads[8];
    st_worker_data_t dl_data[8];
    DWORD t_dl_start = GetTickCount();

    for (int i = 0; i < streams; i++) {
        snprintf(dl_data[i].host, sizeof(dl_data[i].host), "10.10.10.1");
        dl_data[i].port = SPEEDTEST_PORT;
        dl_data[i].bytes_transferred = 0;
        dl_data[i].stop_signal = 0;
        dl_threads[i] = CreateThread(NULL, 0, st_dl_worker, &dl_data[i], 0, NULL);
    }

    WaitForMultipleObjects(streams, dl_threads, TRUE, 6000);
    DWORD dl_elapsed = GetTickCount() - t_dl_start;
    for (int i = 0; i < streams; i++) {
        dl_data[i].stop_signal = 1;
        if (dl_threads[i]) CloseHandle(dl_threads[i]);
    }

    uint64_t total_dl_bytes = 0;
    for (int i = 0; i < streams; i++) {
        total_dl_bytes += dl_data[i].bytes_transferred;
    }

    double dl_sec = (double)dl_elapsed / 1000.0;
    if (dl_sec < 0.5) dl_sec = 0.5;
    double dl_mbps = ((double)total_dl_bytes * 8.0) / (dl_sec * 1000000.0);
    double dl_mb_s = (double)total_dl_bytes / (dl_sec * 1024.0 * 1024.0);
    log_append(LOG_LEVEL_INFO, "[Speed Test] Download: %.2f Mbps (%.2f MB/s) [%.2f MB in %.1fs]",
               dl_mbps, dl_mb_s, (double)total_dl_bytes / (1024.0 * 1024.0), dl_sec);

    /* Step 3: Upload Throughput */
    log_append(LOG_LEVEL_INFO, "[Speed Test] Testing Upload throughput (%d parallel stream%s)...", streams, streams > 1 ? "s" : "");
    HANDLE ul_threads[8];
    st_worker_data_t ul_data[8];
    DWORD t_ul_start = GetTickCount();

    for (int i = 0; i < streams; i++) {
        snprintf(ul_data[i].host, sizeof(ul_data[i].host), "10.10.10.1");
        ul_data[i].port = SPEEDTEST_PORT;
        ul_data[i].bytes_transferred = 0;
        ul_data[i].stop_signal = 0;
        ul_threads[i] = CreateThread(NULL, 0, st_ul_worker, &ul_data[i], 0, NULL);
    }

    Sleep(3500);
    for (int i = 0; i < streams; i++) {
        ul_data[i].stop_signal = 1;
    }

    WaitForMultipleObjects(streams, ul_threads, TRUE, 2000);
    DWORD ul_elapsed = GetTickCount() - t_ul_start;
    for (int i = 0; i < streams; i++) {
        if (ul_threads[i]) CloseHandle(ul_threads[i]);
    }

    uint64_t total_ul_bytes = 0;
    for (int i = 0; i < streams; i++) {
        total_ul_bytes += ul_data[i].bytes_transferred;
    }

    double ul_sec = (double)ul_elapsed / 1000.0;
    if (ul_sec < 0.5) ul_sec = 0.5;
    double ul_mbps = ((double)total_ul_bytes * 8.0) / (ul_sec * 1000000.0);
    double ul_mb_s = (double)total_ul_bytes / (ul_sec * 1024.0 * 1024.0);
    log_append(LOG_LEVEL_INFO, "[Speed Test] Upload:   %.2f Mbps (%.2f MB/s) [%.2f MB in %.1fs]",
               ul_mbps, ul_mb_s, (double)total_ul_bytes / (1024.0 * 1024.0), ul_sec);

    log_append(LOG_LEVEL_INFO, "[Speed Test] Summary: Ping: %.1f ms | Down: %.2f Mbps | Up: %.2f Mbps",
               avg_p, dl_mbps, ul_mbps);
    log_append(LOG_LEVEL_INFO, "[Speed Test] ================================================");
    EnableWindow(g_hBtnSpeedTest, TRUE);
    return 0;
}

/* Helper to add an application to the per-app list */
static void add_application_to_list(const char *path) {
    if (!path || strlen(path) == 0) return;
    if (g_num_selected_apps >= MAX_PER_APPS) {
        MessageBoxA(g_hMainWnd, "Maximum number of applications reached (64).", "Limit Reached", MB_OK | MB_ICONWARNING);
        return;
    }

    /* Check duplicates */
    for (int i = 0; i < g_num_selected_apps; i++) {
        if (_stricmp(g_selected_apps[i].path, path) == 0) {
            return;
        }
    }

    /* Extract filename for display */
    const char *pSlash = strrchr(path, '\\');
    const char *fileName = pSlash ? (pSlash + 1) : path;

    strncpy(g_selected_apps[g_num_selected_apps].path, path, MAX_PATH - 1);
    g_selected_apps[g_num_selected_apps].path[MAX_PATH - 1] = '\0';

    snprintf(g_selected_apps[g_num_selected_apps].display_name,
             sizeof(g_selected_apps[g_num_selected_apps].display_name),
             "%s  -  %s", fileName, path);

    SendMessageA(g_hListApps, LB_ADDSTRING, 0, (LPARAM)g_selected_apps[g_num_selected_apps].display_name);
    g_num_selected_apps++;

    /* Automatically enable Per-App checkbox */
    SendMessage(g_hChkPerApp, BM_SETCHECK, BST_CHECKED, 0);
    log_append(LOG_LEVEL_INFO, "Added application to Per-App tunnel: %s", fileName);
}

/* Refresh the Process Picker listbox */
static void refresh_picker_list(HWND hList, const char *search_filter) {
    SendMessageA(hList, LB_RESETCONTENT, 0, 0);

    for (int i = 0; i < g_num_running_procs; i++) {
        if (search_filter && strlen(search_filter) > 0) {
            char lower_filter[128];
            strncpy(lower_filter, search_filter, sizeof(lower_filter) - 1);
            lower_filter[sizeof(lower_filter) - 1] = '\0';
            for (size_t k = 0; k < strlen(lower_filter); k++) lower_filter[k] = (char)tolower(lower_filter[k]);

            char lower_name[MAX_PATH];
            strncpy(lower_name, g_running_procs[i].exe_name, sizeof(lower_name) - 1);
            lower_name[sizeof(lower_name) - 1] = '\0';
            for (size_t k = 0; k < strlen(lower_name); k++) lower_name[k] = (char)tolower(lower_name[k]);

            if (!strstr(lower_name, lower_filter)) continue;
        }

        char item_text[MAX_PATH + 64];
        snprintf(item_text, sizeof(item_text), "%s  (PID: %lu)  -  %s",
                 g_running_procs[i].exe_name, g_running_procs[i].pid, g_running_procs[i].full_path);

        int idx = (int)SendMessageA(hList, LB_ADDSTRING, 0, (LPARAM)item_text);
        SendMessageA(hList, LB_SETITEMDATA, (WPARAM)idx, (LPARAM)i);
    }
}

/* Process Picker Window Procedure */
static LRESULT CALLBACK ProcessPickerWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

            HWND hLblSearch = CreateWindowExA(0, "STATIC", "Filter Running Processes:",
                WS_VISIBLE | WS_CHILD, 15, 12, 200, 18, hwnd, NULL, NULL, NULL);
            SendMessage(hLblSearch, WM_SETFONT, (WPARAM)hFont, TRUE);

            g_hPickerSearch = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, 15, 32, 455, 24, hwnd, (HMENU)IDC_PICKER_SEARCH, NULL, NULL);
            SendMessage(g_hPickerSearch, WM_SETFONT, (WPARAM)hFont, TRUE);

            HWND hLblList = CreateWindowExA(0, "STATIC", "Select running process(es) to add to tunnel list:",
                WS_VISIBLE | WS_CHILD, 15, 64, 455, 18, hwnd, NULL, NULL, NULL);
            SendMessage(hLblList, WM_SETFONT, (WPARAM)hFont, TRUE);

            g_hPickerList = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", "",
                WS_VISIBLE | WS_CHILD | WS_VSCROLL | LBS_NOTIFY | LBS_EXTENDEDSEL | WS_BORDER,
                15, 84, 455, 235, hwnd, (HMENU)IDC_PICKER_LIST, NULL, NULL);
            SendMessage(g_hPickerList, WM_SETFONT, (WPARAM)hFont, TRUE);

            HWND hBtnAdd = CreateWindowExA(0, "BUTTON", "Add Selected",
                WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON, 15, 328, 140, 28, hwnd, (HMENU)IDC_PICKER_ADD, NULL, NULL);
            SendMessage(hBtnAdd, WM_SETFONT, (WPARAM)hFont, TRUE);

            HWND hBtnRefresh = CreateWindowExA(0, "BUTTON", "Refresh",
                WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 165, 328, 100, 28, hwnd, (HMENU)IDC_PICKER_REFRESH, NULL, NULL);
            SendMessage(hBtnRefresh, WM_SETFONT, (WPARAM)hFont, TRUE);

            HWND hBtnClose = CreateWindowExA(0, "BUTTON", "Close",
                WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 370, 328, 100, 28, hwnd, (HMENU)IDC_PICKER_CLOSE, NULL, NULL);
            SendMessage(hBtnClose, WM_SETFONT, (WPARAM)hFont, TRUE);

            g_num_running_procs = get_running_processes(g_running_procs, 256);
            refresh_picker_list(g_hPickerList, "");
            break;
        }

        case WM_COMMAND: {
            int wmId = LOWORD(wParam);
            int wmEvent = HIWORD(wParam);

            if (wmId == IDC_PICKER_SEARCH && wmEvent == EN_CHANGE) {
                char filter[128];
                GetWindowTextA(g_hPickerSearch, filter, sizeof(filter));
                refresh_picker_list(g_hPickerList, filter);
            } else if (wmId == IDC_PICKER_REFRESH) {
                g_num_running_procs = get_running_processes(g_running_procs, 256);
                char filter[128];
                GetWindowTextA(g_hPickerSearch, filter, sizeof(filter));
                refresh_picker_list(g_hPickerList, filter);
            } else if (wmId == IDC_PICKER_ADD || (wmId == IDC_PICKER_LIST && wmEvent == LBN_DBLCLK)) {
                int selCount = (int)SendMessageA(g_hPickerList, LB_GETSELCOUNT, 0, 0);
                if (selCount > 0) {
                    int *selIndices = (int *)malloc(sizeof(int) * selCount);
                    if (selIndices) {
                        SendMessageA(g_hPickerList, LB_GETSELITEMS, (WPARAM)selCount, (LPARAM)selIndices);
                        for (int i = 0; i < selCount; i++) {
                            int procIdx = (int)SendMessageA(g_hPickerList, LB_GETITEMDATA, (WPARAM)selIndices[i], 0);
                            if (procIdx >= 0 && procIdx < g_num_running_procs) {
                                add_application_to_list(g_running_procs[procIdx].full_path);
                            }
                        }
                        free(selIndices);
                    }
                }
                DestroyWindow(hwnd);
            } else if (wmId == IDC_PICKER_CLOSE) {
                DestroyWindow(hwnd);
            }
            break;
        }

        case WM_CLOSE:
            DestroyWindow(hwnd);
            break;

        case WM_DESTROY:
            if (g_hMainWnd) EnableWindow(g_hMainWnd, TRUE);
            SetForegroundWindow(g_hMainWnd);
            g_hPickerDlg = NULL;
            break;

        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

/* Open the Process Picker dialog */
static void show_process_picker_dialog(HWND hParent) {
    if (g_hPickerDlg) {
        SetForegroundWindow(g_hPickerDlg);
        return;
    }

    HINSTANCE hInst = (HINSTANCE)GetWindowLongPtr(hParent, GWLP_HINSTANCE);

    WNDCLASSA wc;
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc   = ProcessPickerWndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = "LivekadehProcPicker";
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    RegisterClassA(&wc);

    RECT rcParent;
    GetWindowRect(hParent, &rcParent);
    int dlg_w = 495;
    int dlg_h = 405;
    int dlg_x = rcParent.left + (rcParent.right - rcParent.left - dlg_w) / 2;
    int dlg_y = rcParent.top + (rcParent.bottom - rcParent.top - dlg_h) / 2;

    EnableWindow(hParent, FALSE);

    g_hPickerDlg = CreateWindowExA(
        WS_EX_DLGMODALFRAME | WS_EX_TOPMOST,
        "LivekadehProcPicker",
        "Select Running Application",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        dlg_x, dlg_y, dlg_w, dlg_h,
        hParent, NULL, hInst, NULL
    );
}

static void update_mode_ui(void) {
    if (g_mode_server) {
        SetWindowTextA(g_hLabelAddr, "Tunnel Listen Address (Host:Port):");
        SetWindowTextA(g_hEditAddr, "0.0.0.0:8443");
        SetWindowPos(g_hEditAddr, NULL, 20, 68, 540, 24, SWP_NOZORDER);
        ShowWindow(g_hBtnTest, SW_HIDE);
        ShowWindow(g_hBtnSpeedTest, SW_HIDE);
        SetWindowTextA(g_hLabelKey, "Encryption Key:");
        ShowWindow(g_hBtnGenKey, SW_SHOW);
        ShowWindow(g_hLabelConns, SW_HIDE);
        ShowWindow(g_hComboConns, SW_HIDE);
        SetWindowPos(g_hEditKey, NULL, 20, 120, 400, 24, SWP_NOZORDER);

        ShowWindow(g_hChkPerApp, SW_HIDE);
        ShowWindow(g_hListApps, SW_HIDE);
        ShowWindow(g_hBtnRunningApps, SW_HIDE);
        ShowWindow(g_hBtnBrowse, SW_HIDE);
        ShowWindow(g_hBtnRemoveApp, SW_HIDE);
        ShowWindow(g_hBtnClearApps, SW_HIDE);
    } else {
        SetWindowTextA(g_hLabelAddr, "Server Address (IP:Port):");
        SetWindowTextA(g_hEditAddr, "2.59.170.232:8443");
        SetWindowPos(g_hEditAddr, NULL, 20, 68, 240, 24, SWP_NOZORDER);
        ShowWindow(g_hBtnTest, SW_SHOW);
        ShowWindow(g_hBtnSpeedTest, SW_SHOW);
        SetWindowTextA(g_hLabelKey, "Encryption Key (Paste key from server):");
        ShowWindow(g_hBtnGenKey, SW_HIDE);
        ShowWindow(g_hLabelConns, SW_SHOW);
        ShowWindow(g_hComboConns, SW_SHOW);
        SetWindowPos(g_hEditKey, NULL, 20, 120, 340, 24, SWP_NOZORDER);

        ShowWindow(g_hChkPerApp, SW_SHOW);
        ShowWindow(g_hListApps, SW_SHOW);
        ShowWindow(g_hBtnRunningApps, SW_SHOW);
        ShowWindow(g_hBtnBrowse, SW_SHOW);
        ShowWindow(g_hBtnRemoveApp, SW_SHOW);
        ShowWindow(g_hBtnClearApps, SW_SHOW);
    }
}

static void format_traffic_size(uint64_t bytes, char *buf, size_t buf_len) {
    if (bytes < 1024) {
        snprintf(buf, buf_len, "%llu B", (unsigned long long)bytes);
    } else if (bytes < 1024ULL * 1024) {
        snprintf(buf, buf_len, "%.2f KB", (double)bytes / 1024.0);
    } else if (bytes < 1024ULL * 1024 * 1024) {
        snprintf(buf, buf_len, "%.2f MB", (double)bytes / (1024.0 * 1024.0));
    } else {
        snprintf(buf, buf_len, "%.2f GB", (double)bytes / (1024.0 * 1024.0 * 1024.0));
    }
}

static void format_traffic_rate(uint64_t bytes_per_sec, char *buf, size_t buf_len) {
    if (bytes_per_sec < 1024) {
        snprintf(buf, buf_len, "%llu B/s", (unsigned long long)bytes_per_sec);
    } else if (bytes_per_sec < 1024ULL * 1024) {
        snprintf(buf, buf_len, "%.1f KB/s", (double)bytes_per_sec / 1024.0);
    } else {
        snprintf(buf, buf_len, "%.2f MB/s", (double)bytes_per_sec / (1024.0 * 1024.0));
    }
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            g_hMainWnd = hwnd;
            HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

            g_hTerminalBrush = CreateSolidBrush(RGB(15, 23, 42));
            g_hTerminalFont  = CreateFontA(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                          ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                          DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");

            /* Mode Radios */
            g_hRadioClient = CreateWindowExA(0, "BUTTON", "Client Mode (Wintun Virtual Network Adapter)",
                WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON | WS_GROUP,
                20, 15, 340, 22, hwnd, (HMENU)IDC_RADIO_CLIENT, NULL, NULL);
            SendMessage(g_hRadioClient, WM_SETFONT, (WPARAM)hFont, TRUE);
            SendMessage(g_hRadioClient, BM_SETCHECK, BST_CHECKED, 0);

            g_hRadioServer = CreateWindowExA(0, "BUTTON", "Server Mode",
                WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON,
                380, 15, 170, 22, hwnd, (HMENU)IDC_RADIO_SERVER, NULL, NULL);
            SendMessage(g_hRadioServer, WM_SETFONT, (WPARAM)hFont, TRUE);

            /* Server Address & Buttons */
            g_hLabelAddr = CreateWindowExA(0, "STATIC", "Server Address (IP:Port):",
                WS_VISIBLE | WS_CHILD, 20, 48, 240, 18, hwnd, (HMENU)IDC_LABEL_ADDR, NULL, NULL);
            SendMessage(g_hLabelAddr, WM_SETFONT, (WPARAM)hFont, TRUE);

            g_hEditAddr = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "2.59.170.232:8443",
                WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, 20, 68, 240, 24, hwnd, (HMENU)IDC_EDIT_ADDR, NULL, NULL);
            SendMessage(g_hEditAddr, WM_SETFONT, (WPARAM)hFont, TRUE);

            /* Test Tunnel Button */
            g_hBtnTest = CreateWindowExA(0, "BUTTON", "Test Tunnel",
                WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 270, 67, 130, 26, hwnd, (HMENU)IDC_BTN_TEST, NULL, NULL);
            SendMessage(g_hBtnTest, WM_SETFONT, (WPARAM)hFont, TRUE);

            /* Speed Test Button */
            g_hBtnSpeedTest = CreateWindowExA(0, "BUTTON", "Speed Test",
                WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 410, 67, 150, 26, hwnd, (HMENU)IDC_BTN_SPEEDTEST, NULL, NULL);
            SendMessage(g_hBtnSpeedTest, WM_SETFONT, (WPARAM)hFont, TRUE);

            /* Key */
            g_hLabelKey = CreateWindowExA(0, "STATIC", "Encryption Key (Paste key from server):",
                WS_VISIBLE | WS_CHILD, 20, 100, 340, 18, hwnd, (HMENU)IDC_LABEL_KEY, NULL, NULL);
            SendMessage(g_hLabelKey, WM_SETFONT, (WPARAM)hFont, TRUE);

            g_hEditKey = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "0ddd412de196b2bf2110d54ec8c1fa9e1155af78cb770721d9de03034a2e6852",
                WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, 20, 120, 340, 24, hwnd, (HMENU)IDC_EDIT_KEY, NULL, NULL);
            SendMessage(g_hEditKey, WM_SETFONT, (WPARAM)hFont, TRUE);

            /* Transport & Connections Selector */
            g_hLabelConns = CreateWindowExA(0, "STATIC", "Transport & Lanes:",
                WS_VISIBLE | WS_CHILD, 375, 100, 185, 18, hwnd, NULL, NULL, NULL);
            SendMessage(g_hLabelConns, WM_SETFONT, (WPARAM)hFont, TRUE);

            g_hComboConns = CreateWindowExA(0, "COMBOBOX", "",
                WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL,
                375, 120, 185, 140, hwnd, (HMENU)IDC_COMBO_CONNS, NULL, NULL);
            SendMessage(g_hComboConns, WM_SETFONT, (WPARAM)hFont, TRUE);
            SendMessageA(g_hComboConns, CB_ADDSTRING, 0, (LPARAM)"8 Lanes (Multi-TCP)");
            SendMessageA(g_hComboConns, CB_ADDSTRING, 0, (LPARAM)"4 Lanes (Multi-TCP)");
            SendMessageA(g_hComboConns, CB_ADDSTRING, 0, (LPARAM)"1 Lane (Single-TCP)");
            SendMessageA(g_hComboConns, CB_ADDSTRING, 0, (LPARAM)"UDP Datagram (Fast & Low Latency)");
            SendMessageA(g_hComboConns, CB_SETCURSEL, (WPARAM)0, 0);

            g_hBtnGenKey = CreateWindowExA(0, "BUTTON", "Generate Key",
                WS_CHILD | BS_PUSHBUTTON, 430, 119, 130, 26, hwnd, (HMENU)IDC_BTN_GENKEY, NULL, NULL);
            SendMessage(g_hBtnGenKey, WM_SETFONT, (WPARAM)hFont, TRUE);

            /* Per-App Checkbox */
            g_hChkPerApp = CreateWindowExA(0, "BUTTON", "Per-App Routing (Route only listed applications through tunnel)",
                WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 20, 152, 540, 20, hwnd, (HMENU)IDC_CHK_PERAPP, NULL, NULL);
            SendMessage(g_hChkPerApp, WM_SETFONT, (WPARAM)hFont, TRUE);

            /* Per-App ListBox */
            g_hListApps = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", "",
                WS_VISIBLE | WS_CHILD | WS_VSCROLL | LBS_NOTIFY | WS_BORDER,
                20, 175, 540, 75, hwnd, (HMENU)IDC_LIST_APPS, NULL, NULL);
            SendMessage(g_hListApps, WM_SETFONT, (WPARAM)hFont, TRUE);

            /* Per-App Buttons */
            g_hBtnRunningApps = CreateWindowExA(0, "BUTTON", "+ Running Apps...",
                WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 20, 255, 140, 26, hwnd, (HMENU)IDC_BTN_RUNNING_APPS, NULL, NULL);
            SendMessage(g_hBtnRunningApps, WM_SETFONT, (WPARAM)hFont, TRUE);

            g_hBtnBrowse = CreateWindowExA(0, "BUTTON", "+ Browse File...",
                WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 168, 255, 120, 26, hwnd, (HMENU)IDC_BTN_BROWSE, NULL, NULL);
            SendMessage(g_hBtnBrowse, WM_SETFONT, (WPARAM)hFont, TRUE);

            g_hBtnRemoveApp = CreateWindowExA(0, "BUTTON", "Remove Selected",
                WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 296, 255, 130, 26, hwnd, (HMENU)IDC_BTN_REMOVE_APP, NULL, NULL);
            SendMessage(g_hBtnRemoveApp, WM_SETFONT, (WPARAM)hFont, TRUE);

            g_hBtnClearApps = CreateWindowExA(0, "BUTTON", "Clear All",
                WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 434, 255, 126, 26, hwnd, (HMENU)IDC_BTN_CLEAR_APPS, NULL, NULL);
            SendMessage(g_hBtnClearApps, WM_SETFONT, (WPARAM)hFont, TRUE);

            /* Connect/Disconnect Button */
            g_hBtnToggle = CreateWindowExA(0, "BUTTON", "Connect Tunnel",
                WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON, 20, 290, 540, 36, hwnd, (HMENU)IDC_BTN_TOGGLE, NULL, NULL);
            SendMessage(g_hBtnToggle, WM_SETFONT, (WPARAM)hFont, TRUE);

            /* Embedded Terminal Header & Log Level Selector */
            HWND hLabelTerm = CreateWindowExA(0, "STATIC", "Embedded Terminal & Live Connection Log:",
                WS_VISIBLE | WS_CHILD, 20, 336, 300, 18, hwnd, NULL, NULL, NULL);
            SendMessage(hLabelTerm, WM_SETFONT, (WPARAM)hFont, TRUE);

            HWND hLabelLvl = CreateWindowExA(0, "STATIC", "Log Level:",
                WS_VISIBLE | WS_CHILD, 355, 336, 70, 18, hwnd, NULL, NULL, NULL);
            SendMessage(hLabelLvl, WM_SETFONT, (WPARAM)hFont, TRUE);

            g_hComboLogLevel = CreateWindowExA(0, "COMBOBOX", "",
                WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL,
                430, 333, 130, 140, hwnd, (HMENU)IDC_COMBO_LOGLEVEL, NULL, NULL);
            SendMessage(g_hComboLogLevel, WM_SETFONT, (WPARAM)hFont, TRUE);
            SendMessageA(g_hComboLogLevel, CB_ADDSTRING, 0, (LPARAM)"DEBUG");
            SendMessageA(g_hComboLogLevel, CB_ADDSTRING, 0, (LPARAM)"INFO");
            SendMessageA(g_hComboLogLevel, CB_ADDSTRING, 0, (LPARAM)"WARNING");
            SendMessageA(g_hComboLogLevel, CB_ADDSTRING, 0, (LPARAM)"ERROR");
            SendMessageA(g_hComboLogLevel, CB_SETCURSEL, (WPARAM)1, 0);

            /* Embedded Terminal Screen */
            g_hEditLog = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                WS_VISIBLE | WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
                20, 358, 540, 240, hwnd, (HMENU)IDC_EDIT_LOG, NULL, NULL);
            SendMessage(g_hEditLog, WM_SETFONT, (WPARAM)g_hTerminalFont, TRUE);

            /* Traffic Stats Label */
            g_hLabelTraffic = CreateWindowExA(0, "STATIC", "Traffic: Idle  (Sent: 0 B   |   Recv: 0 B)",
                WS_VISIBLE | WS_CHILD, 20, 609, 410, 20, hwnd, NULL, NULL, NULL);
            SendMessage(g_hLabelTraffic, WM_SETFONT, (WPARAM)hFont, TRUE);

            /* Clear Log Button */
            g_hBtnClearLog = CreateWindowExA(0, "BUTTON", "Clear Terminal",
                WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 440, 606, 120, 24, hwnd, (HMENU)IDC_BTN_CLEARLOG, NULL, NULL);
            SendMessage(g_hBtnClearLog, WM_SETFONT, (WPARAM)hFont, TRUE);

            SetTimer(hwnd, 1, 1000, NULL);

            log_append(LOG_LEVEL_INFO, "Livekadeh Tunnel v" LIVEKADEH_VERSION " ready. Running with Administrator privileges.");
            log_append(LOG_LEVEL_INFO, "Default mode: Wintun virtual network adapter (10.10.10.2 <-> 10.10.10.1)");
            break;
        }

        case WM_CTLCOLOREDIT:
        case WM_CTLCOLORSTATIC: {
            HWND hCtl = (HWND)lParam;
            if (hCtl == g_hEditLog) {
                HDC hdc = (HDC)wParam;
                SetTextColor(hdc, RGB(56, 189, 248));      /* Bright Sky Blue */
                SetBkColor(hdc, RGB(15, 23, 42));         /* Dark Navy Terminal Background */
                return (INT_PTR)g_hTerminalBrush;
            }
            return DefWindowProc(hwnd, msg, wParam, lParam);
        }

        case WM_COMMAND: {
            int wmId = LOWORD(wParam);

            if (wmId == IDC_RADIO_CLIENT && HIWORD(wParam) == BN_CLICKED) {
                if (!g_is_running) {
                    g_mode_server = 0;
                    update_mode_ui();
                }
            } else if (wmId == IDC_RADIO_SERVER && HIWORD(wParam) == BN_CLICKED) {
                if (!g_is_running) {
                    g_mode_server = 1;
                    update_mode_ui();
                }
            } else if (wmId == IDC_COMBO_LOGLEVEL && HIWORD(wParam) == CBN_SELCHANGE) {
                int cur = (int)SendMessageA(g_hComboLogLevel, CB_GETCURSEL, 0, 0);
                if (cur >= 0 && cur <= 3) {
                    g_current_log_level = cur;
                    const char *names[] = { "DEBUG", "INFO", "WARNING", "ERROR" };
                    log_append(LOG_LEVEL_INFO, "Log level changed to: %s", names[cur]);
                }
            } else if (wmId == IDC_BTN_CLEARLOG) {
                SetWindowTextA(g_hEditLog, "");
            } else if (wmId == IDC_BTN_TEST) {
                HANDLE h = CreateThread(NULL, 0, test_connection_thread, NULL, 0, NULL);
                if (h) CloseHandle(h);
            } else if (wmId == IDC_BTN_SPEEDTEST) {
                HANDLE h = CreateThread(NULL, 0, speedtest_client_thread, NULL, 0, NULL);
                if (h) CloseHandle(h);
            } else if (wmId == IDC_BTN_GENKEY) {
                char new_key[128];
                if (generate_random_key_hex(new_key, sizeof(new_key)) == 0) {
                    SetWindowTextA(g_hEditKey, new_key);
                    log_append(LOG_LEVEL_INFO, "Generated new 256-bit encryption key.");
                }
            } else if (wmId == IDC_BTN_RUNNING_APPS) {
                show_process_picker_dialog(hwnd);
            } else if (wmId == IDC_BTN_BROWSE) {
                OPENFILENAMEA ofn;
                char szFile[MAX_PATH] = "";
                memset(&ofn, 0, sizeof(ofn));
                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = hwnd;
                ofn.lpstrFile = szFile;
                ofn.nMaxFile = sizeof(szFile);
                ofn.lpstrFilter = "Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
                ofn.nFilterIndex = 1;
                ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
                if (GetOpenFileNameA(&ofn)) {
                    add_application_to_list(szFile);
                }
            } else if (wmId == IDC_BTN_REMOVE_APP) {
                int cur = (int)SendMessageA(g_hListApps, LB_GETCURSEL, 0, 0);
                if (cur != LB_ERR && cur < g_num_selected_apps) {
                    log_append(LOG_LEVEL_INFO, "Removed application: %s", g_selected_apps[cur].path);
                    SendMessageA(g_hListApps, LB_DELETESTRING, (WPARAM)cur, 0);
                    for (int i = cur; i < g_num_selected_apps - 1; i++) {
                        g_selected_apps[i] = g_selected_apps[i + 1];
                    }
                    g_num_selected_apps--;
                }
            } else if (wmId == IDC_BTN_CLEAR_APPS) {
                SendMessageA(g_hListApps, LB_RESETCONTENT, 0, 0);
                g_num_selected_apps = 0;
                log_append(LOG_LEVEL_INFO, "Cleared application routing list.");
            } else if (wmId == IDC_BTN_TOGGLE) {
                if (!g_is_running) {
                    gui_worker_params_t *p = (gui_worker_params_t *)malloc(sizeof(gui_worker_params_t));
                    p->is_server = g_mode_server;
                    p->is_per_app = (SendMessage(g_hChkPerApp, BM_GETCHECK, 0, 0) == BST_CHECKED);
                    p->num_apps = g_num_selected_apps;
                    for (int i = 0; i < g_num_selected_apps; i++) {
                        snprintf(p->app_paths[i], sizeof(p->app_paths[i]), "%s", g_selected_apps[i].path);
                    }

                    int sel_conns = (int)SendMessage(g_hComboConns, CB_GETCURSEL, 0, 0);
                    if (sel_conns == 3) {
                        p->is_udp = 1;
                        p->max_conns = 1;
                    } else if (sel_conns == 2) {
                        p->is_udp = 0;
                        p->max_conns = 1;
                    } else if (sel_conns == 1) {
                        p->is_udp = 0;
                        p->max_conns = 4;
                    } else {
                        p->is_udp = 0;
                        p->max_conns = 8;
                    }

                    GetWindowTextA(g_hEditAddr, p->addr, sizeof(p->addr));
                    GetWindowTextA(g_hEditKey, p->key, sizeof(p->key));

                    if (strlen(p->key) == 0) {
                        if (p->is_server) {
                            generate_random_key_hex(p->key, sizeof(p->key));
                            SetWindowTextA(g_hEditKey, p->key);
                            log_append(LOG_LEVEL_INFO, "Auto-generated session key for server.");
                        } else {
                            MessageBoxA(hwnd, "Please paste the encryption key provided by the server.",
                                        "Key Required", MB_OK | MB_ICONWARNING);
                            free(p);
                            break;
                        }
                    }

                    g_is_running = 1;
                    SetWindowTextA(g_hBtnToggle, "Disconnect Tunnel");
                    EnableWindow(g_hRadioClient, FALSE);
                    EnableWindow(g_hRadioServer, FALSE);
                    EnableWindow(g_hEditAddr, FALSE);
                    EnableWindow(g_hEditKey, FALSE);
                    EnableWindow(g_hBtnGenKey, FALSE);
                    EnableWindow(g_hComboConns, FALSE);
                    EnableWindow(g_hChkPerApp, FALSE);
                    EnableWindow(g_hListApps, FALSE);
                    EnableWindow(g_hBtnRunningApps, FALSE);
                    EnableWindow(g_hBtnBrowse, FALSE);
                    EnableWindow(g_hBtnRemoveApp, FALSE);
                    EnableWindow(g_hBtnClearApps, FALSE);

                    if (g_mode_server) {
                        log_append(LOG_LEVEL_INFO, "Tunnel Server starting on %s...", p->addr);
                    } else {
                        if (p->is_per_app && p->num_apps > 0) {
                            log_append(LOG_LEVEL_INFO, "Starting Per-App VPN (%d conns) for %d app(s) -> %s", p->max_conns, p->num_apps, p->addr);
                        } else {
                            log_append(LOG_LEVEL_INFO, "Connecting to %s (%d conns, all ports accessible at 10.10.10.1)", p->addr, p->max_conns);
                        }
                    }

                    HANDLE hThread = CreateThread(NULL, 0, gui_tunnel_thread, p, 0, NULL);
                    if (hThread) CloseHandle(hThread);

                } else {
                    stop_active_tunnel();
                    g_is_running = 0;
                    SetWindowTextA(g_hBtnToggle, "Connect Tunnel");
                    EnableWindow(g_hRadioClient, TRUE);
                    EnableWindow(g_hRadioServer, TRUE);
                    EnableWindow(g_hEditAddr, TRUE);
                    EnableWindow(g_hEditKey, TRUE);
                    if (g_mode_server) EnableWindow(g_hBtnGenKey, TRUE);
                    EnableWindow(g_hComboConns, TRUE);
                    EnableWindow(g_hChkPerApp, TRUE);
                    EnableWindow(g_hListApps, TRUE);
                    EnableWindow(g_hBtnRunningApps, TRUE);
                    EnableWindow(g_hBtnBrowse, TRUE);
                    EnableWindow(g_hBtnRemoveApp, TRUE);
                    EnableWindow(g_hBtnClearApps, TRUE);
                    log_append(LOG_LEVEL_INFO, "Tunnel disconnected.");
                }
            }
            break;
        }

        case WM_TIMER: {
            if (wParam == 1) {
                static uint64_t last_tx = 0;
                static uint64_t last_rx = 0;

                uint64_t cur_tx = g_traffic_tx_bytes;
                uint64_t cur_rx = g_traffic_rx_bytes;

                uint64_t delta_tx = (cur_tx >= last_tx) ? (cur_tx - last_tx) : 0;
                uint64_t delta_rx = (cur_rx >= last_rx) ? (cur_rx - last_rx) : 0;

                last_tx = cur_tx;
                last_rx = cur_rx;

                if (g_is_running) {
                    char str_tx[32], str_rx[32];
                    char spd_tx[32], spd_rx[32];
                    format_traffic_size(cur_tx, str_tx, sizeof(str_tx));
                    format_traffic_size(cur_rx, str_rx, sizeof(str_rx));
                    format_traffic_rate(delta_tx, spd_tx, sizeof(spd_tx));
                    format_traffic_rate(delta_rx, spd_rx, sizeof(spd_rx));

                    char status_text[256];
                    snprintf(status_text, sizeof(status_text),
                             "Traffic:  Sent: %s (%s)   |   Recv: %s (%s)",
                             str_tx, spd_tx, str_rx, spd_rx);
                    SetWindowTextA(g_hLabelTraffic, status_text);
                } else {
                    SetWindowTextA(g_hLabelTraffic, "Traffic: Idle  (Sent: 0 B   |   Recv: 0 B)");
                    last_tx = 0;
                    last_rx = 0;
                }
            }
            break;
        }

        case WM_USER + 200:
            g_is_running = 0;
            SetWindowTextA(g_hBtnToggle, "Connect Tunnel");
            EnableWindow(g_hRadioClient, TRUE);
            EnableWindow(g_hRadioServer, TRUE);
            EnableWindow(g_hEditAddr, TRUE);
            EnableWindow(g_hEditKey, TRUE);
            if (g_mode_server) EnableWindow(g_hBtnGenKey, TRUE);
            EnableWindow(g_hComboConns, TRUE);
            EnableWindow(g_hChkPerApp, TRUE);
            EnableWindow(g_hListApps, TRUE);
            EnableWindow(g_hBtnRunningApps, TRUE);
            EnableWindow(g_hBtnBrowse, TRUE);
            EnableWindow(g_hBtnRemoveApp, TRUE);
            EnableWindow(g_hBtnClearApps, TRUE);
            break;

        case WM_DESTROY:
            KillTimer(hwnd, 1);
            stop_active_tunnel();
            if (g_hTerminalBrush) DeleteObject(g_hTerminalBrush);
            if (g_hTerminalFont) DeleteObject(g_hTerminalFont);
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

static inline int run_win32_gui(HINSTANCE hInstance, int nCmdShow) {
    ensure_admin_elevation();

    WNDCLASSA wc;
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.lpszClassName = "LivekadehTunnelGUI";
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon         = LoadIcon(hInstance, MAKEINTRESOURCE(1));
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);

    RegisterClassA(&wc);

    int win_w = 600;
    int win_h = 680;
    int pos_x = (GetSystemMetrics(SM_CXSCREEN) - win_w) / 2;
    int pos_y = (GetSystemMetrics(SM_CYSCREEN) - win_h) / 2;

    HWND hwnd = CreateWindowExA(
        WS_EX_APPWINDOW,
        "LivekadehTunnelGUI",
        "Livekadeh Tunnel v" LIVEKADEH_VERSION " - Network Adapter (Wintun)",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        pos_x, pos_y, win_w, win_h,
        NULL, NULL, hInstance, NULL
    );

    if (!hwnd) return 1;

    SendMessage(hwnd, WM_SETICON, ICON_BIG, (LPARAM)LoadIcon(hInstance, MAKEINTRESOURCE(1)));
    SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)LoadIcon(hInstance, MAKEINTRESOURCE(1)));

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}

#endif /* _WIN32 */

#endif /* LIVEKADEH_GUI_WIN32_H */
