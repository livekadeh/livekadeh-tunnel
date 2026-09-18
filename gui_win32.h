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
#include "tunnel_common.h"
#include "tun_proto.h"

#define IDC_RADIO_CLIENT     1001
#define IDC_RADIO_SERVER     1002
#define IDC_LABEL_ADDR       1003
#define IDC_EDIT_ADDR        1004
#define IDC_LABEL_KEY        1005
#define IDC_EDIT_KEY         1006
#define IDC_BTN_GENKEY       1007
#define IDC_CHK_PERAPP       1008
#define IDC_EDIT_APPPATH     1009
#define IDC_BTN_BROWSE       1010
#define IDC_BTN_TOGGLE       1011
#define IDC_EDIT_LOG         1012

static HWND g_hRadioClient = NULL;
static HWND g_hRadioServer = NULL;
static HWND g_hLabelAddr   = NULL;
static HWND g_hEditAddr    = NULL;
static HWND g_hLabelKey    = NULL;
static HWND g_hEditKey     = NULL;
static HWND g_hBtnGenKey   = NULL;
static HWND g_hChkPerApp   = NULL;
static HWND g_hEditAppPath = NULL;
static HWND g_hBtnBrowse   = NULL;
static HWND g_hBtnToggle   = NULL;
static HWND g_hEditLog     = NULL;

static int  g_is_running   = 0;
static int  g_mode_server  = 0;

static void append_log(const char *text) {
    if (!g_hEditLog) return;
    int len = GetWindowTextLengthA(g_hEditLog);
    SendMessageA(g_hEditLog, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageA(g_hEditLog, EM_REPLACESEL, FALSE, (LPARAM)text);
    SendMessageA(g_hEditLog, EM_REPLACESEL, FALSE, (LPARAM)"\r\n");
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
            SHELLEXECUTEINFOA sei = { sizeof(sei) };
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

typedef struct {
    int is_server;
    int is_per_app;
    char addr[256];
    char key[512];
    char app_path[MAX_PATH];
} gui_worker_params_t;

static DWORD WINAPI gui_tunnel_thread(LPVOID arg) {
    gui_worker_params_t *p = (gui_worker_params_t *)arg;
    if (p->is_server) {
        int listen_port = 8443;
        char listen_host[256];
        parse_host_port(p->addr, listen_host, sizeof(listen_host), &listen_port);
        run_tunnel_server(listen_host, listen_port, "127.0.0.1", 22, p->key);
    } else {
        win_tun_client_params_t *tp = (win_tun_client_params_t *)malloc(sizeof(win_tun_client_params_t));
        int server_port = 8443;
        parse_host_port(p->addr, tp->server_host, sizeof(tp->server_host), &server_port);
        tp->server_port = server_port;
        snprintf(tp->key, sizeof(tp->key), "%s", p->key);
        snprintf(tp->app_path, sizeof(tp->app_path), "%s", p->is_per_app ? p->app_path : "");

        win_tun_client_thread(tp);
    }
    free(p);
    return 0;
}

static void update_mode_ui(void) {
    if (g_mode_server) {
        SetWindowTextA(g_hLabelAddr, "Tunnel Listen Address (Host:Port):");
        SetWindowTextA(g_hEditAddr, "0.0.0.0:8443");
        SetWindowTextA(g_hLabelKey, "Encryption Key:");
        ShowWindow(g_hBtnGenKey, SW_SHOW);
        SetWindowPos(g_hEditKey, NULL, 20, 120, 360, 24, SWP_NOZORDER);
        ShowWindow(g_hChkPerApp, SW_HIDE);
        ShowWindow(g_hEditAppPath, SW_HIDE);
        ShowWindow(g_hBtnBrowse, SW_HIDE);
    } else {
        SetWindowTextA(g_hLabelAddr, "Server Address (IP:Port):");
        SetWindowTextA(g_hEditAddr, "2.59.170.232:8443");
        SetWindowTextA(g_hLabelKey, "Encryption Key (Paste key from server):");
        ShowWindow(g_hBtnGenKey, SW_HIDE);
        SetWindowPos(g_hEditKey, NULL, 20, 120, 480, 24, SWP_NOZORDER);
        ShowWindow(g_hChkPerApp, SW_SHOW);
        ShowWindow(g_hEditAppPath, SW_SHOW);
        ShowWindow(g_hBtnBrowse, SW_SHOW);
    }
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

            /* Mode Radios */
            g_hRadioClient = CreateWindowExA(0, "BUTTON", "Client Mode (Wintun Virtual Network Adapter)",
                WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON | WS_GROUP,
                20, 15, 300, 22, hwnd, (HMENU)IDC_RADIO_CLIENT, NULL, NULL);
            SendMessage(g_hRadioClient, WM_SETFONT, (WPARAM)hFont, TRUE);
            SendMessage(g_hRadioClient, BM_SETCHECK, BST_CHECKED, 0);

            g_hRadioServer = CreateWindowExA(0, "BUTTON", "Server Mode",
                WS_VISIBLE | WS_CHILD | BS_AUTORADIOBUTTON,
                330, 15, 170, 22, hwnd, (HMENU)IDC_RADIO_SERVER, NULL, NULL);
            SendMessage(g_hRadioServer, WM_SETFONT, (WPARAM)hFont, TRUE);

            /* Server Address */
            g_hLabelAddr = CreateWindowExA(0, "STATIC", "Server Address (IP:Port):",
                WS_VISIBLE | WS_CHILD, 20, 48, 480, 18, hwnd, (HMENU)IDC_LABEL_ADDR, NULL, NULL);
            SendMessage(g_hLabelAddr, WM_SETFONT, (WPARAM)hFont, TRUE);

            g_hEditAddr = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "2.59.170.232:8443",
                WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, 20, 68, 480, 24, hwnd, (HMENU)IDC_EDIT_ADDR, NULL, NULL);
            SendMessage(g_hEditAddr, WM_SETFONT, (WPARAM)hFont, TRUE);

            /* Key */
            g_hLabelKey = CreateWindowExA(0, "STATIC", "Encryption Key (Paste key from server):",
                WS_VISIBLE | WS_CHILD, 20, 100, 480, 18, hwnd, (HMENU)IDC_LABEL_KEY, NULL, NULL);
            SendMessage(g_hLabelKey, WM_SETFONT, (WPARAM)hFont, TRUE);

            g_hEditKey = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "0ddd412de196b2bf2110d54ec8c1fa9e1155af78cb770721d9de03034a2e6852",
                WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, 20, 120, 480, 24, hwnd, (HMENU)IDC_EDIT_KEY, NULL, NULL);
            SendMessage(g_hEditKey, WM_SETFONT, (WPARAM)hFont, TRUE);

            g_hBtnGenKey = CreateWindowExA(0, "BUTTON", "Generate Key",
                WS_CHILD | BS_PUSHBUTTON, 390, 119, 110, 26, hwnd, (HMENU)IDC_BTN_GENKEY, NULL, NULL);
            SendMessage(g_hBtnGenKey, WM_SETFONT, (WPARAM)hFont, TRUE);

            /* Per-App Checkbox & Browse */
            g_hChkPerApp = CreateWindowExA(0, "BUTTON", "Per-App Routing (Only route selected .exe through tunnel)",
                WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 20, 155, 480, 20, hwnd, (HMENU)IDC_CHK_PERAPP, NULL, NULL);
            SendMessage(g_hChkPerApp, WM_SETFONT, (WPARAM)hFont, TRUE);

            g_hEditAppPath = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, 20, 180, 380, 24, hwnd, (HMENU)IDC_EDIT_APPPATH, NULL, NULL);
            SendMessage(g_hEditAppPath, WM_SETFONT, (WPARAM)hFont, TRUE);

            g_hBtnBrowse = CreateWindowExA(0, "BUTTON", "Browse...",
                WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 410, 179, 90, 26, hwnd, (HMENU)IDC_BTN_BROWSE, NULL, NULL);
            SendMessage(g_hBtnBrowse, WM_SETFONT, (WPARAM)hFont, TRUE);

            /* Toggle Button */
            g_hBtnToggle = CreateWindowExA(0, "BUTTON", "Connect Tunnel",
                WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON, 20, 215, 480, 34, hwnd, (HMENU)IDC_BTN_TOGGLE, NULL, NULL);
            SendMessage(g_hBtnToggle, WM_SETFONT, (WPARAM)hFont, TRUE);

            /* Log area */
            HWND hLabelLog = CreateWindowExA(0, "STATIC", "Connection & Activity Log:",
                WS_VISIBLE | WS_CHILD, 20, 258, 480, 18, hwnd, NULL, NULL, NULL);
            SendMessage(hLabelLog, WM_SETFONT, (WPARAM)hFont, TRUE);

            g_hEditLog = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                WS_VISIBLE | WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
                20, 278, 480, 150, hwnd, (HMENU)IDC_EDIT_LOG, NULL, NULL);
            SendMessage(g_hEditLog, WM_SETFONT, (WPARAM)hFont, TRUE);

            append_log("[Livekadeh Tunnel] Ready. Running with Administrator privileges.");
            break;
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
            } else if (wmId == IDC_BTN_GENKEY) {
                char new_key[128];
                if (generate_random_key_hex(new_key, sizeof(new_key)) == 0) {
                    SetWindowTextA(g_hEditKey, new_key);
                    append_log("[Key] Generated 256-bit encryption key.");
                }
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
                    SetWindowTextA(g_hEditAppPath, szFile);
                    SendMessage(g_hChkPerApp, BM_SETCHECK, BST_CHECKED, 0);
                }
            } else if (wmId == IDC_BTN_TOGGLE) {
                if (!g_is_running) {
                    gui_worker_params_t *p = (gui_worker_params_t *)malloc(sizeof(gui_worker_params_t));
                    p->is_server = g_mode_server;
                    p->is_per_app = (SendMessage(g_hChkPerApp, BM_GETCHECK, 0, 0) == BST_CHECKED);
                    GetWindowTextA(g_hEditAddr, p->addr, sizeof(p->addr));
                    GetWindowTextA(g_hEditKey, p->key, sizeof(p->key));
                    GetWindowTextA(g_hEditAppPath, p->app_path, sizeof(p->app_path));

                    if (strlen(p->key) == 0) {
                        if (p->is_server) {
                            generate_random_key_hex(p->key, sizeof(p->key));
                            SetWindowTextA(g_hEditKey, p->key);
                            append_log("[Server] Auto-generated key for session.");
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
                    EnableWindow(g_hChkPerApp, FALSE);
                    EnableWindow(g_hEditAppPath, FALSE);
                    EnableWindow(g_hBtnBrowse, FALSE);

                    char log_msg[512];
                    if (g_mode_server) {
                        snprintf(log_msg, sizeof(log_msg), "[Server] Running on %s", p->addr);
                    } else {
                        if (p->is_per_app && strlen(p->app_path) > 0) {
                            snprintf(log_msg, sizeof(log_msg), "[Wintun Per-App] Connecting to %s (Routing: %s)", p->addr, p->app_path);
                        } else {
                            snprintf(log_msg, sizeof(log_msg), "[Wintun Adapter] Connecting to %s. All server ports accessible via 10.10.10.1", p->addr);
                        }
                    }
                    append_log(log_msg);

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
                    EnableWindow(g_hChkPerApp, TRUE);
                    EnableWindow(g_hEditAppPath, TRUE);
                    EnableWindow(g_hBtnBrowse, TRUE);
                    append_log("[Tunnel] Disconnected.");
                }
            }
            break;
        }

        case WM_DESTROY:
            stop_active_tunnel();
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
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);

    RegisterClassA(&wc);

    int win_w = 540;
    int win_h = 485;
    int pos_x = (GetSystemMetrics(SM_CXSCREEN) - win_w) / 2;
    int pos_y = (GetSystemMetrics(SM_CYSCREEN) - win_h) / 2;

    HWND hwnd = CreateWindowExA(
        WS_EX_APPWINDOW,
        "LivekadehTunnelGUI",
        "Livekadeh Tunnel - Network Adapter (Wintun)",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        pos_x, pos_y, win_w, win_h,
        NULL, NULL, hInstance, NULL
    );

    if (!hwnd) return 1;

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
