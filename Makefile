CC = gcc
WIN_CC = x86_64-w64-mingw32-gcc
CFLAGS = -O2 -Wall -Wextra
LDFLAGS_LINUX = -pthread
LDFLAGS_WIN = -lws2_32 -lcomctl32 -lcomdlg32 -lgdi32 -lfwpuclnt -s

BUILD_DIR = build

all: $(BUILD_DIR) linux windows

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

linux: main.c crypto.h tunnel_common.h menu_cli.h tun_proto.h tun_linux.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) main.c $(LDFLAGS_LINUX) -o $(BUILD_DIR)/livekadeh

windows: main.c crypto.h tunnel_common.h menu_cli.h tun_proto.h tun_wintun.h gui_win32.h | $(BUILD_DIR)
	$(WIN_CC) $(CFLAGS) main.c $(LDFLAGS_WIN) -o $(BUILD_DIR)/livekadeh.exe

clean:
	rm -f $(BUILD_DIR)/livekadeh $(BUILD_DIR)/livekadeh.exe

.PHONY: all clean linux windows
