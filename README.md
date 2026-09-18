# Livekadeh Tunnel (لایوکده تانل)

A lightweight, high-performance, full-duplex TCP stream-encrypted tunnel and WireGuard-style Per-App L3 VPN. Encrypts and proxies arbitrary traffic (such as SSH, RDP, or specific Windows applications) between Linux servers and Windows/Linux clients without SSL/TLS overhead, identifiable handshakes, or DPI fingerprints.

---

## ⚡ Key Highlights

- **Single Unified Binary:** Both Server and Client engines are compiled into a single executable (`livekadeh` on Linux, `livekadeh.exe` on Windows).
- **Zero Handshake Footprint (Anti-DPI):** No TLS ClientHello, no certificates, no TLS SNI. Session starts with a 16-byte random nonce, presenting uniform random binary noise to Deep Packet Inspection (DPI) firewalls.
- **WireGuard-Style Per-App VPN (`Wintun` + `WFP`):**
  - Routes only a specific application (e.g. `chrome.exe`, `app.exe`) through the encrypted tunnel.
  - All other applications continue using the standard local network untouched.
  - Uses the official WireGuard high-throughput `wintun.dll` driver and Windows Filtering Platform (`WFP`).
- **Automatic Cryptographic Key Generation:**
  - Running in server mode without a key automatically generates a cryptographically secure 256-bit key to share with clients.
  - Standalone key generation subcommand: `livekadeh genkey`.
- **Dual Interface (CLI + Native GUI):**
  - Full CLI support with subcommands (`server`, `client`, `genkey`).
  - Interactive terminal menu when launched without arguments in console.
  - Native Win32 graphical window (`livekadeh.exe`) with App file picker and live activity log.

---

## 📁 Directory Structure

```
livekadeh_tunnel/
├── crypto.h              # Standalone SHA-256, HMAC-SHA256 & RFC 8439 ChaCha20
├── tunnel_common.h       # Cross-platform socket and threading abstractions
├── menu_cli.h            # Interactive terminal menu
├── tun_proto.h           # L3 Packet framing and transport engine
├── tun_linux.h           # Linux TUN device (/dev/net/tun) & NAT masquerade
├── tun_wintun.h          # Windows Wintun driver loader & WFP Per-App router
├── gui_win32.h           # Native Windows GUI dialog with file browse
├── main.c                # Single unified entrypoint
├── wintun.h              # Official WireGuard Wintun C header
├── Makefile              # Unified build automation
├── verify_tunnel.py      # Automated cryptographic test suite
└── build/
    ├── livekadeh         # Linux 64-bit unified executable (~47 KB)
    ├── livekadeh.exe     # Windows 64-bit unified executable (~75 KB)
    └── wintun.dll        # Official WireGuard Wintun 64-bit driver
```

---

## 🛠️ Build Instructions

From Linux host:

```bash
cd /root/test_project/livekadeh_tunnel

# Compile unified binaries for Linux and Windows
make all

# Or compile individual targets:
make linux    # build/livekadeh
make windows  # build/livekadeh.exe
```

---

## 🚀 Usage Guide

### 1. Key Generation
Generate a secure 256-bit encryption key:
```bash
./build/livekadeh genkey
```

---

### 2. Standard TCP Port Forwarding (e.g. for SSH)

#### Server Side (Linux):
```bash
# Auto-generates a key and forwards to local SSH port 22:
./build/livekadeh server -l 0.0.0.0:8443 -t 127.0.0.1:22

# Or specify your own key:
./build/livekadeh server -l 0.0.0.0:8443 -t 127.0.0.1:22 -k "YourSecretKey"
```

#### Client Side (Windows - CLI):
```powershell
.\livekadeh.exe client -s <SERVER_IP>:8443 -l 127.0.0.1:2222 -k "YourSecretKey"
```
Then connect via SSH:
```powershell
ssh -p 2222 root@127.0.0.1
```

---

### 3. WireGuard-Style Per-App VPN Mode (`Wintun` + `WFP`)

Route an entire application's network traffic through the encrypted tunnel:

#### Server Side (Linux):
Start the L3 VPN tunnel server (automatically creates `tun0`, enables IP forwarding, and configures `iptables` NAT):
```bash
sudo ./build/livekadeh server --tun -l 0.0.0.0:8443 -k "YourSecretKey"
```

#### Client Side (Windows - GUI):
1. Place `livekadeh.exe` and `wintun.dll` in the same directory.
2. Run `livekadeh.exe` (Run as Administrator for Wintun/WFP adapter installation).
3. Select **Client Mode**.
4. Check **Per-App VPN Mode**.
5. Click **[ Browse... ]** and select the executable (e.g. `C:\Program Files\Google\Chrome\Application\chrome.exe`).
6. Enter the Server IP and Secret Key, then click **[ Start Tunnel ]**.

#### Client Side (Windows - CLI):
```powershell
# Run PowerShell as Administrator:
.\livekadeh.exe client -s <SERVER_IP>:8443 --app "C:\Path\To\YourApp.exe" -k "YourSecretKey"
```

---

### 4. Interactive Terminal Menu
Run without arguments or with `--menu`:
```bash
./build/livekadeh --menu
```
```
===================================================
       Livekadeh Tunnel (لایوکده تانل)
===================================================
  [1] Start Tunnel Server
  [2] Start Tunnel Client
  [3] Generate Secure Encryption Key
  [4] Exit
===================================================
```
