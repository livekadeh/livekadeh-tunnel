# Livekadeh Tunnel (لایوکده تانل)

A lightweight, high-performance, full-duplex TCP stream-encrypted tunnel and WireGuard-style Virtual Network Adapter (Wintun L3 VPN). Encrypts and tunnels arbitrary network traffic (SSH, Web, RDP, databases, or specific Windows applications) between Linux servers and Windows/Linux clients without SSL/TLS overhead, identifiable handshakes, or Deep Packet Inspection (DPI) fingerprints.

---

## ⚡ Key Highlights

- **Single Unified Binary:** Both Server and Client engines are compiled into a single executable (`livekadeh` on Linux, `livekadeh.exe` on Windows).
- **Zero Handshake Footprint (Anti-DPI):** No TLS ClientHello, no certificates, no TLS SNI. The initial connection sends only a 16-byte cryptographically secure random nonce, presenting uniform random noise to DPI firewalls.
- **WireGuard-Style Virtual Network Adapter (`Wintun`):**
  - Connects to the server as a high-throughput virtual network card.
  - Transparent access to **all ports and protocols** on the remote server via `10.10.10.1` (SSH, HTTP/S, databases, UDP, Ping).
  - Optional **Per-App Routing** via Windows Filtering Platform (`WFP`) to tunnel only a specific `.exe` (e.g. `chrome.exe`), keeping other system traffic untouched.
- **Automatic Administrator Elevation on Windows:**
  - Embedded Windows Application Manifest (`requireAdministrator`) and UAC auto-elevation logic.
  - Automatically requests administrator privileges upon launch without manual configuration.
- **Automatic Cryptographic Key Generation:**
  - Running in server mode without a key automatically generates a cryptographically secure 256-bit key to share with clients.
  - Standalone key generation subcommand: `livekadeh genkey`.
- **Dual Interface (CLI + 100% English Native GUI):**
  - Full CLI support with subcommands (`server`, `client`, `genkey`).
  - Interactive terminal menu when launched without arguments in console (`--menu`).
  - Native Win32 graphical window with application file browser and live connection log.

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
├── gui_win32.h           # Native Windows GUI dialog (English UI)
├── app.manifest          # Windows UAC Administrator execution manifest
├── app.rc                # Windows PE resource script
├── main.c                # Single unified entrypoint
├── wintun.h              # Official WireGuard Wintun C header
├── Makefile              # Unified build automation
├── verify_tunnel.py      # Automated cryptographic test suite
└── build/
    ├── livekadeh         # Linux 64-bit unified executable (~47 KB)
    ├── livekadeh.exe     # Windows 64-bit unified executable (~77 KB, with UAC manifest)
    ├── wintun.dll        # Official WireGuard Wintun 64-bit driver (418 KB)
    ├── livekadeh-windows-x86_64.zip
    └── livekadeh-linux-x86_64.tar.gz
```

---

## 🌐 Public GitHub Repository & Releases

- **GitHub Repository:** [https://github.com/livekadeh/livekadeh-tunnel](https://github.com/livekadeh/livekadeh-tunnel)
- **Releases:** [https://github.com/livekadeh/livekadeh-tunnel/releases/tag/v1.0.0](https://github.com/livekadeh/livekadeh-tunnel/releases/tag/v1.0.0)
- **Download Windows ZIP:** [livekadeh-windows-x86_64.zip](https://github.com/livekadeh/livekadeh-tunnel/releases/download/v1.0.0/livekadeh-windows-x86_64.zip)

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

## 🚀 Deployment & Usage Guide

### 1. Key Generation
Generate a secure 256-bit encryption key:
```bash
./build/livekadeh genkey
```

---

### 2. Full Network Adapter Mode (Access All Server Ports via `10.10.10.1`)

#### Server Side (Linux):
Run with `--tun` to create virtual network device `tun0` (IP `10.10.10.1`) and enable kernel NAT masquerade:
```bash
sudo /usr/local/bin/livekadeh server --tun -l 0.0.0.0:8443 -k "YourSecretKey"
```

#### Systemd Service (`/etc/systemd/system/livekadeh-tunnel.service`):
```ini
[Unit]
Description=Livekadeh Tunnel VPN Server (Wintun / TUN)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/livekadeh server --tun -l 0.0.0.0:8443 -k "YourSecretKey"
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```
Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now livekadeh-tunnel
```

#### Client Side (Windows - GUI):
1. Download and extract `livekadeh-windows-x86_64.zip`.
2. Double-click `livekadeh.exe` (automatically elevates to Administrator).
3. Select **Client Mode (Wintun Virtual Network Adapter)**.
4. Enter Server Address: `<SERVER_IP>:8443`
5. Paste Encryption Key.
6. Click **[ Connect Tunnel ]**.

#### Connecting to Server Services from Windows:
Once connected, the Windows client is assigned IP `10.10.10.2` and the server is at `10.10.10.1`. You have direct, encrypted access to **all server ports**:
- **SSH:** `ssh root@10.10.10.1`
- **Web Services:** Browse `http://10.10.10.1` or `https://10.10.10.1`
- **MySQL / PostgreSQL:** Connect to `10.10.10.1:3306` or `10.10.10.1:5432`
- **Ping / ICMP:** `ping 10.10.10.1`

---

### 3. WireGuard-Style Per-App Routing Mode

Route only a single selected application through the tunnel:

#### In Windows GUI:
1. Check **Per-App Routing (Only route selected .exe through tunnel)**.
2. Click **[ Browse... ]** and select target executable (e.g. `C:\Program Files\Google\Chrome\Application\chrome.exe`).
3. Click **[ Connect Tunnel ]**.

#### In Windows CLI:
```powershell
.\livekadeh.exe client -s <SERVER_IP>:8443 --app "C:\Path\To\app.exe" -k "YourSecretKey"
```

---

### 4. Single Port Forwarding Mode (Alternative to Virtual Adapter)

To proxy a single local TCP port (e.g. for SSH without creating a virtual network adapter):

#### Server:
```bash
./build/livekadeh server -l 0.0.0.0:8443 -t 127.0.0.1:22 -k "YourSecretKey"
```

#### Client:
```powershell
.\livekadeh.exe client -s <SERVER_IP>:8443 -l 127.0.0.1:2222 --port-forward -k "YourSecretKey"
ssh -p 2222 root@127.0.0.1
```

---

## 🔒 Verification & Security Testing

Run the automated integration test verifying 1MB bidirectional throughput and SSH handshake transmission:

```bash
python3 verify_tunnel.py
```
