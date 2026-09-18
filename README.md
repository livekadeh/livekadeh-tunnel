# Livekadeh Tunnel (لایوکده تانل) v1.1.1

A lightweight, high-performance, full-duplex TCP stream-encrypted tunnel and WireGuard-style Virtual Network Adapter (Wintun L3 VPN). Encrypts and tunnels arbitrary network traffic (SSH, Web, RDP, databases, or specific Windows applications) between Linux / MikroTik CHR servers and Windows/Linux clients without SSL/TLS overhead, identifiable handshakes, or Deep Packet Inspection (DPI) fingerprints.

---

## ⚡ Key Highlights

- **Single Unified Binary:** Both Server and Client engines are compiled into a single executable (`livekadeh_tunnel` on Linux, `livekadeh_tunnel.exe` on Windows).
- **Zero Handshake Footprint (Anti-DPI):** No TLS ClientHello, no certificates, no TLS SNI. The initial connection sends only a 16-byte cryptographically secure random nonce, presenting uniform random noise to DPI firewalls.
- **WireGuard-Style Virtual Network Adapter (`Wintun`):**
  - Connects to the server as a high-throughput virtual network card.
  - Transparent access to **all ports and protocols** on the remote server via `10.10.10.1` (SSH, HTTP/S, databases, UDP, Ping).
  - Optional **Per-App Routing** via Windows Filtering Platform (`WFP`) to tunnel only a specific `.exe` (e.g. `chrome.exe`), keeping other system traffic untouched.
- **Server Version Negotiation:**
  - Client automatically requests and displays the exact version of the connected server (e.g. `Connected to Livekadeh Tunnel Server v1.1.1`).
- **MikroTik CHR (RouterOS v7 Container) Ready:**
  - Dedicated pre-packaged `.tar` image (`livekadeh_tunnel-mikrotik-chr.tar`) ready for MikroTik `/container/add`.
  - Automatically fetches the latest release from GitHub on container startup.
  - Automatically displays the active encryption key in the MikroTik Container Log / WinBox!
- **Status & Diagnostics Command:**
  - View real-time service state, active encryption key, TUN interface status, and live TX/RX throughput using `livekadeh_tunnel -status`.
- **Automatic Administrator Elevation on Windows:**
  - Embedded Windows Application Manifest (`requireAdministrator`) and UAC auto-elevation logic.
- **Automatic Cryptographic Key Generation:**
  - Auto-generates a cryptographically secure 256-bit key when run without `-k`.
  - Standalone key generator: `livekadeh_tunnel genkey`.
- **Dual Interface (CLI + Native Windows GUI):**
  - Full CLI support with subcommands (`server`, `client`, `genkey`, `-status`).
  - Interactive terminal menu (`--menu`).
  - Native Win32 graphical window with real-time Send/Receive bandwidth display and per-app process picker.

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
├── gui_win32.h           # Native Windows GUI dialog (English UI + Traffic Monitor)
├── app.manifest          # Windows UAC Administrator execution manifest
├── app.rc                # Windows PE resource script
├── main.c                # Single unified entrypoint
├── wintun.h              # Official WireGuard Wintun C header
├── docker/
│   ├── Dockerfile        # MikroTik Container Dockerfile (Alpine + gcompat + iptables)
│   └── entrypoint.sh     # Auto-updater from GitHub & Key Logger script
├── Makefile              # Unified build automation
├── verify_tunnel.py      # Automated cryptographic test suite
└── build/
    ├── livekadeh_tunnel                    # Linux 64-bit unified binary (~51 KB)
    ├── livekadeh_tunnel.exe                # Windows 64-bit unified binary (~124 KB)
    ├── wintun.dll                          # Official WireGuard Wintun 64-bit driver (418 KB)
    ├── livekadeh_tunnel-windows-x86_64.zip # Windows bundle
    ├── livekadeh_tunnel-linux-x86_64.tar.gz# Linux bundle
    └── livekadeh_tunnel-mikrotik-chr.tar   # MikroTik CHR Container image (~23 MB)
```

---

## 🌐 Public GitHub Repository & Downloads

- **GitHub Repository:** [https://github.com/livekadeh/livekadeh-tunnel](https://github.com/livekadeh/livekadeh-tunnel)
- **Latest Release:** [https://github.com/livekadeh/livekadeh-tunnel/releases/tag/v1.1.1](https://github.com/livekadeh/livekadeh-tunnel/releases/tag/v1.1.1)
- **Windows Client:** [livekadeh_tunnel-windows-x86_64.zip](https://github.com/livekadeh/livekadeh-tunnel/releases/download/v1.1.1/livekadeh_tunnel-windows-x86_64.zip)
- **Linux Server / Client:** [livekadeh_tunnel-linux-x86_64.tar.gz](https://github.com/livekadeh/livekadeh-tunnel/releases/download/v1.1.1/livekadeh_tunnel-linux-x86_64.tar.gz)
- **MikroTik CHR Container:** [livekadeh_tunnel-mikrotik-chr.tar](https://github.com/livekadeh/livekadeh-tunnel/releases/download/v1.1.1/livekadeh_tunnel-mikrotik-chr.tar)

---

## 🚀 Quick Start & Deployment Guide

### 1. View Status & Active Key
Check the current tunnel state, active encryption key, and live traffic:
```bash
livekadeh_tunnel -status
```

Output:
```
==================================================================
       Livekadeh Tunnel Status (v1.1.1)
==================================================================
 Service/Process: RUNNING (Active)
 Encryption Key:  0ddd412de196b2bf2110d54ec8c1fa9e1155af78cb770721d9de03034a2e6852
 TUN Interface:   tun0 (10.10.10.1) [ONLINE]
 Traffic Stats:   Sent: 89.30 MB | Recv: 13.93 MB
==================================================================
```

---

### 2. MikroTik CHR Server Deployment (Container)

#### A. Enable Container Mode on MikroTik:
```routeros
/system/device-mode/update container=yes
/system/reboot
```

#### B. Setup Network Bridge & VETH:
```routeros
/interface/veth/add name=veth-livekadeh address=172.17.0.2/24 gateway=172.17.0.1
/interface/bridge/add name=bridge-docker
/ip/address/add address=172.17.0.1/24 interface=bridge-docker
/interface/bridge/port add bridge=bridge-docker interface=veth-livekadeh

/ip/firewall/nat/add chain=srcnat action=masquerade src-address=172.17.0.0/24
/ip/firewall/nat/add chain=dstnat action=dst-nat to-addresses=172.17.0.2 to-ports=8443 protocol=tcp dst-port=8443
```

#### C. Upload and Start Container:
1. Upload `livekadeh_tunnel-mikrotik-chr.tar` to your MikroTik storage via WinBox (Files) or SFTP.
2. In RouterOS Terminal:
```routeros
/container/add file=livekadeh_tunnel-mikrotik-chr.tar interface=veth-livekadeh logging=yes
/container/start 0
```
3. Check the WinBox **Log** window or run:
```routeros
/log/print where topics~"container"
```
The container will auto-update to the latest release, start the server, and print the **Encryption Key** in the log!

---

### 3. Linux Server Deployment (Systemd)

```bash
# Download and install binary
tar -xzf livekadeh_tunnel-linux-x86_64.tar.gz
sudo mv livekadeh_tunnel /usr/local/bin/livekadeh_tunnel

# Start systemd service
sudo nano /etc/systemd/system/livekadeh-tunnel.service
```

Service Definition:
```ini
[Unit]
Description=Livekadeh Tunnel VPN Server (Wintun / TUN)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/livekadeh_tunnel server --tun -l 0.0.0.0:8443 -k "YourSecretKey"
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now livekadeh-tunnel
```

---

### 4. Windows Client Deployment (GUI & Per-App)

1. Download and unzip `livekadeh_tunnel-windows-x86_64.zip`.
2. Run `livekadeh_tunnel.exe` as Administrator.
3. Enter Server IP (`<SERVER_IP>:8443`) and the Encryption Key.
4. (Optional) Choose **Per-App Routing** to select specific executables (Chrome, Firefox, etc.).
5. Click **[ Connect Tunnel ]**.
6. View live **Sent** and **Received** traffic in the status bar at the bottom.
