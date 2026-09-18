#!/bin/sh
set -e

echo ""
echo "=================================================================="
echo "          Livekadeh Tunnel - MikroTik CHR Container              "
echo "=================================================================="

# 1. Ensure /dev/net/tun exists
mkdir -p /dev/net
if [ ! -c /dev/net/tun ]; then
    mknod /dev/net/tun c 10 200 2>/dev/null || true
fi

# 2. Try downloading latest release from GitHub
LATEST_URL="https://github.com/livekadeh/livekadeh-tunnel/releases/latest/download/livekadeh_tunnel-linux-x86_64.tar.gz"
echo "[*] Checking GitHub for updates ($LATEST_URL)..."

UPDATE_DIR="/tmp/livekadeh_update"
mkdir -p "$UPDATE_DIR"

if curl -sL --connect-timeout 5 --max-time 15 "$LATEST_URL" -o "$UPDATE_DIR/update.tar.gz" 2>/dev/null || \
   wget -q -T 5 -t 1 "$LATEST_URL" -O "$UPDATE_DIR/update.tar.gz" 2>/dev/null; then
    if tar -xzf "$UPDATE_DIR/update.tar.gz" -C "$UPDATE_DIR" 2>/dev/null; then
        if [ -f "$UPDATE_DIR/livekadeh_tunnel" ]; then
            cp -f "$UPDATE_DIR/livekadeh_tunnel" /usr/local/bin/livekadeh_tunnel
            chmod +x /usr/local/bin/livekadeh_tunnel
            echo "[+] Successfully updated livekadeh_tunnel from GitHub release!"
        fi
    fi
    rm -rf "$UPDATE_DIR"
else
    echo "[!] Could not fetch update from GitHub (using bundled version)."
fi

# 3. Resolve Port
PORT="${TUNNEL_PORT:-${PORT:-8443}}"

# 4. Resolve Encryption Key
KEY_FILE="/etc/livekadeh_tunnel.key"
ACTIVE_KEY=""

if [ -n "$TUNNEL_KEY" ]; then
    ACTIVE_KEY="$TUNNEL_KEY"
elif [ -n "$KEY" ]; then
    ACTIVE_KEY="$KEY"
elif [ -s "$KEY_FILE" ]; then
    ACTIVE_KEY="$(cat "$KEY_FILE" | tr -d '\r\n ')"
fi

if [ -z "$ACTIVE_KEY" ]; then
    # Generate new key
    GEN_OUTPUT="$(/usr/local/bin/livekadeh_tunnel genkey 2>/dev/null || true)"
    ACTIVE_KEY="$(echo "$GEN_OUTPUT" | grep -oE '[0-9a-f]{64}' | head -n 1)"
    if [ -z "$ACTIVE_KEY" ]; then
        ACTIVE_KEY="0ddd412de196b2bf2110d54ec8c1fa9e1155af78cb770721d9de03034a2e6852"
    fi
fi

# Save key for persistence and -status command
echo "$ACTIVE_KEY" > "$KEY_FILE"

# 5. Output prominent banner in container log
echo ""
echo "=================================================================="
echo " >>> LIVEKADEH TUNNEL SERVER RUNNING <<<"
echo " Version:        $(/usr/local/bin/livekadeh_tunnel -v 2>/dev/null || echo 'v1.1.1')"
echo " Listen Port:    $PORT (TCP)"
echo " Subnet IP:      10.10.10.1 (Server) <-> 10.10.10.2 (Client)"
echo "------------------------------------------------------------------"
echo " ENCRYPTION KEY:"
echo " $ACTIVE_KEY"
echo "=================================================================="
echo " Hint: Run '/container/shell <id>' and type 'livekadeh_tunnel -status'"
echo "       to see real-time tunnel status, IP, and traffic."
echo "=================================================================="
echo ""

# 6. Execute server
exec /usr/local/bin/livekadeh_tunnel server --tun -l "0.0.0.0:$PORT" -k "$ACTIVE_KEY"
