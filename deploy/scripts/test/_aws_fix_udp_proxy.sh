#!/bin/bash
# Fix the nginx stream UDP block: replace
#   proxy_responses 0;
# (which means "do not forward any reply") with the default behaviour
# (no proxy_responses directive at all -> unlimited replies). Then
# reload nginx.
set -euo pipefail
CONF=/etc/nginx/nginx.conf
TS=$(date +%Y%m%d_%H%M%S)
sudo cp -a "$CONF" "${CONF}.bak.${TS}"

# Strip the proxy_responses line inside our managed block.
sudo awk '
BEGIN { in_block = 0 }
/# === shadowsocks-rust udp via nginx stream \(BEGIN\) ===/ { in_block = 1 }
in_block && /^[[:space:]]*proxy_responses[[:space:]]+/ { next }
/# === shadowsocks-rust udp via nginx stream \(END\) ===/ { in_block = 0 }
{ print }
' "$CONF" > /tmp/_nginx.new
sudo mv /tmp/_nginx.new "$CONF"
sudo chmod 644 "$CONF"

echo "=== updated stream block ==="
sudo awk '/shadowsocks-rust udp/,/END/' "$CONF"

echo
echo "=== nginx -t ==="
if ! sudo nginx -t 2>&1; then
    echo "!! nginx -t failed, rolling back"
    sudo cp -a "${CONF}.bak.${TS}" "$CONF"
    exit 1
fi

echo
echo "=== reload nginx ==="
sudo systemctl reload nginx

sleep 1
echo
echo "=== UDP listeners ==="
sudo ss -ulnp | awk '/:443|:1080/'
