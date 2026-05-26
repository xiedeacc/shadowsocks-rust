#!/bin/bash
# Adds an nginx top-level `stream` block that proxies UDP/443 to
# the local ssserver UDP listener (127.0.0.1:1080). Idempotent — re-running
# refuses to add a duplicate block.
set -euo pipefail

CONF=/etc/nginx/nginx.conf
TS=$(date +%Y%m%d_%H%M%S)
MARK_BEGIN="# === shadowsocks-rust udp via nginx stream (BEGIN) ==="
MARK_END="# === shadowsocks-rust udp via nginx stream (END) ==="

if sudo grep -qF "$MARK_BEGIN" "$CONF"; then
    echo "stream block already present in $CONF — nothing to do."
    sudo nginx -t
    exit 0
fi

echo "=== backup $CONF -> ${CONF}.bak.${TS} ==="
sudo cp -a "$CONF" "${CONF}.bak.${TS}"

echo "=== checking ssserver UDP listener (127.0.0.1:1080) ==="
sudo ss -ulnp | awk '/127.0.0.1:1080/' || true

read -r -d '' STREAM_BLOCK <<EOF || true

${MARK_BEGIN}
stream {
    log_format ss_udp '\$remote_addr [\$time_local] \$protocol '
                      '\$bytes_received/\$bytes_sent \$session_time '
                      '-> \$upstream_addr (\$upstream_bytes_received/\$upstream_bytes_sent)';
    access_log /var/log/nginx/ss-udp.log ss_udp;
    error_log  /var/log/nginx/ss-udp-error.log warn;

    server {
        listen 443 udp reuseport;
        proxy_pass        127.0.0.1:1080;
        proxy_timeout     600s;
        proxy_responses   0;
        proxy_buffer_size 64k;
    }
}
${MARK_END}
EOF

echo "=== appending stream block to $CONF ==="
echo "$STREAM_BLOCK" | sudo tee -a "$CONF" >/dev/null

echo "=== nginx -t ==="
if ! sudo nginx -t; then
    echo "!! nginx -t failed, rolling back"
    sudo cp -a "${CONF}.bak.${TS}" "$CONF"
    exit 1
fi

echo "=== reload nginx ==="
sudo systemctl reload nginx

sleep 1
echo
echo "=== UDP listeners after reload ==="
sudo ss -ulnp | awk '/:443|:1080/'

echo
echo "=== ssserver UDP loopback sanity check ==="
# Sending an unencrypted UDP datagram won't decrypt, but ssserver should at
# least accept it on the socket (we just verify nginx forwards to it).
# Watch ssserver's journal for "received" hints — only useful with debug logs,
# so skip; instead just confirm the port is reachable from inside the box.
echo -n "PING" | timeout 2 nc -u -w 1 127.0.0.1 443 >/dev/null 2>&1 || true
echo "=== nginx ss-udp.log tail ==="
sudo tail -n 10 /var/log/nginx/ss-udp.log 2>/dev/null || true
sudo tail -n 10 /var/log/nginx/ss-udp-error.log 2>/dev/null || true
echo "done."
