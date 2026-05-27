#!/usr/bin/env bash
# Enable TLS 1.3 session resumption + 0-RTT on nginx.
#
# Why this matters: without tickets nginx 1.30 + TLS 1.3 forces a full
# 1-RTT handshake on every new connection, because TLS 1.3 deleted the
# session-id resumption mechanism (only stateless tickets survived).
# Once mux=8 is enabled in xray-plugin the tunnel reconnects rarely, but
# every full reconnect (and every parallel TCP connection from a fresh
# Chrome tab) eats one extra RTT to AWS Singapore (~50 ms each).
#
# Trade-off: tickets carry forward-secrecy risk if the ticket key is
# compromised. We mitigate by:
#   * Keeping default ticket lifetime (24h ish via session_timeout).
#   * Letting nginx rotate keys per restart.
# 0-RTT (early data) is intentionally NOT enabled because xray-plugin
# uses POST-equivalent semantics inside the WebSocket frames and 0-RTT
# would expose those to replay.

set -euo pipefail
SUDO=""; [[ $EUID -ne 0 ]] && SUDO="sudo"

CONF=/etc/nginx/nginx.conf
BACKUP="${CONF}.bak.$(date +%s)"
$SUDO cp "$CONF" "$BACKUP"

# Flip ssl_session_tickets off -> on (idempotent: if already on, no change).
if grep -qE '^\s*ssl_session_tickets\s+off;' "$CONF"; then
    $SUDO sed -i -E 's/^(\s*ssl_session_tickets\s+)off;/\1on;/' "$CONF"
    echo "ssl_session_tickets: off -> on"
elif grep -qE '^\s*ssl_session_tickets\s+on;' "$CONF"; then
    echo "ssl_session_tickets already on"
else
    # No directive found at all; insert after the session_cache line
    $SUDO sed -i -E '/^\s*ssl_session_cache\s+/a\    ssl_session_tickets  on;' "$CONF"
    echo "ssl_session_tickets directive inserted"
fi

# Bump session_timeout to keep tickets valid longer (24h instead of 5m).
# Longer than 24h is discouraged for FS reasons.
$SUDO sed -i -E 's/^(\s*ssl_session_timeout\s+).+;/\11d;/' "$CONF"

if $SUDO nginx -t; then
    $SUDO systemctl reload nginx
    echo "nginx reloaded; current TLS settings:"
    grep -E 'ssl_session_(tickets|timeout|cache)' "$CONF" | head -5
else
    echo "nginx -t failed, reverting from $BACKUP"
    $SUDO cp "$BACKUP" "$CONF"
    exit 1
fi
