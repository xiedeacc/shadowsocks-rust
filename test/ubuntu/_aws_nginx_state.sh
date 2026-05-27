#!/bin/bash
set -u
echo "=== nginx -V ==="
sudo nginx -V 2>&1 | tr ' ' '\n' | grep -E 'with-stream|conf-path|prefix=' || true
echo
echo "=== nginx.conf top-level (events/http/stream lines) ==="
sudo awk '/^[a-z]+ *{/{lvl++} /^}/{lvl--} {if(lvl<=0) print NR": "$0}' /etc/nginx/nginx.conf | head -120
echo
echo "=== includes ==="
sudo grep -n '^include\|include ' /etc/nginx/nginx.conf
sudo grep -rn '^include\|include ' /etc/nginx/conf.d/ 2>/dev/null
echo
echo "=== conf.d listing ==="
ls -la /etc/nginx/conf.d/ /etc/nginx/sites-enabled/ /etc/nginx/sites-available/ 2>/dev/null | head -30
echo
echo "=== stream-related already present? ==="
sudo grep -rn 'stream\|listen .*udp' /etc/nginx/ 2>/dev/null | head -20
