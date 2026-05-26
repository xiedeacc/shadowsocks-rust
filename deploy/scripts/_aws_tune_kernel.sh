#!/usr/bin/env bash
# Idempotent AWS server tuning for the shadowsocks tunnel use-case.
#
# Targets the production server reachable as `ssh aws`. Run via:
#   ssh aws 'bash -s' < deploy/scripts/_aws_tune_kernel.sh
#
# What it changes:
#   1. Loads tcp_bbr + writes /etc/modules-load.d/bbr.conf so it survives reboot.
#   2. Drops a sysctl snippet into /etc/sysctl.d/99-shadowsocks-tune.conf with:
#      - BBR + fq qdisc (better behaviour at the cross-Pacific BDP we see).
#      - tcp_fastopen=3 (both client + server cookies; nginx and ssserver
#        both benefit because the upstream xray-plugin loopback uses TFO too).
#      - tcp_slow_start_after_idle=0 (xray-plugin keeps long-lived WS
#        connections, the kernel would otherwise reset cwnd after every
#        keepalive gap).
#      - bigger rmem_max / wmem_max / tcp_rmem / tcp_wmem so autotuning can
#        actually grow to the BDP for ~50 ms WAN links.
#      - bigger netdev backlog + somaxconn + syn_backlog for burst connect.
#      - tcp_mtu_probing=1 to survive PMTU black-holes through middleboxes.
#      - tcp_notsent_lowat=131072 to reduce HoL blocking on TLS records.
#   3. Bumps nginx events { worker_connections } from 768 to 16384 via
#      an idempotent sed patch, then reload-tests + reloads nginx.
#
# The script is safe to re-run: every step checks current state first.

set -euo pipefail

SUDO=""
if [[ $EUID -ne 0 ]]; then
    SUDO="sudo"
fi

echo "==[1/3]== BBR module"
if ! lsmod | grep -q '^tcp_bbr '; then
    $SUDO modprobe tcp_bbr
fi
if ! grep -q '^tcp_bbr$' /etc/modules-load.d/bbr.conf 2>/dev/null; then
    echo 'tcp_bbr' | $SUDO tee /etc/modules-load.d/bbr.conf >/dev/null
fi
echo "current congestion control: $(sysctl -n net.ipv4.tcp_congestion_control)"
echo "available: $(sysctl -n net.ipv4.tcp_available_congestion_control)"

echo "==[2/3]== sysctl snippet"
SYSCTL_FILE=/etc/sysctl.d/99-shadowsocks-tune.conf
$SUDO tee "$SYSCTL_FILE" >/dev/null <<'EOF'
# Managed by deploy/scripts/_aws_tune_kernel.sh

# Congestion control: BBR + fq pacing. fq is required for proper BBR
# pacing - without it BBR falls back to bursty behaviour on send.
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

# TCP Fast Open client+server. xray-plugin uses TFO on its TCP loopback
# to ssserver; cross-host TFO works opportunistically.
net.ipv4.tcp_fastopen = 3

# Persistent keepalive connections (xray-plugin WebSocket) regularly
# go idle for >RTO. Slow-start-after-idle would reset cwnd to ~10
# every time, killing first-byte time on bursty browsing.
net.ipv4.tcp_slow_start_after_idle = 0

# Socket buffer ceilings. Stock Ubuntu sets 212992 (208 KiB), which
# caps autotuning well below the BDP for ~50 ms links and starves
# parallel connections. 16 MiB allows up to ~2 Gbit/s per flow at
# 50 ms RTT.
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144

# TCP autotune ranges. The kernel picks within these bounds based on
# RTT and window growth. Max is in sync with rmem_max/wmem_max.
net.ipv4.tcp_rmem = 4096 262144 16777216
net.ipv4.tcp_wmem = 4096 262144 16777216

# Receive path: handle bursts without dropping under sudden load
# (common when a TUN client opens many short connections to fan out).
net.core.netdev_max_backlog = 10000
net.core.somaxconn = 8192
net.ipv4.tcp_max_syn_backlog = 8192

# PMTU discovery hardening - some intermediate carriers black-hole
# fragmentation needed messages, which strands long TLS records.
net.ipv4.tcp_mtu_probing = 1

# Limit unsent bytes in the send buffer so TLS records don't queue
# up behind one another; helps latency on interactive workloads.
net.ipv4.tcp_notsent_lowat = 131072

# Re-use TIME-WAIT sockets for outbound; xray-plugin opens many
# short-lived loopback connections to ssserver.
net.ipv4.tcp_tw_reuse = 1
EOF

$SUDO sysctl --system >/dev/null
echo "applied sysctl:"
sysctl net.ipv4.tcp_congestion_control \
       net.core.default_qdisc \
       net.ipv4.tcp_fastopen \
       net.ipv4.tcp_slow_start_after_idle \
       net.core.rmem_max \
       net.core.wmem_max \
       net.ipv4.tcp_mtu_probing \
       net.ipv4.tcp_notsent_lowat \
       net.core.somaxconn

echo "==[3/3]== nginx events { worker_connections }"
NGINX_CONF=/etc/nginx/nginx.conf
CURRENT=$(grep -E '^\s*worker_connections\s+' "$NGINX_CONF" | head -1 | awk '{print $2}' | tr -d ';')
echo "current worker_connections = $CURRENT"
if [[ "$CURRENT" != "16384" ]]; then
    $SUDO cp "$NGINX_CONF" "${NGINX_CONF}.bak.$(date +%s)"
    $SUDO sed -i -E 's/^(\s*worker_connections\s+)[0-9]+;/\116384;/' "$NGINX_CONF"
    if $SUDO nginx -t; then
        $SUDO systemctl reload nginx
        echo "nginx reloaded with worker_connections=16384"
    else
        echo "nginx -t FAILED, reverting"
        $SUDO mv "${NGINX_CONF}.bak."* "$NGINX_CONF"
        exit 1
    fi
fi

echo "done"
