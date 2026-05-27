#!/bin/bash
# Probe AWS Security Group UDP openness without poking AWS APIs.
# We spawn netcat UDP listeners on a few candidate ports, then ask the
# instance metadata service for the public IP so the client can target it.
set -u

echo "=== public IP (IMDSv2) ==="
TOKEN=$(curl -sS -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null)
PUBIP=$(curl -sS -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null)
echo "public-ip = ${PUBIP:-unknown}"

echo
echo "=== local IPs ==="
ip -o -4 addr show | awk '{print $2, $4}'

echo
echo "=== existing UDP listeners ==="
sudo ss -ulnp 2>/dev/null

echo
echo "=== will spawn one-shot UDP echo listeners on 8388, 8443, 443 ==="
# Kill anything we left lying around from a previous probe.
sudo pkill -f '_udp_echo_probe' 2>/dev/null
sleep 0.2

LOG=/tmp/_udp_probe.log
: >"$LOG"

start_udp_echo () {
    local port="$1"
    nohup bash -c "
        exec -a _udp_echo_probe_${port} bash -c '
            python3 - <<PY 2>>'$LOG'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.settimeout(45)
s.bind((\"0.0.0.0\", ${port}))
print(\"listen ${port}\", flush=True)
while True:
    try:
        data, addr = s.recvfrom(2048)
    except socket.timeout:
        print(\"timeout ${port}\", flush=True)
        break
    print(\"recv ${port}\", len(data), \"from\", addr, flush=True)
    s.sendto(b\"PONG:\" + data, addr)
PY
        '
    " >>"$LOG" 2>&1 &
    disown
}

# Need root for :443 only.
sudo bash -c "
    exec -a _udp_echo_probe_443 python3 - <<'PY' >>$LOG 2>&1 &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.settimeout(45)
s.bind(('0.0.0.0', 443))
print('listen 443', flush=True)
while True:
    try:
        data, addr = s.recvfrom(2048)
    except socket.timeout:
        print('timeout 443', flush=True)
        break
    print('recv 443', len(data), 'from', addr, flush=True)
    s.sendto(b'PONG:' + data, addr)
PY
"
echo "spawned 443 (root)"

for p in 8388 8443; do
    exec -a _udp_echo_probe_${p} python3 - <<PY >>"$LOG" 2>&1 &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.settimeout(45)
s.bind(("0.0.0.0", ${p}))
print("listen ${p}", flush=True)
while True:
    try:
        data, addr = s.recvfrom(2048)
    except socket.timeout:
        print("timeout ${p}", flush=True)
        break
    print("recv ${p}", len(data), "from", addr, flush=True)
    s.sendto(b"PONG:" + data, addr)
PY
    disown
    echo "spawned ${p}"
done

sleep 1
echo
echo "=== sockets after spawn ==="
sudo ss -ulnp | awk '/:443|:8388|:8443/'

echo
echo "=== log so far ==="
cat "$LOG"
echo "(probe listeners idle for 45s; client must hit ${PUBIP}:{443,8388,8443} now)"
