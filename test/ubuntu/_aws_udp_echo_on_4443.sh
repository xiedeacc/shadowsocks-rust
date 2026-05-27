#!/bin/bash
# Spin up a one-shot UDP echo on 0.0.0.0:4443 (a port we can choose freely
# for SG validation without touching the ssserver path on 443).
# Stays up for $1 seconds (default 60).
set -u
DUR="${1:-60}"
PORT=4443
sudo pkill -f '_udp_echo_probe_4443' 2>/dev/null
sleep 0.2
LOG=/tmp/_udp_probe_4443.log
sudo rm -f "$LOG"
sudo touch "$LOG"
sudo chmod 666 "$LOG"
exec -a _udp_echo_probe_4443 python3 - <<PY >>"$LOG" 2>&1 &
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.settimeout(${DUR})
s.bind(("0.0.0.0", ${PORT}))
print("listen ${PORT}", flush=True)
while True:
    try:
        data, addr = s.recvfrom(2048)
    except socket.timeout:
        print("timeout ${PORT}", flush=True)
        break
    print("recv ${PORT}", len(data), "from", addr, flush=True)
    s.sendto(b"PONG:" + data, addr)
PY
disown
sleep 0.5
echo "spawned echo on UDP/${PORT} for ${DUR}s"
sudo ss -ulnp | awk '/:4443/'
echo "log: $LOG"
