#!/bin/bash
# Spin a UDP echo on 127.0.0.1:30000 (loopback only -- reachable through
# nginx if we add a stream block, or reachable as a "destination" via
# the ssserver UDP relay since ssserver accepts dst=anywhere).
# For end-to-end testing we actually need it to be REACHABLE FROM THE
# INTERNET so the client's SS-UDP relay can target it. ssserver will
# forward the decrypted UDP datagram to the (target_ip, target_port)
# embedded in the SS-UDP packet -- so we just need this listener to be
# reachable from ssserver, i.e. localhost works.
set -u
DUR="${1:-180}"
sudo pkill -f '_ss_udp_echo' 2>/dev/null || true
sleep 0.2
LOG=/tmp/_ss_udp_echo.log
sudo rm -f "$LOG"
sudo touch "$LOG"
sudo chmod 666 "$LOG"
nohup bash -c "
    exec -a _ss_udp_echo python3 - <<'PY' >>$LOG 2>&1
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.settimeout(${DUR})
s.bind(('0.0.0.0', 30000))
print(time.strftime('%H:%M:%S'), 'listen 30000', flush=True)
while True:
    try:
        data, addr = s.recvfrom(2048)
    except socket.timeout:
        print(time.strftime('%H:%M:%S'), 'idle timeout', flush=True)
        break
    print(time.strftime('%H:%M:%S'), 'recv', len(data), 'from', addr, repr(data[:32]), flush=True)
    s.sendto(b'PONG:' + data, addr)
PY
" >>"$LOG" 2>&1 &
disown
sleep 0.5
echo "spawned _ss_udp_echo for ${DUR}s on 0.0.0.0:30000"
sudo ss -ulnp | awk '/:30000/'
echo "log: $LOG"
