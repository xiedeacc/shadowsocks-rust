#!/bin/bash
# Trace UDP packets ssserver sends/receives. Saves to /tmp/_ssudp.pcap
# and prints a brief tail for inspection.
set -u
DUR="${1:-30}"
sudo pkill -f '_ssudp_dump' 2>/dev/null
sleep 0.2
sudo tcpdump -i ens5 -nn -e -ttt -v -s 0 -U \
    'udp and (host 162.159.200.1 or host 54.179.191.126 or portrange 30000-30000)' \
    -G "$DUR" -W 1 -w /tmp/_ssudp_ens5.pcap >/dev/null 2>&1 &
sudo tcpdump -i lo -nn -e -ttt -v -s 0 -U \
    'udp and (port 1080 or port 30000 or port 443)' \
    -G "$DUR" -W 1 -w /tmp/_ssudp_lo.pcap >/dev/null 2>&1 &
echo "tcpdump for ${DUR}s started"
echo "waiting ${DUR}s for activity..."
sleep "$DUR"
echo "--- ens5 (external) ---"
sudo tcpdump -nn -e -ttt -r /tmp/_ssudp_ens5.pcap 2>/dev/null | head -50
echo "--- lo (loopback nginx<->ssserver) ---"
sudo tcpdump -nn -e -ttt -r /tmp/_ssudp_lo.pcap 2>/dev/null | head -50
