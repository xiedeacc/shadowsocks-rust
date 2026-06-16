#!/bin/sh
# One-shot snapshot of every DIRECT (forwarded, NOT proxied) connection from the Windows client,
# with original destination, client source port, and reply byte count.
# Excludes proxied (:12345), DNS (53), NTP (123), the quote stream (9595), and LAN dests.
CLIENT=192.168.2.166
awk -v c="src=$CLIENT " '
  index($0, c) {
    odst=""; odport=""; osport=""; rbytes=0; nb=0; proxied=0
    for (i=1;i<=NF;i++) {
      if ($i ~ /^dst=/ && odst=="")          odst=$i
      else if ($i ~ /^sport=/ && osport=="") osport=$i
      else if ($i ~ /^dport=/ && odport=="") odport=$i
      if ($i ~ /^bytes=/) { nb++; if (nb==2) { sub("bytes=","",$i); rbytes=$i } }
      if ($i == "sport=12345") proxied=1
    }
    if (proxied) next
    if (odport == "dport=53" || odport == "dport=123" || odport == "dport=9595") next
    if (odst ~ /dst=192\.168\./ || odst ~ /dst=127\./) next
    sub("dst=","",odst); sub("dport=","",odport); sub("sport=","",osport)
    printf "%-16s :%-5s lport=%-6s rbytes=%s\n", odst, odport, osport, rbytes
  }' /proc/net/nf_conntrack | sort
