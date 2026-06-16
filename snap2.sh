#!/bin/sh
# Dump every public connection from the Windows client with orig+reply byte counts and proxied/direct mode.
# Output: mode dst dport sport origbytes replybytes  (one line per connection)
CLIENT=192.168.2.166
awk -v c="src=$CLIENT " '
  index($0, c) {
    odst=""; odport=""; osport=""; ob=0; rb=0; nb=0; mode="DIRECT"
    for (i=1;i<=NF;i++) {
      if ($i ~ /^dst=/ && odst=="")          odst=$i
      else if ($i ~ /^sport=/ && osport=="") osport=$i
      else if ($i ~ /^dport=/ && odport=="") odport=$i
      if ($i ~ /^bytes=/) { nb++; v=$i; sub("bytes=","",v); if (nb==1) ob=v; else if (nb==2) rb=v }
      if ($i == "sport=12345") mode="PROXIED"
    }
    if (odport=="dport=53" || odport=="dport=123" || odport=="dport=9595") next
    if (odst ~ /dst=192\.168\./ || odst ~ /dst=127\./) next
    sub("dst=","",odst); sub("dport=","",odport); sub("sport=","",osport)
    printf "%s %s %s %s %s %s\n", mode, odst, odport, osport, ob, rb
  }' /proc/net/nf_conntrack | sort
