#!/bin/sh
# Track every connection from the Windows client: PROXIED (redirected to :12345) vs DIRECT (forwarded),
# recording the peak reply-byte count so we can see which connection carries order traffic.
CLIENT=192.168.2.166
: > /tmp/ct.raw
while true; do
  awk -v c="src=$CLIENT " '
    index($0, c) {
      odst=""; odport=""; osport=""; rbytes="0"; mode="DIRECT"; nb=0
      for (i=1;i<=NF;i++) {
        if ($i ~ /^dst=/ && odst=="")          odst=$i
        else if ($i ~ /^sport=/ && osport=="") osport=$i
        else if ($i ~ /^dport=/ && odport=="") odport=$i
        if ($i ~ /^bytes=/) { nb++; if (nb==2) { rbytes=$i } }
        if ($i == "sport=12345") mode="PROXIED"
      }
      if (odport != "dport=53" && odst !~ /dst=192\.168\./ && odst !~ /dst=127\./)
        printf "%s %s %s %s %s\n", mode, odst, odport, osport, rbytes
    }' /proc/net/nf_conntrack >> /tmp/ct.raw
  sort -u /tmp/ct.raw > /tmp/ct.log
  sleep 1
done
