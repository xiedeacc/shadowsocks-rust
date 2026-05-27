#!/bin/sh
# sslocal-watch — long-running OpenWrt diagnostic sampler for shadowsocks-rust.
#
# Why this exists
# ---------------
# We've been hitting a recurring failure where the router stops forwarding
# any traffic until the shadowsocks-rust service is restarted. The visible
# symptoms (SSH to the router itself slows down, SSH to the SS server
# fails, DNS dies) all match either CPU saturation, memory pressure, or
# kernel-state exhaustion (conntrack / file descriptors / socket buffers).
#
# Once it dies in real time it's nearly impossible to log into the box and
# poke around — by then SSH itself is degraded. So this script runs as
# its own /etc/init.d service, samples cheap counters every SAMPLE_SEC
# seconds, and writes a rotating log. After a hang we just look at the
# last ~5 minutes of samples and the cause is usually obvious.
#
# What it captures every sample
# -----------------------------
# * sslocal: RSS, VSZ, %CPU, threads, fd count, /proc/PID/status NFD-ish
# * sslocal sockets: tcp/udp/established/listen counts (per process)
# * global: load avg, MemAvailable, /proc/net/sockstat (TCP/UDP/orphan),
#           /proc/net/nf_conntrack count by proto
# * routing: GET http://127.0.0.1:9090/api/dns/cache/stats (via curl)
# * reachability: ping LAN gateway, ping SS server (port 22 TCP probe),
#                 DNS-direct query to 223.5.5.5 (must NOT go through ss)
#
# Health gate
# -----------
# A sample is "unhealthy" if any of:
#   - sslocal RSS over RSS_WARN_KB
#   - sslocal fd count over FD_WARN
#   - conntrack over CT_WARN
#   - reachability probes failing
# When unhealthy we additionally dump:
#   - top -bn1 (CPU snapshot)
#   - ss -s and ss -ant | head
#   - dmesg -T | tail
#
# Tuning knobs (env or /etc/sslocal-watch.conf)
SAMPLE_SEC="${SAMPLE_SEC:-30}"
LOG_DIR="${LOG_DIR:-/usr/local/shadowsocks/logs}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/sslocal-watch.log}"
MAX_LOG_BYTES="${MAX_LOG_BYTES:-2097152}"   # 2 MiB rotation
ROTATE_KEEP="${ROTATE_KEEP:-3}"
RSS_WARN_KB="${RSS_WARN_KB:-65536}"          # warn if RSS > 64 MiB
FD_WARN="${FD_WARN:-2048}"
CT_WARN="${CT_WARN:-100000}"
WEB_ADMIN_URL="${WEB_ADMIN_URL:-http://127.0.0.1:9090/api/dns/cache/stats}"
SS_SERVER="${SS_SERVER:-54.179.191.126}"
SS_PROBE_PORT="${SS_PROBE_PORT:-443}"
LAN_GATEWAY="${LAN_GATEWAY:-192.168.2.1}"
DIRECT_DNS="${DIRECT_DNS:-223.5.5.5}"
PROBE_DOMAIN="${PROBE_DOMAIN:-www.aliyun.com}"

[ -f /etc/sslocal-watch.conf ] && . /etc/sslocal-watch.conf

mkdir -p "$LOG_DIR"

ts() { date '+%Y-%m-%dT%H:%M:%S'; }

rotate_log() {
	[ -f "$LOG_FILE" ] || return 0
	sz=$(wc -c <"$LOG_FILE" 2>/dev/null || echo 0)
	[ "$sz" -lt "$MAX_LOG_BYTES" ] && return 0
	i="$ROTATE_KEEP"
	while [ "$i" -gt 0 ]; do
		prev=$((i - 1))
		[ -f "$LOG_FILE.$prev" ] && mv "$LOG_FILE.$prev" "$LOG_FILE.$i"
		i=$prev
	done
	mv "$LOG_FILE" "$LOG_FILE.0"
	: >"$LOG_FILE"
}

emit() { printf '[%s] %s\n' "$(ts)" "$*" >>"$LOG_FILE"; }

emit_block() {
	header="$1"
	shift
	emit "----- $header -----"
	{ "$@"; } 2>&1 | sed 's/^/    /' >>"$LOG_FILE"
}

# Locate sslocal pid. Prefer procd's tracked one; fall back to pgrep.
sslocal_pid() {
	# procd sets /var/run/$service.pid in newer builds; not guaranteed.
	for f in /var/run/shadowsocks-rust.pid /var/run/sslocal.pid; do
		if [ -f "$f" ]; then
			pid=$(cat "$f" 2>/dev/null)
			[ -n "$pid" ] && [ -d "/proc/$pid" ] && {
				printf '%s\n' "$pid"
				return 0
			}
		fi
	done
	pgrep -f '/usr/local/shadowsocks/bin/sslocal' | head -n1
}

# /proc/PID/stat field 14 is utime, 15 stime, 22 starttime; we just print
# RSS/VSZ from /proc/PID/status.
proc_summary() {
	pid="$1"
	[ -z "$pid" ] && {
		echo "no sslocal pid"
		return
	}
	[ -d "/proc/$pid" ] || {
		echo "stale pid $pid"
		return
	}
	rss=$(awk '/^VmRSS:/{print $2}' "/proc/$pid/status" 2>/dev/null)
	vsz=$(awk '/^VmSize:/{print $2}' "/proc/$pid/status" 2>/dev/null)
	threads=$(awk '/^Threads:/{print $2}' "/proc/$pid/status" 2>/dev/null)
	fdcount=$(ls -1 "/proc/$pid/fd" 2>/dev/null | wc -l)
	# Walk /proc/PID/fd → count socket: entries (cheap, no ss needed).
	socks=$(ls -l "/proc/$pid/fd" 2>/dev/null | grep -c 'socket:')
	# Per-process tcp/udp from /proc/PID/net/{tcp,tcp6,udp,udp6}. Subtract
	# the header line.
	count_lines() {
		f="/proc/$pid/net/$1"
		[ -r "$f" ] || {
			echo 0
			return
		}
		n=$(wc -l <"$f" 2>/dev/null || echo 1)
		echo $((n - 1))
	}
	tcp4=$(count_lines tcp)
	tcp6=$(count_lines tcp6)
	udp4=$(count_lines udp)
	udp6=$(count_lines udp6)
	# %CPU from /proc/PID/stat (utime + stime over wall clock since
	# previous sample) — cheap delta, computed by the loop in sample().
	utime=$(awk '{print $14}' "/proc/$pid/stat" 2>/dev/null)
	stime=$(awk '{print $15}' "/proc/$pid/stat" 2>/dev/null)
	printf 'pid=%s rss=%sKB vsz=%sKB threads=%s fd=%s socks=%s tcp=%s/%s udp=%s/%s utime=%s stime=%s\n' \
		"$pid" "$rss" "$vsz" "$threads" "$fdcount" "$socks" "$tcp4" "$tcp6" "$udp4" "$udp6" "$utime" "$stime"
}

global_summary() {
	loadavg=$(awk '{print $1, $2, $3}' /proc/loadavg)
	memav=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
	memfree=$(awk '/^MemFree:/{print $2}' /proc/meminfo)
	swap=$(awk '/^SwapFree:/{print $2}' /proc/meminfo)
	# /proc/net/sockstat: lines like "TCP: inuse 12 orphan 0 tw 4 alloc 14 mem 1"
	sockstat=$(awk 'NR<=4 {gsub(/[ \t]+/," "); printf "%s|", $0}' /proc/net/sockstat 2>/dev/null)
	ct=0
	if [ -r /proc/sys/net/netfilter/nf_conntrack_count ]; then
		ct=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
	elif [ -r /proc/net/nf_conntrack ]; then
		ct=$(wc -l </proc/net/nf_conntrack)
	fi
	ctmax=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo "?")
	printf 'load=%s memavail=%sKB memfree=%sKB swapfree=%sKB conntrack=%s/%s sockstat=%s\n' \
		"$loadavg" "$memav" "$memfree" "$swap" "$ct" "$ctmax" "$sockstat"
}

dns_cache_stats() {
	# /api/dns/cache/stats returns a small JSON. We use curl with very tight
	# timeouts so a hung sslocal can't hold up the watcher.
	curl -fsS --connect-timeout 2 --max-time 4 "$WEB_ADMIN_URL" 2>/dev/null \
		|| echo "{\"error\":\"curl failed or admin unresponsive\"}"
}

# Reachability — every probe times out fast; we want to know "did it
# answer in under N seconds", not get a full result.
probe_lan() {
	if ping -c1 -W2 "$LAN_GATEWAY" >/dev/null 2>&1; then echo ok; else echo fail; fi
}
probe_ssserver_tcp() {
	# nc -z is BusyBox-friendly. -w gives us a hard wall clock.
	if nc -z -w3 "$SS_SERVER" "$SS_PROBE_PORT" >/dev/null 2>&1; then echo ok; else echo fail; fi
}
probe_dns_direct() {
	# nslookup against $DIRECT_DNS, NOT through dnsmasq / sslocal. If this
	# fails the upstream DNS is broken or the route is gone, not a sslocal
	# bug.
	out=$(nslookup "$PROBE_DOMAIN" "$DIRECT_DNS" 2>&1)
	echo "$out" | grep -q 'Address' && echo ok || echo fail
}

# Health gate — returns 0 if healthy, non-zero if unhealthy.
is_unhealthy() {
	pid="$1"
	rss="$2"
	fd="$3"
	ct="$4"
	lan="$5"
	srv="$6"
	dns="$7"
	[ -n "$pid" ] || return 1
	[ "$rss" -gt "$RSS_WARN_KB" ] 2>/dev/null && return 0
	[ "$fd" -gt "$FD_WARN" ] 2>/dev/null && return 0
	[ "$ct" -gt "$CT_WARN" ] 2>/dev/null && return 0
	[ "$lan" = fail ] && return 0
	[ "$srv" = fail ] && return 0
	[ "$dns" = fail ] && return 0
	return 1
}

unhealthy_dump() {
	emit_block "top" top -bn1
	emit_block "ss -s" ss -s
	emit_block "ss -ant top 30" sh -c 'ss -ant 2>/dev/null | head -n 30'
	emit_block "ss -anu top 30" sh -c 'ss -anu 2>/dev/null | head -n 30'
	emit_block "/proc/net/sockstat" cat /proc/net/sockstat
	emit_block "dmesg tail" sh -c 'dmesg -T 2>/dev/null | tail -n 40 || dmesg | tail -n 40'
	emit_block "iptables nat -nvL (top 60)" sh -c 'iptables -t nat -nvL 2>/dev/null | head -n 60'
	emit_block "nft ruleset (head)" sh -c 'nft list ruleset 2>/dev/null | head -n 80'
}

emit "watcher started: SAMPLE_SEC=$SAMPLE_SEC RSS_WARN_KB=$RSS_WARN_KB FD_WARN=$FD_WARN CT_WARN=$CT_WARN"

prev_total_jiffies=""
prev_proc_jiffies=""

while :; do
	rotate_log

	pid=$(sslocal_pid)
	psum=$(proc_summary "$pid")
	gsum=$(global_summary)

	# %CPU = (Δ proc utime+stime) / (Δ total cpu time). Both come from
	# /proc/PID/stat and /proc/stat respectively. Skipped on the very first
	# iteration.
	cur_total=$(awk '/^cpu / {sum=0; for (i=2;i<=NF;i++) sum+=$i; print sum; exit}' /proc/stat)
	cur_proc=""
	[ -n "$pid" ] && [ -d "/proc/$pid" ] && cur_proc=$(awk '{print $14+$15}' "/proc/$pid/stat" 2>/dev/null)
	cpu_pct="-"
	if [ -n "$prev_total_jiffies" ] && [ -n "$prev_proc_jiffies" ] && [ -n "$cur_proc" ] && [ -n "$cur_total" ]; then
		dt=$((cur_total - prev_total_jiffies))
		dp=$((cur_proc - prev_proc_jiffies))
		if [ "$dt" -gt 0 ] && [ "$dp" -ge 0 ]; then
			cpu_pct=$(awk -v dp="$dp" -v dt="$dt" 'BEGIN{printf "%.1f", (dp*100)/dt}')
		fi
	fi
	prev_total_jiffies="$cur_total"
	prev_proc_jiffies="${cur_proc:-$prev_proc_jiffies}"

	# Extract numeric values back out of psum for the gate (cheap parse).
	rss_kb=$(printf '%s\n' "$psum" | awk '{for(i=1;i<=NF;i++) if($i ~ /^rss=/){ sub(/^rss=/,"",$i); sub(/KB$/,"",$i); print $i; exit } }')
	fd_n=$(printf '%s\n' "$psum"  | awk '{for(i=1;i<=NF;i++) if($i ~ /^fd=/){  sub(/^fd=/,"",$i); print $i; exit  } }')
	ct_n=$(printf '%s\n' "$gsum"  | awk '{for(i=1;i<=NF;i++) if($i ~ /^conntrack=/){ sub(/^conntrack=/,"",$i); split($i,a,"/"); print a[1]; exit } }')
	rss_kb=${rss_kb:-0}; fd_n=${fd_n:-0}; ct_n=${ct_n:-0}

	lan_st=$(probe_lan)
	srv_st=$(probe_ssserver_tcp)
	dns_st=$(probe_dns_direct)

	stats_json=$(dns_cache_stats)

	emit "sslocal:  $psum cpu=${cpu_pct}%"
	emit "global:   $gsum"
	emit "probes:   lan=$lan_st ss_server_tcp=$srv_st dns_direct=$dns_st"
	emit "dns_cache: $stats_json"

	if is_unhealthy "$pid" "$rss_kb" "$fd_n" "$ct_n" "$lan_st" "$srv_st" "$dns_st"; then
		emit "***** UNHEALTHY SAMPLE — dumping details *****"
		unhealthy_dump
		emit "***** END OF UNHEALTHY DUMP *****"
	fi

	sleep "$SAMPLE_SEC"
done
