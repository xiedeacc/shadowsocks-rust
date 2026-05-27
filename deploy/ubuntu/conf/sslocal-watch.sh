#!/bin/sh
# sslocal-watch — long-running Ubuntu diagnostic sampler for shadowsocks-rust.
#
# Port of deploy/openwrt/conf/sslocal-watch.sh adapted for an Ubuntu /
# systemd host.  Same purpose: passively sample cheap counters every
# SAMPLE_SEC seconds so that, after a hang, we have a forensic trail
# even when the symptoms (SSH lag, DNS timeouts) make the box hard to
# poke at live.
#
# Differences vs. the OpenWrt version
# -----------------------------------
# * pid discovery via `pgrep -fx '/usr/local/shadowsocks/bin/sslocal …'`
#   instead of /var/run/shadowsocks-rust.pid (procd-specific).
# * uses iproute2 `ss` everywhere (Ubuntu ships full ss; busybox-only
#   fallbacks are dropped).
# * dmesg path is `dmesg -T`; OpenWrt's logread isn't present.
# * conntrack file path may be missing if nf_conntrack hasn't loaded
#   yet (until any nft conntrack-using rule fires), handled gracefully.

SAMPLE_SEC="${SAMPLE_SEC:-30}"
LOG_DIR="${LOG_DIR:-/usr/local/shadowsocks/logs}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/sslocal-watch.log}"
MAX_LOG_BYTES="${MAX_LOG_BYTES:-4194304}"
ROTATE_KEEP="${ROTATE_KEEP:-3}"
RSS_WARN_KB="${RSS_WARN_KB:-262144}"        # x86_64 RSS runs higher
FD_WARN="${FD_WARN:-4096}"
CT_WARN="${CT_WARN:-100000}"
WEB_ADMIN_URL="${WEB_ADMIN_URL:-http://127.0.0.1:9090/api/dns/cache/stats}"
SS_SERVER="${SS_SERVER:-54.179.191.126}"
SS_PROBE_PORT="${SS_PROBE_PORT:-443}"
LAN_GATEWAY="${LAN_GATEWAY:-}"
DIRECT_DNS="${DIRECT_DNS:-223.5.5.5}"
PROBE_DOMAIN="${PROBE_DOMAIN:-www.aliyun.com}"

[ -f /etc/sslocal-watch.conf ] && . /etc/sslocal-watch.conf

# Auto-detect the LAN gateway if not pinned via the conf file. We pick
# the first default route — anything more elaborate (route metrics,
# wlan vs ethernet preference) is the operator's call via the env var.
if [ -z "$LAN_GATEWAY" ]; then
	LAN_GATEWAY=$(ip route show default 2>/dev/null | awk '/^default/ {print $3; exit}')
fi

mkdir -p "$LOG_DIR"

ts() { date '+%Y-%m-%dT%H:%M:%S'; }
emit() { printf '[%s] %s\n' "$(ts)" "$*" >>"$LOG_FILE"; }
emit_block() {
	header="$1"
	shift
	emit "----- $header -----"
	{ "$@"; } 2>&1 | sed 's/^/    /' >>"$LOG_FILE"
}

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

# Resolve the sslocal pid. The systemd unit creates an exact ExecStart
# line we can grep for; fall back to a lax pgrep if the user passed
# different args.
sslocal_pid() {
	pid=$(pgrep -f '^/usr/local/shadowsocks/bin/sslocal ' 2>/dev/null | head -n1)
	[ -n "$pid" ] && { printf '%s\n' "$pid"; return 0; }
	pgrep -f '/usr/local/shadowsocks/bin/sslocal' 2>/dev/null | head -n1
}

proc_summary() {
	pid="$1"
	[ -z "$pid" ] && { echo "no sslocal pid"; return; }
	[ -d "/proc/$pid" ] || { echo "stale pid $pid"; return; }
	rss=$(awk '/^VmRSS:/{print $2}' "/proc/$pid/status" 2>/dev/null)
	vsz=$(awk '/^VmSize:/{print $2}' "/proc/$pid/status" 2>/dev/null)
	threads=$(awk '/^Threads:/{print $2}' "/proc/$pid/status" 2>/dev/null)
	fdcount=$(ls -1 "/proc/$pid/fd" 2>/dev/null | wc -l)
	socks=$(ls -l "/proc/$pid/fd" 2>/dev/null | grep -c 'socket:')
	count_lines() {
		f="/proc/$pid/net/$1"
		[ -r "$f" ] || { echo 0; return; }
		n=$(wc -l <"$f" 2>/dev/null || echo 1)
		echo $((n - 1))
	}
	tcp4=$(count_lines tcp)
	tcp6=$(count_lines tcp6)
	udp4=$(count_lines udp)
	udp6=$(count_lines udp6)
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
	sockstat=$(awk 'NR<=5 {gsub(/[ \t]+/," "); printf "%s|", $0}' /proc/net/sockstat 2>/dev/null)
	ct="?"
	if [ -r /proc/sys/net/netfilter/nf_conntrack_count ]; then
		ct=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
	fi
	ctmax=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo "?")
	printf 'load=%s memavail=%sKB memfree=%sKB swapfree=%sKB conntrack=%s/%s sockstat=%s\n' \
		"$loadavg" "$memav" "$memfree" "$swap" "$ct" "$ctmax" "$sockstat"
}

dns_cache_stats() {
	curl -fsS --connect-timeout 2 --max-time 4 "$WEB_ADMIN_URL" 2>/dev/null \
		|| echo "{\"error\":\"curl failed or admin unresponsive\"}"
}

probe_lan() {
	[ -z "$LAN_GATEWAY" ] && { echo skip; return; }
	if ping -c1 -W2 "$LAN_GATEWAY" >/dev/null 2>&1; then echo ok; else echo fail; fi
}
probe_ssserver_tcp() {
	# Newer netcats use -G/-w differently; use bash's /dev/tcp to avoid
	# the portability mess. timeout(1) ships in coreutils on Ubuntu.
	if timeout 3 bash -c "exec 3<>/dev/tcp/${SS_SERVER}/${SS_PROBE_PORT}; exec 3<&-; exec 3>&-" >/dev/null 2>&1; then
		echo ok
	else
		echo fail
	fi
}
probe_dns_direct() {
	# `nslookup` on Ubuntu is bind9's; `+timeout`-style is dig. Use both
	# defensively — nslookup is present in most installs, dig may not be.
	if command -v dig >/dev/null 2>&1; then
		dig +time=2 +tries=1 "@$DIRECT_DNS" "$PROBE_DOMAIN" +short 2>/dev/null | grep -qE '^[0-9]+\.' && echo ok || echo fail
	elif command -v nslookup >/dev/null 2>&1; then
		nslookup -timeout=2 -retry=0 "$PROBE_DOMAIN" "$DIRECT_DNS" 2>&1 | grep -q 'Address' && echo ok || echo fail
	else
		echo skip
	fi
}

is_unhealthy() {
	pid="$1" rss="$2" fd="$3" ct="$4" lan="$5" srv="$6" dns="$7"
	[ -n "$pid" ] || return 0
	[ "${rss:-0}" -gt "$RSS_WARN_KB" ] 2>/dev/null && return 0
	[ "${fd:-0}" -gt "$FD_WARN" ] 2>/dev/null && return 0
	case "$ct" in ''|*[!0-9]*) ;; *) [ "$ct" -gt "$CT_WARN" ] && return 0 ;; esac
	[ "$lan" = fail ] && return 0
	[ "$srv" = fail ] && return 0
	[ "$dns" = fail ] && return 0
	return 1
}

unhealthy_dump() {
	emit_block "top" top -bn1
	emit_block "ss -s" ss -s
	emit_block "ss -ant top 50" sh -c 'ss -ant 2>/dev/null | head -n 50'
	emit_block "ss -anu top 50" sh -c 'ss -anu 2>/dev/null | head -n 50'
	emit_block "/proc/net/sockstat" cat /proc/net/sockstat
	emit_block "dmesg tail" sh -c 'dmesg -T 2>/dev/null | tail -n 60'
	emit_block "nft ruleset (head)" sh -c 'nft list ruleset 2>/dev/null | head -n 200'
}

emit "watcher started: SAMPLE_SEC=$SAMPLE_SEC RSS_WARN_KB=$RSS_WARN_KB FD_WARN=$FD_WARN CT_WARN=$CT_WARN LAN_GATEWAY=$LAN_GATEWAY"

prev_total_jiffies=""
prev_proc_jiffies=""

while :; do
	rotate_log

	pid=$(sslocal_pid)
	psum=$(proc_summary "$pid")
	gsum=$(global_summary)

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
