#!/bin/sh
# sslocal-probe — active liveness probe + forensic dumper for shadowsocks-rust on Ubuntu.
#
# Port of deploy/openwrt/conf/sslocal-probe.sh. The OpenWrt and Ubuntu
# instances are intentionally near-identical so a hang on either side
# produces forensic dumps with the same layout (so they can be diffed).
#
# Detection logic
# ---------------
# Every PROBE_INTERVAL_SEC we run ONE `curl https://www.google.com/...`
# with --max-time PROBE_TIMEOUT_SEC. Because the deployed config sets
# `route_rules.dns_intercept_mode = "both"`, sslocal:
#   1) intercepts DNS requests on UDP/TCP 53 via nft (table inet
#      ssrust_dns, prerouting chain) and serves them from port 1053,
#   2) pushes the resolved IPs of "proxy" domains into the nft `bypass4`
#      set,
#   3) the same nft table contains an OUTPUT redirect rule that sends
#      TCP destined for @bypass4 to the redir listener on port 12345.
# So a plain `curl https://www.google.com/...` from this host is
# exactly the LAN-client code path we want to test — no `curl -x`
# tricks, no separate uid/cgroup, no need for /etc/resolv.conf rewriting.
#
# 5 consecutive failures => DOWN edge. On the DOWN edge we capture:
#   * SIGUSR1 to sslocal (triggers the in-process diagnostic dump
#     installed in crates/shadowsocks-service/src/local/mod.rs)
#   * /proc/PID/stack for every thread, twice with a 1s gap
#   * top -bn1 -H -p PID
#   * ss -anp, /proc/net/sockstat, conntrack counts
#   * dmesg -T tail
#   * full `nft list ruleset`
#   * if perf is installed, 5s of perf record at 99Hz
# These land in $DUMP_DIR with a common timestamp stem.

PROBE_INTERVAL_SEC="${PROBE_INTERVAL_SEC:-1}"
PROBE_TIMEOUT_SEC="${PROBE_TIMEOUT_SEC:-2}"
DOWN_THRESHOLD="${DOWN_THRESHOLD:-5}"
UP_THRESHOLD="${UP_THRESHOLD:-3}"
PROBE_TARGETS="${PROBE_TARGETS:-https://www.google.com/generate_204 http://www.gstatic.com/generate_204}"
LOG_DIR="${LOG_DIR:-/usr/local/shadowsocks/logs}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/sslocal-probe.log}"
DUMP_DIR="${DUMP_DIR:-$LOG_DIR/dumps}"
MAX_LOG_BYTES="${MAX_LOG_BYTES:-4194304}"
ROTATE_KEEP="${ROTATE_KEEP:-3}"
PERF_RECORD_SEC="${PERF_RECORD_SEC:-5}"
DUMP_COOLDOWN_SEC="${DUMP_COOLDOWN_SEC:-120}"

[ -f /etc/sslocal-probe.conf ] && . /etc/sslocal-probe.conf

mkdir -p "$LOG_DIR" "$DUMP_DIR"

ts() { date '+%Y-%m-%dT%H:%M:%S'; }
ts_compact() { date '+%Y%m%d-%H%M%S'; }
emit() { printf '[%s] %s\n' "$(ts)" "$*" >>"$LOG_FILE"; }

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

sslocal_pid() {
	pid=$(pgrep -f '^/usr/local/shadowsocks/bin/sslocal ' 2>/dev/null | head -n1)
	[ -n "$pid" ] && { printf '%s\n' "$pid"; return 0; }
	pgrep -f '/usr/local/shadowsocks/bin/sslocal' 2>/dev/null | head -n1
}

# Single probe attempt. Returns 0 on success, non-zero on timeout/error.
# We unset http(s)_proxy explicitly so the probe never accidentally
# detours through some shell-inherited proxy — we want the transparent
# redir path under test, nothing else.
probe_once() {
	for url in $PROBE_TARGETS; do
		ct=$(awk -v t="$PROBE_TIMEOUT_SEC" 'BEGIN{ printf "%.2f", t/2 }')
		if env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY \
			curl -fsS -k -o /dev/null \
			--connect-timeout "$ct" \
			--max-time "$PROBE_TIMEOUT_SEC" \
			"$url" >/dev/null 2>&1; then
			return 0
		fi
	done
	return 1
}

collect_stacks() {
	pid="$1"
	stem="$2"
	pass="$3"
	out="$DUMP_DIR/${stem}.stacks.${pass}.txt"
	[ -d "/proc/$pid/task" ] || { echo "no /proc/$pid/task" >"$out"; return; }
	{
		echo "captured at $(ts)"
		echo "pid=$pid"
		for t in /proc/"$pid"/task/*; do
			[ -d "$t" ] || continue
			tid=$(basename "$t")
			state=$(awk '{print $3}' "$t/stat" 2>/dev/null)
			wchan=$(cat "$t/wchan" 2>/dev/null)
			comm=$(cat "$t/comm" 2>/dev/null)
			printf '\n===== tid %s state=%s wchan=%s comm=%s =====\n' \
				"$tid" "$state" "$wchan" "$comm"
			if [ -r "$t/stack" ]; then
				cat "$t/stack" 2>/dev/null
			else
				echo "(stack unavailable; need CAP_SYS_ADMIN or kptr_restrict relaxed)"
			fi
		done
	} >"$out" 2>&1
}

snapshot_forensics() {
	pid="$1"
	stem="$2"

	emit "DOWN: capturing forensic dump (stem=$stem pid=${pid:-none})"

	# 1. SIGUSR1 → in-process Rust dump task (see local/mod.rs Task #3).
	if [ -n "$pid" ]; then
		kill -USR1 "$pid" 2>/dev/null && emit "SIGUSR1 sent to $pid"
	fi

	# 2. /proc snapshots.
	[ -n "$pid" ] && cp -f "/proc/$pid/status"        "$DUMP_DIR/${stem}.proc-status.txt"        2>/dev/null
	[ -n "$pid" ] && cp -f "/proc/$pid/limits"        "$DUMP_DIR/${stem}.proc-limits.txt"        2>/dev/null
	[ -n "$pid" ] && cp -f "/proc/$pid/net/sockstat"  "$DUMP_DIR/${stem}.proc-sockstat.txt"      2>/dev/null
	[ -n "$pid" ] && ls -l "/proc/$pid/fd" 2>/dev/null | head -n 200 >"$DUMP_DIR/${stem}.proc-fd-head.txt"

	# 3. Two stack snapshots, 1s apart, so we can tell stuck from slow.
	[ -n "$pid" ] && collect_stacks "$pid" "$stem" "pass1"
	sleep 1
	[ -n "$pid" ] && collect_stacks "$pid" "$stem" "pass2"

	# 4. Per-thread CPU (procps top supports -H -p PID).
	{
		echo "===== top -bn1 -H -p $pid ====="
		top -bn1 -H -p "$pid" 2>/dev/null | head -n 100
	} >"$DUMP_DIR/${stem}.top.txt"

	# 5. Sockets.
	{
		echo "===== ss -s ====="
		ss -s 2>&1
		echo
		echo "===== ss -tan top 100 ====="
		ss -tan 2>&1 | head -n 100
		echo
		echo "===== ss -uan top 100 ====="
		ss -uan 2>&1 | head -n 100
		echo
		echo "===== ss -anp top 200 ====="
		ss -anp 2>&1 | head -n 200
		echo
		echo "===== /proc/net/sockstat ====="
		cat /proc/net/sockstat 2>/dev/null
		echo
		echo "===== conntrack count ====="
		cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null
		cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null
	} >"$DUMP_DIR/${stem}.sockets.txt"

	# 6. dmesg tail.
	dmesg -T 2>/dev/null | tail -n 100 >"$DUMP_DIR/${stem}.dmesg.txt"

	# 7. nft full ruleset (Ubuntu uses nftables natively).
	{
		echo "===== nft list ruleset ====="
		nft list ruleset 2>&1
	} >"$DUMP_DIR/${stem}.firewall.txt"

	# 8. perf if available.
	if command -v perf >/dev/null 2>&1 && [ -n "$pid" ]; then
		(
			perf record -F 99 -g -p "$pid" -o "$DUMP_DIR/${stem}.perf.data" \
				-- sleep "$PERF_RECORD_SEC" >/dev/null 2>&1 \
				&& perf script -i "$DUMP_DIR/${stem}.perf.data" \
				   >"$DUMP_DIR/${stem}.perf.txt" 2>&1 \
				|| echo "perf failed" >>"$DUMP_DIR/${stem}.perf.txt"
		) &
	else
		emit "perf not available; relying on /proc/PID/task/*/stack"
	fi

	# 9. journald tail for sslocal — gives us application-level context
	#    alongside the kernel-side stack snapshots.
	journalctl -u shadowsocks-client.service --no-pager -n 200 2>/dev/null \
		>"$DUMP_DIR/${stem}.journal.txt"

	emit "DOWN: forensic dump complete (see $DUMP_DIR/${stem}.*)"
}

emit "probe started: interval=${PROBE_INTERVAL_SEC}s timeout=${PROBE_TIMEOUT_SEC}s down=${DOWN_THRESHOLD} up=${UP_THRESHOLD} cooldown=${DUMP_COOLDOWN_SEC}s targets=$PROBE_TARGETS"

consec_fail=0
consec_ok=0
state="ok"
last_dump_epoch=0

while :; do
	rotate_log

	if probe_once; then
		consec_ok=$((consec_ok + 1))
		consec_fail=0
		if [ "$state" = "down" ] && [ "$consec_ok" -ge "$UP_THRESHOLD" ]; then
			state="ok"
			emit "RECOVERED after $consec_ok consecutive successes"
		fi
	else
		consec_fail=$((consec_fail + 1))
		consec_ok=0
		emit "probe FAIL ($consec_fail in a row)"
		if [ "$state" = "ok" ] && [ "$consec_fail" -ge "$DOWN_THRESHOLD" ]; then
			now_epoch=$(date +%s 2>/dev/null || echo 0)
			since=$((now_epoch - last_dump_epoch))
			if [ "$since" -ge "$DUMP_COOLDOWN_SEC" ]; then
				state="down"
				stem="$(ts_compact)-down"
				pid=$(sslocal_pid)
				snapshot_forensics "$pid" "$stem"
				last_dump_epoch="$now_epoch"
			else
				emit "DOWN edge but in cooldown (${since}s of ${DUMP_COOLDOWN_SEC}s); skipping dump"
				state="down"
			fi
		fi
	fi

	sleep "$PROBE_INTERVAL_SEC"
done
