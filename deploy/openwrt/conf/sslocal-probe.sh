#!/bin/sh
# sslocal-probe — active liveness probe + forensic dumper for shadowsocks-rust on OpenWrt.
#
# Companion to sslocal-watch.sh. While sslocal-watch is a *passive* sampler
# (RSS / fd / conntrack every 30s), this one is an *active* black-box probe:
# every PROBE_INTERVAL_SEC seconds it runs a single curl through the
# transparent-redir path with a short PROBE_TIMEOUT_SEC timeout. The point is
# to catch the precise moment client-visible traffic dies, NOT to load-test
# the proxy.
#
# What "going through transparent proxy" means here
# -------------------------------------------------
# We run from the OpenWrt box itself. The init script's iptables/nftables
# redir rules redirect `OUTPUT` TCP to localhost:12345, which is sslocal's
# redir listener. So a plain `curl http://www.google.com/` from the router
# is the *exact same* code path a LAN client takes. We deliberately do NOT
# use `curl -x http://...:1081` (HTTP proxy) — that would bypass the redir
# code we're trying to test.
#
# Detection logic
# ---------------
# * 5 consecutive timeouts/errors = "DOWN". On the DOWN edge we:
#     1. SIGUSR1 the sslocal pid (triggers in-process Rust dump task).
#     2. Snapshot /proc/PID/stack and every thread's task/*/stack + wchan
#        (twice with a 1s gap, so we can compare and tell "stuck on
#        the same syscall" from "running, just slow").
#     3. Snapshot top -bn1 -H -p PID (per-thread CPU).
#     4. Snapshot ss -anp focused on sslocal sockets.
#     5. If `perf` is available, record 5s @ 99Hz and dump the script.
#     6. Tail dmesg for kernel-side OOM / conntrack warnings.
# * 3 consecutive successes after a DOWN = "RECOVERED". Normal probing
#   continues.
#
# Output
# ------
# All output goes to a separate log under $LOG_DIR. Each forensic
# capture is its own timestamped file, so post-mortem you can `ls -lt`
# and walk through the events in time order.
#
# Tunables (env or /etc/sslocal-probe.conf)
PROBE_INTERVAL_SEC="${PROBE_INTERVAL_SEC:-1}"
PROBE_TIMEOUT_SEC="${PROBE_TIMEOUT_SEC:-2}"
DOWN_THRESHOLD="${DOWN_THRESHOLD:-5}"
UP_THRESHOLD="${UP_THRESHOLD:-3}"
PROBE_TARGETS="${PROBE_TARGETS:-https://www.google.com/generate_204 http://www.gstatic.com/generate_204}"
LOG_DIR="${LOG_DIR:-/usr/local/shadowsocks/logs}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/sslocal-probe.log}"
DUMP_DIR="${DUMP_DIR:-$LOG_DIR/dumps}"
MAX_LOG_BYTES="${MAX_LOG_BYTES:-2097152}"
ROTATE_KEEP="${ROTATE_KEEP:-3}"
PERF_RECORD_SEC="${PERF_RECORD_SEC:-5}"
# Cooldown after a forensic dump — without this, a wedged sslocal would
# trigger a new dump every PROBE_INTERVAL_SEC, filling /tmp.
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

# Single probe attempt. Returns 0 on success, non-zero on timeout/error.
# We prefer https with --max-time so a hung sslocal blocks for at most
# PROBE_TIMEOUT_SEC. -k skips cert validation (we only care that
# something replied; a captive-portal/MITM page is "the network is
# reachable but proxy is broken" — a different signal than total death,
# and we don't want false alarms).
probe_once() {
	for url in $PROBE_TARGETS; do
		# --connect-timeout has its own short ceiling so a black-holed
		# SYN doesn't soak the entire probe budget.
		ct=$(awk -v t="$PROBE_TIMEOUT_SEC" 'BEGIN{ printf "%.2f", t/2 }')
		if curl -fsS -k -o /dev/null \
			--connect-timeout "$ct" \
			--max-time "$PROBE_TIMEOUT_SEC" \
			"$url" >/dev/null 2>&1; then
			return 0
		fi
	done
	return 1
}

# Take a stack snapshot of every thread of a pid. Cheap on Linux
# (kernel-side stacks via /proc), and crucially WORKS even if the
# user-space process is wedged — these stacks come from the kernel's
# view of where the syscall is parked.
# Layout in the dump dir:
#   <stem>.stacks.<pass>.txt with the format
#     ===== tid <tid> ===== state=<S/D/R/...> wchan=<sym>
#     <kernel stack frames>
collect_stacks() {
	pid="$1"
	stem="$2"
	pass="$3"
	out="$DUMP_DIR/${stem}.stacks.${pass}.txt"
	[ -d "/proc/$pid/task" ] || {
		echo "no /proc/$pid/task" >"$out"
		return
	}
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
			# /proc/PID/task/TID/stack only exists when CONFIG_STACKTRACE
			# is enabled in the kernel — true for stock OpenWrt. Falls
			# back gracefully when not.
			if [ -r "$t/stack" ]; then
				cat "$t/stack" 2>/dev/null
			else
				echo "(stack unavailable; CONFIG_STACKTRACE missing?)"
			fi
		done
	} >"$out" 2>&1
}

# Snapshot of all the things we want at the moment of a DOWN edge.
# "stem" is the timestamp + tag used in filenames.
snapshot_forensics() {
	pid="$1"
	stem="$2"

	emit "DOWN: capturing forensic dump (stem=$stem pid=${pid:-none})"

	# 1. SIGUSR1 the process so the in-process Rust dump task emits
	#    its routing-state snapshot into the *sslocal* log. That log
	#    is logread / procd, NOT this script's log; we cross-reference
	#    by timestamp.
	if [ -n "$pid" ]; then
		kill -USR1 "$pid" 2>/dev/null && emit "SIGUSR1 sent to $pid"
	fi

	# 2. /proc snapshots (status + fds) — quick, useful even when
	#    everything else is hung.
	cp -f "/proc/$pid/status"   "$DUMP_DIR/${stem}.proc-status.txt"  2>/dev/null
	cp -f "/proc/$pid/limits"   "$DUMP_DIR/${stem}.proc-limits.txt"  2>/dev/null
	cp -f "/proc/$pid/net/sockstat" "$DUMP_DIR/${stem}.proc-sockstat.txt" 2>/dev/null
	ls -l "/proc/$pid/fd" 2>/dev/null | head -n 200 \
		>"$DUMP_DIR/${stem}.proc-fd-head.txt"

	# 3. First stack snapshot. We take TWO with a 1s gap so we can
	#    diff them — if every thread is on the SAME wchan/stack, it's
	#    a deadlock; if frames move, it's just slow.
	[ -n "$pid" ] && collect_stacks "$pid" "$stem" "pass1"
	sleep 1
	[ -n "$pid" ] && collect_stacks "$pid" "$stem" "pass2"

	# 4. Per-thread CPU snapshot — top -H. On busybox top this is the
	#    -H flag; on procps top it's `top -H -bn1 -p PID`. Try both.
	{
		echo "===== top -H (busybox) ====="
		top -H -bn1 2>/dev/null | head -n 80
		echo
		echo "===== top -bn1 -H (procps) ====="
		# busybox top doesn't support -p; this falls through silently.
		top -bn1 -H -p "$pid" 2>/dev/null | head -n 80
	} >"$DUMP_DIR/${stem}.top.txt"

	# 5. Socket-level snapshot — globally, then narrowed to sslocal
	#    via the pid. ss -K is "kill sockets" — never use it here.
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
		echo "===== ss -anp top 100 (process attribution) ====="
		ss -anp 2>&1 | head -n 100
		echo
		echo "===== /proc/net/sockstat ====="
		cat /proc/net/sockstat 2>/dev/null
		echo
		echo "===== conntrack count ====="
		cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null
		cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null
	} >"$DUMP_DIR/${stem}.sockets.txt"

	# 6. dmesg tail for kernel-side OOM / conntrack warnings.
	{
		dmesg -T 2>/dev/null | tail -n 80 || dmesg | tail -n 80
	} >"$DUMP_DIR/${stem}.dmesg.txt"

	# 7. nft / iptables view — useful when redir is broken.
	{
		echo "===== nft list ruleset (head 200) ====="
		nft list ruleset 2>&1 | head -n 200
		echo
		echo "===== iptables -t nat -nvL (head 200) ====="
		iptables -t nat -nvL 2>&1 | head -n 200
	} >"$DUMP_DIR/${stem}.firewall.txt"

	# 8. perf, IFF available. Most stock OpenWrt builds don't ship it,
	#    so we degrade gracefully.
	if command -v perf >/dev/null 2>&1 && [ -n "$pid" ]; then
		(
			perf record -F 99 -g -p "$pid" -o "$DUMP_DIR/${stem}.perf.data" \
				-- sleep "$PERF_RECORD_SEC" >/dev/null 2>&1 \
				&& perf script -i "$DUMP_DIR/${stem}.perf.data" \
				   >"$DUMP_DIR/${stem}.perf.txt" 2>&1 \
				|| echo "perf failed" >>"$DUMP_DIR/${stem}.perf.txt"
		) &
		# Don't wait — perf runs for PERF_RECORD_SEC, no point blocking
		# the probe loop on it. The next probe attempt will resume.
	else
		emit "perf not available; relying on /proc/PID/task/*/stack"
	fi

	# 9. Pointers to the relevant bits of the sslocal log itself.
	#    procd's log goes to logread; a bare `logread | tail` is
	#    cheap and grabs everything since boot from in-memory ring.
	logread 2>/dev/null | tail -n 200 >"$DUMP_DIR/${stem}.logread-tail.txt"

	emit "DOWN: forensic dump complete (see $DUMP_DIR/${stem}.*)"
}

emit "probe started: interval=${PROBE_INTERVAL_SEC}s timeout=${PROBE_TIMEOUT_SEC}s down=${DOWN_THRESHOLD} up=${UP_THRESHOLD} cooldown=${DUMP_COOLDOWN_SEC}s"

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
			# Cooldown: if we already grabbed a dump recently, just
			# log the event but don't burn another full forensic
			# capture. The first dump after a DOWN edge is the
			# valuable one anyway.
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
