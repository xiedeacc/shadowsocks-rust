#!/usr/bin/env bash
# loadtest_redir_client.sh — drive the OpenWrt sslocal transparent proxy
# from a LAN client (this Ubuntu workstation), NOT from inside the router.
# Same code path as the original loadtest_redir.sh, but split into a
# client side (the curl workers, here) and a router-side health probe
# (over SSH, between ramp steps).
#
# Key safety properties:
#   * Workers ramp 1 -> 2 -> 4 -> 8 -> ... doubling every $RAMP_SECS.
#   * Between every ramp step we SSH the router and verify:
#       - load average < $MAX_LOAD,
#       - default route still present,
#       - `nft list table inet ssrust_dns` succeeds (table exists),
#       - logread tail doesn't show > $MAX_TIMEOUTS_PER_STEP fresh
#         `dns udp ... lookup timed out` lines.
#     If ANY check fails, stop ramping, report the breaking point,
#     and exit non-zero. Workers are killed before exit.
#   * If SSH itself fails to return in $SSH_PROBE_TIMEOUT, we treat that
#     as "router going down" and bail immediately.
#   * Hard cap at $MAX_WORKERS regardless of ramp count.
#
# DNS resolution: this script does NOT change /etc/resolv.conf. It runs
# curl with --dns-servers $ROUTER pointing at the router, so each
# request transits the router's sslocal DNS+redir pipeline exactly the
# way a LAN client would. (Falls back to --resolve via getent if
# libcurl was built without ares — see resolve_via_router().)
#
# Usage:
#   bash test/ubuntu/loadtest_redir_client.sh [--max-workers N]
#                                             [--ramp-secs N]
#                                             [--max-load X.X]
#                                             [--router HOST]
#                                             [--ssh-port N]
set -u

ROUTER="${ROUTER:-192.168.2.1}"
SSH_PORT="${SSH_PORT:-10022}"
SSH_USER="${SSH_USER:-root}"
MAX_WORKERS="${MAX_WORKERS:-16}"
RAMP_SECS="${RAMP_SECS:-30}"
MAX_LOAD="${MAX_LOAD:-2.0}"
MAX_TIMEOUTS_PER_STEP="${MAX_TIMEOUTS_PER_STEP:-20}"
SSH_PROBE_TIMEOUT="${SSH_PROBE_TIMEOUT:-5}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-3}"
MAX_TIME="${MAX_TIME:-8}"
LOG_DIR="${LOG_DIR:-/tmp/openwrt-loadtest}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/client-load.log}"
HEALTH_LOG="${HEALTH_LOG:-$LOG_DIR/router-health.log}"

while [ $# -gt 0 ]; do
	case "$1" in
		--max-workers) MAX_WORKERS="$2"; shift 2 ;;
		--ramp-secs)   RAMP_SECS="$2";   shift 2 ;;
		--max-load)    MAX_LOAD="$2";    shift 2 ;;
		--router)      ROUTER="$2";      shift 2 ;;
		--ssh-port)    SSH_PORT="$2";    shift 2 ;;
		-h|--help) sed -n '2,/^set -u/p' "$0"; exit 0 ;;
		*) echo "unknown arg: $1" >&2; exit 2 ;;
	esac
done

mkdir -p "$LOG_DIR"
: >"$LOG_FILE"
: >"$HEALTH_LOG"

DOMAINS=(
	www.google.com www.youtube.com www.cloudflare.com www.wikipedia.org
	github.com www.qq.com www.baidu.com www.taobao.com www.bilibili.com
	www.aliyun.com httpbin.org example.com
)
N_DOMAINS=${#DOMAINS[@]}

ssh_router() {
	# -o BatchMode=yes so we never hang on a password prompt when the
	# router has stopped accepting our key (= about to go down).
	ssh -o BatchMode=yes -o ConnectTimeout="$SSH_PROBE_TIMEOUT" \
		-o ServerAliveInterval=2 -o ServerAliveCountMax=2 \
		-p "$SSH_PORT" "$SSH_USER@$ROUTER" "$@" 2>&1
}

probe_router() {
	# Single SSH round-trip pulls everything we need so we minimise
	# stress on the very box we're trying to keep alive.
	ssh_router 'echo "===LOAD==="; cat /proc/loadavg;
		echo "===ROUTE==="; ip route show default;
		echo "===NFT==="; nft list table inet ssrust_dns 2>&1 | head -1;
		echo "===TIMEOUTS==="; logread | grep "lookup timed out" | tail -50 | wc -l;
		echo "===END==="'
}

worker() {
	local wid="$1"
	local iter=0
	while :; do
		iter=$((iter + 1))
		local dom="${DOMAINS[$((RANDOM % N_DOMAINS))]}"
		# Strip every proxy env var. The point of the test is to drive
		# the router's transparent-redirect path, not whatever HTTP/SOCKS
		# proxy Cursor / the shell happens to have exported.
		local out
		out=$(env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
			-u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY \
			curl -sS -k -o /dev/null \
			--connect-timeout "$CONNECT_TIMEOUT" \
			--max-time "$MAX_TIME" \
			--dns-servers "$ROUTER" \
			-w '%{http_code} %{remote_ip} %{time_total}' \
			"https://$dom/" 2>/dev/null || echo "ERR - -")
		printf '%(%H:%M:%S)T w=%d iter=%d dom=%s out=%s\n' \
			-1 "$wid" "$iter" "$dom" "$out" >>"$LOG_FILE"
	done
}

PIDS=()
cleanup() {
	echo "[$(date +%H:%M:%S)] cleanup: killing ${#PIDS[@]} workers" >&2
	for p in "${PIDS[@]}"; do
		kill "$p" 2>/dev/null || true
	done
	wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

spawn_n() {
	# Spawn workers until total = $1. Idempotent.
	local target="$1"
	while [ "${#PIDS[@]}" -lt "$target" ]; do
		worker "${#PIDS[@]}" &
		PIDS+=($!)
	done
}

parse_field() {
	# Extract the body of a ===KEY=== block from probe output.
	awk -v k="$1" '
		$0 == "==="k"===" { capture=1; next }
		/^===/             { capture=0 }
		capture            { print }
	'
}

echo "[$(date +%H:%M:%S)] loadtest start: router=$ROUTER max_workers=$MAX_WORKERS ramp_secs=$RAMP_SECS" >&2

# Baseline check before spawning anything. If the router isn't healthy
# now, abort — don't make it worse.
echo "[$(date +%H:%M:%S)] baseline probe" >&2
baseline=$(probe_router) || {
	echo "[$(date +%H:%M:%S)] BAIL: cannot ssh router before any load" >&2
	exit 2
}
printf 'BASELINE\n%s\n\n' "$baseline" >>"$HEALTH_LOG"
echo "$baseline" | parse_field LOAD

n=1
while [ "$n" -le "$MAX_WORKERS" ]; do
	echo "[$(date +%H:%M:%S)] ramp to $n workers" >&2
	spawn_n "$n"
	# Snapshot timeout count BEFORE this step so we only count NEW
	# timeouts that appeared during the step's duration.
	pre=$(probe_router) || { echo "BAIL: ssh failed pre-step" >&2; exit 1; }
	pre_timeouts=$(echo "$pre" | parse_field TIMEOUTS | head -1)
	pre_timeouts=${pre_timeouts:-0}
	# Soak at this worker count for $RAMP_SECS.
	sleep "$RAMP_SECS"
	# Now check health.
	post=$(probe_router) || { echo "BAIL: ssh failed during step $n" >&2; exit 1; }
	printf 'STEP n=%d\n%s\n\n' "$n" "$post" >>"$HEALTH_LOG"

	load1=$(echo "$post" | parse_field LOAD | awk '{print $1}')
	route=$(echo "$post"  | parse_field ROUTE | tr -d '\n')
	nft=$(echo "$post"    | parse_field NFT | tr -d '\n')
	post_timeouts=$(echo "$post" | parse_field TIMEOUTS | head -1)
	post_timeouts=${post_timeouts:-0}
	new_timeouts=$((post_timeouts - pre_timeouts))

	echo "[$(date +%H:%M:%S)] step n=$n: load1=$load1 route_ok=$([ -n "$route" ] && echo yes || echo NO) nft='$nft' new_timeouts=$new_timeouts" >&2

	# Hard breaks: any of these = router degrading, stop ramping.
	bad=""
	awk -v l="$load1" -v m="$MAX_LOAD" 'BEGIN{exit !(l+0 > m+0)}' \
		&& bad="load $load1 > $MAX_LOAD"
	[ -z "$route" ] && bad="default route gone"
	echo "$nft" | grep -qv 'No such' && nft_ok=1 || nft_ok=0
	[ "$nft_ok" = 0 ] && bad="ssrust_dns table missing"
	[ "$new_timeouts" -gt "$MAX_TIMEOUTS_PER_STEP" ] \
		&& bad="$new_timeouts fresh DNS timeouts (>$MAX_TIMEOUTS_PER_STEP)"

	if [ -n "$bad" ]; then
		echo "[$(date +%H:%M:%S)] BREAKING POINT at $n workers: $bad" >&2
		echo "[$(date +%H:%M:%S)] router health log: $HEALTH_LOG" >&2
		echo "[$(date +%H:%M:%S)] client log:        $LOG_FILE" >&2
		exit 1
	fi

	n=$((n * 2))
done

echo "[$(date +%H:%M:%S)] reached MAX_WORKERS=$MAX_WORKERS without degradation" >&2
echo "[$(date +%H:%M:%S)] router health log: $HEALTH_LOG" >&2
echo "[$(date +%H:%M:%S)] client log:        $LOG_FILE" >&2
exit 0
