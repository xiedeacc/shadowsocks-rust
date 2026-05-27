#!/bin/sh
# loadtest_redir.sh (OpenWrt/BusyBox ash port) — sustained load against the
# local sslocal transparent proxy (redir + DNS intercept). Drives the same
# code path that hangs in production: plain HTTPS that gets redirected to
# 127.0.0.1:12345 by the nft rules sslocal installs.
#
# Two modes:
#   default   pick from a fixed list of common CN+intl domains; exercises
#             the steady-state DNS cache-hit path + connection churn.
#   --unique  every request uses a fresh random hostname under
#             <rand>.nip.io / sslip.io so every iteration forces a real
#             DNS lookup -> maximum pressure on add_dns_results /
#             prune_dns_cache / nft add element.
#
# Stop conditions:
#   * --duration N        wall-clock seconds (default 3600)
#   * sslocal-probe.log shows a `DOWN: capturing forensic dump` line
#     newer than test start -> exit non-zero with the dump stem.
#
# BusyBox-ash notes:
#   * no arrays, no `(( ))`, no `<<<`, no `printf '%(...)T'`, no `$RANDOM`
#     on stock BusyBox. We use $$/date for entropy and `awk` / `date +%s`
#     for math/time formatting.
set -u

WORKERS="${WORKERS:-32}"
DURATION="${DURATION:-3600}"
MODE="fixed"
LOG_DIR="${LOG_DIR:-/usr/local/shadowsocks/logs}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/load-test.log}"
PROBE_LOG="${PROBE_LOG:-$LOG_DIR/sslocal-probe.log}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-2}"
MAX_TIME="${MAX_TIME:-5}"
SLEEP_MS="${SLEEP_MS:-0}"

while [ $# -gt 0 ]; do
	case "$1" in
		--workers)   WORKERS="$2"; shift 2 ;;
		--duration)  DURATION="$2"; shift 2 ;;
		--unique)    MODE="unique"; LOG_FILE="$LOG_DIR/load-test-unique.log"; shift ;;
		--log)       LOG_FILE="$2"; shift 2 ;;
		--sleep-ms)  SLEEP_MS="$2"; shift 2 ;;
		-h|--help)
			sed -n '2,/^set -u/p' "$0"; exit 0 ;;
		*) echo "unknown arg: $1" >&2; exit 2 ;;
	esac
done

mkdir -p "$LOG_DIR"
: >"$LOG_FILE"

# Fixed-mode domain pool. Mix of:
#   * intl proxied through ssserver (google/youtube/wiki/cloudflare/fb/x)
#   * CN direct (qq/iqiyi/aliyun/baidu/jd/taobao/weibo)
#   * mixed CDNs (akamai/fastly/cloudfront)
# Space-separated (no bash arrays in ash). 32 entries.
DOMAINS_FIXED="www.google.com www.youtube.com youtu.be yt3.ggpht.com static.xx.fbcdn.net \
twitter.com x.com www.cloudflare.com www.wikipedia.org commons.wikimedia.org \
upload.wikimedia.org www.reddit.com github.com api.github.com \
www.qq.com www.iqiyi.com www.aliyun.com www.baidu.com www.jd.com \
www.taobao.com weibo.com www.bilibili.com www.zhihu.com www.douyin.com \
www.akamai.com www.fastly.com d3js.org cdnjs.cloudflare.com \
httpbin.org example.com www.example.org www.example.net"
DOMAINS_COUNT=32

# Returns a random hostname for --unique mode. Hostname encodes random
# octets so nip.io / sslip.io return a deterministic A record without
# hitting any real authority -- minimum upstream cost, maximum pressure
# on the local DNS write path.
rand_unique_host() {
	# awk-based RNG seeded with PID + nanosecond clock; way better entropy
	# than ash's missing $RANDOM. Outputs four 1..254 octets + service.
	awk -v seed="$$.$(date +%N 2>/dev/null || echo 0)" 'BEGIN{
		srand(seed + systime());
		o1=int(rand()*253)+1; o2=int(rand()*253)+1;
		o3=int(rand()*253)+1; o4=int(rand()*253)+1;
		svc=(int(rand()*2)==0)?"nip.io":"sslip.io";
		printf "%d.%d.%d.%d.%s", o1,o2,o3,o4,svc;
	}'
}

# Pre-split DOMAINS_FIXED into a single line for cheap awk lookup.
pick_domain() {
	if [ "$MODE" = "unique" ]; then
		rand_unique_host
	else
		# Pick a random word out of DOMAINS_FIXED.
		awk -v list="$DOMAINS_FIXED" -v n="$DOMAINS_COUNT" -v seed="$$.$(date +%N 2>/dev/null || echo 0)" 'BEGIN{
			srand(seed + systime());
			cnt=split(list, a, " ");
			if (n > cnt) n = cnt;
			printf "%s", a[int(rand()*n)+1];
		}'
	fi
}

# Per-worker loop. Writes one line per iteration:
#   HH:MM:SS iter=N w=W dom=... code=... ip=... rt=...
worker() {
	wid="$1"
	iter=0
	while :; do
		iter=$((iter + 1))
		dom=$(pick_domain)
		# Strip every proxy env var so the request actually transits the
		# transparent-redirect path under test, not a parent shell's proxy.
		out=$(env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
			-u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY \
			curl -sS -k -o /dev/null \
			--connect-timeout "$CONNECT_TIMEOUT" \
			--max-time "$MAX_TIME" \
			-w '%{http_code} %{remote_ip} %{time_total}' \
			"https://$dom/" 2>/dev/null || echo "ERR - -")
		code=$(echo "$out" | awk '{print $1}')
		ip=$(echo "$out"   | awk '{print $2}')
		rt=$(echo "$out"   | awk '{print $3}')
		printf '%s iter=%d w=%d dom=%-32s code=%-4s ip=%-15s rt=%s\n' \
			"$(date '+%H:%M:%S')" "$iter" "$wid" "$dom" "$code" "$ip" "$rt" \
			>>"$LOG_FILE"
		[ "$SLEEP_MS" != 0 ] && sleep "$(awk -v ms="$SLEEP_MS" 'BEGIN{printf "%.3f", ms/1000}')"
	done
}

# Snapshot the probe log size so we only react to NEW DOWN events.
PROBE_OFFSET=0
[ -f "$PROBE_LOG" ] && PROBE_OFFSET=$(wc -c <"$PROBE_LOG" | awk '{print $1}')

START_EPOCH=$(date +%s)
echo "loadtest start: mode=$MODE workers=$WORKERS duration=${DURATION}s log=$LOG_FILE" >&2

# Spawn workers in background. Track PIDs in a space-separated string
# (no arrays in ash).
PIDS=""
w=1
while [ "$w" -le "$WORKERS" ]; do
	worker "$w" &
	PIDS="$PIDS $!"
	w=$((w + 1))
done

cleanup() {
	for p in $PIDS; do
		kill "$p" 2>/dev/null || true
	done
	wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Supervisor: every 2s scan the probe log tail (from PROBE_OFFSET on)
# for the DOWN line. Also bail when DURATION elapses.
DOWN_STEM=""
while :; do
	now=$(date +%s)
	elapsed=$((now - START_EPOCH))
	if [ "$elapsed" -ge "$DURATION" ]; then
		echo "loadtest: duration reached (${elapsed}s); stopping cleanly" >&2
		break
	fi
	if [ -f "$PROBE_LOG" ]; then
		new=$(dd if="$PROBE_LOG" bs=1 skip="$PROBE_OFFSET" 2>/dev/null \
			| grep 'DOWN: capturing forensic dump' | tail -n1 || true)
		if [ -n "$new" ]; then
			DOWN_STEM=$(echo "$new" | sed -n 's/.*stem=\([^ )]*\).*/\1/p')
			echo "loadtest: DOWN edge detected after ${elapsed}s -- stem=${DOWN_STEM:-?}" >&2
			break
		fi
	fi
	sleep 2
done

# Print a tiny summary the operator (or supervising script) can use.
LINES=$(wc -l <"$LOG_FILE" 2>/dev/null | awk '{print $1}')
ERRS=$(grep -c 'code=ERR' "$LOG_FILE" 2>/dev/null || echo 0)
TIMEOUTS=$(grep -c 'code=000' "$LOG_FILE" 2>/dev/null || echo 0)
echo "loadtest summary: lines=$LINES err=$ERRS timeouts=$TIMEOUTS dump_stem=${DOWN_STEM:-none}" >&2

if [ -n "$DOWN_STEM" ]; then
	exit 1
fi
exit 0
