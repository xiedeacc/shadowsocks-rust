#!/usr/bin/env bash
# loadtest_redir.sh — sustained load against the local sslocal transparent
# proxy (redir + DNS intercept). Drives the same code path that hangs in
# production: no `curl -x`, just plain HTTPS that gets redirected to
# 127.0.0.1:12345 by the nft rules sslocal installs.
#
# Two modes:
#   default — pick from a fixed list of common CN+intl domains; exercises
#             the steady-state DNS cache-hit path + connection churn.
#   --unique — every request uses a fresh random hostname under
#              <rand>.nip.io / sslip.io so every iteration forces a real
#              DNS lookup → maximum pressure on add_dns_results /
#              prune_dns_cache / nft add element.
#
# Stop conditions:
#   * --duration N        wall-clock seconds (default 3600)
#   * sslocal-probe.log shows a `DOWN: capturing forensic dump` line
#     newer than test start → exit non-zero with the dump stem.
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
DOMAINS_FIXED=(
	www.google.com www.youtube.com youtu.be yt3.ggpht.com static.xx.fbcdn.net
	twitter.com x.com www.cloudflare.com www.wikipedia.org commons.wikimedia.org
	upload.wikimedia.org www.reddit.com github.com api.github.com
	www.qq.com www.iqiyi.com www.aliyun.com www.baidu.com www.jd.com
	www.taobao.com weibo.com www.bilibili.com www.zhihu.com www.douyin.com
	www.akamai.com www.fastly.com d3js.org cdnjs.cloudflare.com
	httpbin.org example.com www.example.org www.example.net
)

# Returns a random hostname for --unique mode. Hostname encodes a random
# RFC1918-style numeric so nip.io/sslip.io will return a deterministic A
# record without hitting any real authority — minimum upstream cost,
# maximum pressure on the local DNS write path.
rand_unique_host() {
	# 4 random octets in 1..254 (avoid .0 / .255)
	o1=$(( (RANDOM % 253) + 1 ))
	o2=$(( (RANDOM % 253) + 1 ))
	o3=$(( (RANDOM % 253) + 1 ))
	o4=$(( (RANDOM % 253) + 1 ))
	# alternate between the two services so neither bears the full load
	if [ $((RANDOM % 2)) -eq 0 ]; then
		printf '%d.%d.%d.%d.nip.io' "$o1" "$o2" "$o3" "$o4"
	else
		printf '%d.%d.%d.%d.sslip.io' "$o1" "$o2" "$o3" "$o4"
	fi
}

pick_domain() {
	if [ "$MODE" = "unique" ]; then
		rand_unique_host
	else
		printf '%s' "${DOMAINS_FIXED[$((RANDOM % ${#DOMAINS_FIXED[@]}))]}"
	fi
}

# Per-worker loop. Writes one line per iteration:
#   HH:MM:SS.ffffff iter=N w=W dom=… code=… ip=… rt=…
worker() {
	local wid="$1"
	local iter=0
	while :; do
		iter=$((iter + 1))
		local dom; dom=$(pick_domain)
		local out; out=$(env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY \
			curl -sS -k -o /dev/null \
			--connect-timeout "$CONNECT_TIMEOUT" \
			--max-time "$MAX_TIME" \
			-w '%{http_code} %{remote_ip} %{time_total}' \
			"https://$dom/" 2>/dev/null || echo "ERR - -")
		local code ip rt
		read -r code ip rt <<<"$out"
		printf '%(%H:%M:%S)T.%06d iter=%d w=%d dom=%-32s code=%-4s ip=%-15s rt=%s\n' \
			-1 "$((RANDOM * 30))" "$iter" "$wid" "$dom" "$code" "$ip" "$rt" \
			>>"$LOG_FILE"
		[ "$SLEEP_MS" != 0 ] && sleep "$(awk -v ms="$SLEEP_MS" 'BEGIN{printf "%.3f", ms/1000}')"
	done
}

# Snapshot the probe log size so we only react to NEW DOWN events.
PROBE_OFFSET=0
[ -f "$PROBE_LOG" ] && PROBE_OFFSET=$(wc -c <"$PROBE_LOG")

START_EPOCH=$(date +%s)
echo "loadtest start: mode=$MODE workers=$WORKERS duration=${DURATION}s log=$LOG_FILE" >&2

# Spawn workers in background.
PIDS=()
for w in $(seq 1 "$WORKERS"); do
	worker "$w" &
	PIDS+=($!)
done

cleanup() {
	for p in "${PIDS[@]}"; do
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
		# Read only the slice past PROBE_OFFSET so we ignore old DOWNs.
		new=$(dd if="$PROBE_LOG" bs=1 skip="$PROBE_OFFSET" 2>/dev/null \
			| grep -E 'DOWN: capturing forensic dump' | tail -n1 || true)
		if [ -n "$new" ]; then
			DOWN_STEM=$(printf '%s' "$new" | sed -nE 's/.*stem=([^ )]*).*/\1/p')
			echo "loadtest: DOWN edge detected after ${elapsed}s — stem=${DOWN_STEM:-?}" >&2
			break
		fi
	fi
	sleep 2
done

# Print a tiny summary the operator (or supervising script) can use.
LINES=$(wc -l <"$LOG_FILE" 2>/dev/null || echo 0)
ERRS=$(grep -c 'code=ERR' "$LOG_FILE" 2>/dev/null || echo 0)
TIMEOUTS=$(grep -c 'code=000' "$LOG_FILE" 2>/dev/null || echo 0)
echo "loadtest summary: lines=$LINES err=$ERRS timeouts=$TIMEOUTS dump_stem=${DOWN_STEM:-none}" >&2

if [ -n "$DOWN_STEM" ]; then
	exit 1
fi
exit 0
