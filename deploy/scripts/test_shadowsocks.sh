#!/usr/bin/env bash
# Test the deployed shadowsocks-rust client on Ubuntu localhost or OpenWrt.
#
# Ubuntu mode runs curl/admin probes on this host. OpenWrt mode SSHes into the
# router and runs the same probes against the router-local listeners.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

TARGET="${TARGET:-ubuntu}"
REPORT="${REPORT:-}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/shadowsocks}"
REMOTE_DIR="${REMOTE_DIR:-/usr/local/shadowsocks}"
HOST="${HOST:-root@192.168.2.1}"
SSH_PORT="${SSH_PORT:-10022}"
CURL_MAX_TIME="${CURL_MAX_TIME:-12}"
ADMIN_MAX_TIME="${ADMIN_MAX_TIME:-8}"

DEFAULT_URLS=(
	"https://www.baidu.com"
	"https://www.google.com/generate_204"
)

URLS=()
if [[ -n "${TEST_URLS:-}" ]]; then
	IFS=',' read -r -a URLS <<<"$TEST_URLS"
else
	URLS=("${DEFAULT_URLS[@]}")
fi

usage() {
	cat <<'EOF'
test_shadowsocks.sh - test shadowsocks-rust redir/http/socks paths.

Usage:
  deploy/scripts/test_shadowsocks.sh [--target ubuntu|openwrt] [--report PATH]
  deploy/scripts/test_shadowsocks.sh --ubuntu
  deploy/scripts/test_shadowsocks.sh --openwrt

Default report:
  test_shadowsocks_ubuntu.md or test_shadowsocks_openwrt.md in the repo root.

Env knobs:
  TARGET=ubuntu|openwrt
  TEST_URLS=https://www.baidu.com,https://www.google.com/generate_204
  INSTALL_DIR=/usr/local/shadowsocks
  HOST=root@192.168.2.1 SSH_PORT=10022 REMOTE_DIR=/usr/local/shadowsocks
  CURL_MAX_TIME=12 ADMIN_MAX_TIME=8
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--target)
			TARGET="${2:-}"; shift 2 ;;
		--target=*)
			TARGET="${1#*=}"; shift ;;
		--ubuntu)
			TARGET=ubuntu; shift ;;
		--openwrt)
			TARGET=openwrt; shift ;;
		--report)
			REPORT="${2:-}"; shift 2 ;;
		--report=*)
			REPORT="${1#*=}"; shift ;;
		-h|--help)
			usage; exit 0 ;;
		*)
			printf 'unknown arg: %s\n\n' "$1" >&2
			usage >&2
			exit 2 ;;
	esac
done

case "$TARGET" in
	ubuntu|openwrt) ;;
	*) printf 'invalid target: %s\n' "$TARGET" >&2; exit 2 ;;
esac

if [[ -z "$REPORT" ]]; then
	REPORT="$ROOT_DIR/test_shadowsocks_${TARGET}.md"
elif [[ "$REPORT" != /* ]]; then
	REPORT="$ROOT_DIR/$REPORT"
fi

need_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		printf 'missing required command: %s\n' "$1" >&2
		exit 1
	fi
}

need_cmd curl
need_cmd jq
if [[ "$TARGET" = openwrt ]]; then
	need_cmd ssh
fi

log() {
	printf '[test] %s\n' "$*" >&2
}

sh_quote() {
	local s="${1-}"
	printf "'"
	printf '%s' "$s" | sed "s/'/'\\\\''/g"
	printf "'"
}

run_target_sh() {
	local script="$1"
	if [[ "$TARGET" = ubuntu ]]; then
		/bin/sh -c "$script"
	else
		ssh -o ConnectTimeout=8 -p "$SSH_PORT" "$HOST" "sh -c $(sh_quote "$script")"
	fi
}

read_target_file() {
	local path="$1"
	if [[ "$TARGET" = ubuntu ]]; then
		[[ -r "$path" ]] && cat "$path"
	else
		ssh -o ConnectTimeout=8 -p "$SSH_PORT" "$HOST" "cat $(sh_quote "$path") 2>/dev/null"
	fi
}

json_value() {
	local filter="$1" fallback="$2"
	local value
	value="$(jq -er "$filter // empty" "$CONFIG_JSON" 2>/dev/null || true)"
	if [[ -n "$value" ]]; then
		printf '%s\n' "$value"
	else
		printf '%s\n' "$fallback"
	fi
}

json_first_local_port() {
	local protocol="$1" fallback="$2"
	json_value "[.locals[]? | select(.protocol == \"$protocol\") | .local_port][0]" "$fallback"
}

json_has_local_protocol() {
	local protocol="$1"
	jq -e "[.locals[]? | select(.protocol == \"$protocol\")] | length > 0" "$CONFIG_JSON" >/dev/null 2>&1
}

admin_port_from_listen() {
	local listen="$1" port
	port="${listen##*:}"
	port="${port%]}"
	if [[ "$port" =~ ^[0-9]+$ ]]; then
		printf '%s\n' "$port"
	else
		printf '9090\n'
	fi
}

kv_get() {
	local file="$1" key="$2"
	awk -v key="$key" 'index($0, key "=") == 1 { print substr($0, length(key) + 2); exit }' "$file"
}

md_cell() {
	local s="${1-}"
	s="${s//$'\n'/ }"
	s="${s//$'\r'/ }"
	s="${s//|/\\|}"
	if [[ -z "$s" ]]; then
		printf -- '-'
	else
		printf '%s' "$s"
	fi
}

error_cell() {
	local s="${1-}"
	if [[ -z "$s" || "$s" = "-" || "$s" = "null" ]]; then
		printf 'OK'
	else
		md_cell "$s"
	fi
}

ok_from_http_code() {
	local exit_code="$1" http_code="$2"
	[[ "$exit_code" = 0 && "$http_code" =~ ^[23][0-9][0-9]$ ]]
}

json_field() {
	local file="$1" filter="$2"
	jq -r "$filter | if . == null then \"-\" elif type == \"array\" then map(tostring) | join(\", \") else tostring end" "$file" 2>/dev/null || printf -- '-\n'
}

json_label_bool() {
	local file="$1" filter="$2" value
	value="$(jq -r "$filter | if . == true then \"true\" elif . == false then \"false\" else \"\" end" "$file" 2>/dev/null || true)"
	case "$value" in
		true) printf 'yes\n' ;;
		false) printf 'no\n' ;;
		*) printf -- '-\n' ;;
	esac
}

json_label_cache() {
	local file="$1" value
	value="$(jq -r '.dns_cache_hit | if . == true then "true" elif . == false then "false" else "" end' "$file" 2>/dev/null || true)"
	case "$value" in
		true) printf 'hit\n' ;;
		false) printf 'miss\n' ;;
		*) printf -- '-\n' ;;
	esac
}

json_port_status() {
	local file="$1"
	jq -r '.port_status // (if .port_running == false then "not running" elif .transparent_port_received == true then "received" else "not received" end) // "-"' "$file" 2>/dev/null || printf -- '-\n'
}

seconds_to_ms() {
	local seconds="${1-}"
	if [[ "$seconds" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
		awk -v seconds="$seconds" 'BEGIN { printf "%.1f", seconds * 1000 }'
	else
		printf -- '-'
	fi
}

target_firewall_status() {
	local script
	script="if command -v nft >/dev/null 2>&1 && nft list table inet ssrust_redir >/dev/null 2>&1; then
	printf 'nft\n';
else
	printf 'missing\n';
fi"
	run_target_sh "$script" 2>/dev/null || printf 'unknown\n'
}

curl_env_unset='env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY'
curl_write_fmt='http_code=%{http_code}
remote_ip=%{remote_ip}
time_namelookup=%{time_namelookup}
time_connect=%{time_connect}
time_appconnect=%{time_appconnect}
time_starttransfer=%{time_starttransfer}
time_total=%{time_total}
size_download=%{size_download}
'

curl_probe() {
	local mode="$1" url="$2" outfile="$3" proxy_args=""

	case "$mode" in
		redir)
			if [[ "$REDIR_READY" != 1 ]]; then
				{
					printf 'exit_code=255\n'
					printf 'http_code=000\n'
					printf 'remote_ip=\n'
					printf 'time_namelookup=0\n'
					printf 'time_connect=0\n'
					printf 'time_appconnect=0\n'
					printf 'time_starttransfer=0\n'
					printf 'time_total=0\n'
					printf 'size_download=0\n'
					printf 'curl_error=redir not ready: %s\n' "$REDIR_REASON"
				} >"$outfile"
				return 0
			fi
			proxy_args="--noproxy $(sh_quote '*')" ;;
		http)
			proxy_args="-x $(sh_quote "http://127.0.0.1:${HTTP_PORT}")" ;;
		socks)
			proxy_args="-x $(sh_quote "socks5h://127.0.0.1:${SOCKS_PORT}")" ;;
		*)
			printf 'unknown probe mode: %s\n' "$mode" >&2
			exit 2 ;;
	esac

	local script
	script="tmp=\${TMPDIR:-/tmp}/test-shadowsocks-curl.\$\$;
rm -f \"\$tmp\";
out=\$($curl_env_unset curl -4 -L -sS -o /dev/null --max-time $(sh_quote "$CURL_MAX_TIME") $proxy_args -w $(sh_quote "$curl_write_fmt") $(sh_quote "$url") 2>\"\$tmp\");
ec=\$?;
err=\$(tr '\n' ' ' <\"\$tmp\" 2>/dev/null | sed 's/[[:space:]][[:space:]]*/ /g');
rm -f \"\$tmp\";
printf 'exit_code=%s\n' \"\$ec\";
printf '%s' \"\$out\";
printf 'curl_error=%s\n' \"\$err\""

	if ! run_target_sh "$script" >"$outfile"; then
		{
			printf 'exit_code=255\n'
			printf 'http_code=000\n'
			printf 'remote_ip=\n'
			printf 'time_namelookup=0\n'
			printf 'time_connect=0\n'
			printf 'time_appconnect=0\n'
			printf 'time_starttransfer=0\n'
			printf 'time_total=0\n'
			printf 'size_download=0\n'
			printf 'curl_error=target command failed\n'
		} >"$outfile"
	fi
}

admin_debug() {
	local mode="$1" url="$2" outfile="$3" payload auth_arg="" raw exit_code error json
	payload="$(jq -nc --arg url "$url" --arg mode "$mode" '{url: $url, mode: $mode}')"
	if [[ -n "$ADMIN_TOKEN" ]]; then
		auth_arg="-H $(sh_quote "x-admin-token: ${ADMIN_TOKEN}")"
	fi

	local script
	script="tmp=\${TMPDIR:-/tmp}/test-shadowsocks-admin.\$\$;
rm -f \"\$tmp\";
out=\$($curl_env_unset curl -sS --max-time $(sh_quote "$ADMIN_MAX_TIME") -X POST -H $(sh_quote 'content-type: application/json') $auth_arg -d $(sh_quote "$payload") $(sh_quote "${ADMIN_ENDPOINT}/api/sys/debug-url") 2>\"\$tmp\");
ec=\$?;
err=\$(tr '\n' ' ' <\"\$tmp\" 2>/dev/null | sed 's/[[:space:]][[:space:]]*/ /g');
rm -f \"\$tmp\";
printf 'exit_code=%s\n' \"\$ec\";
printf 'curl_error=%s\n' \"\$err\";
printf 'json=%s\n' \"\$out\""

	if ! raw="$(run_target_sh "$script")"; then
		raw='exit_code=255
curl_error=target admin command failed
json='
	fi
	exit_code="$(printf '%s\n' "$raw" | awk 'index($0, "exit_code=") == 1 { print substr($0, 11); exit }')"
	error="$(printf '%s\n' "$raw" | awk 'index($0, "curl_error=") == 1 { print substr($0, 12); exit }')"
	json="$(printf '%s\n' "$raw" | awk 'index($0, "json=") == 1 { print substr($0, 6); exit }')"

	if printf '%s' "$json" | jq -e . >/dev/null 2>&1; then
		printf '%s' "$json" | jq \
			--arg request_exit_code "${exit_code:-0}" \
			--arg request_error "$error" \
			'. + {
				admin_request_exit_code: ($request_exit_code | tonumber?),
				admin_request_error: (if $request_error == "" then null else $request_error end)
			}' >"$outfile"
	else
		jq -n \
			--arg url "$url" \
			--arg mode "$mode" \
			--arg request_exit_code "${exit_code:-255}" \
			--arg request_error "$error" \
			--arg raw "$json" \
			'{
				url: $url,
				debug_mode: $mode,
				error: "admin debug request failed",
				admin_request_exit_code: ($request_exit_code | tonumber?),
				admin_request_error: (if $request_error == "" then null else $request_error end),
				raw: $raw
			}' >"$outfile"
	fi
}

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
CONFIG_JSON="$TMP_DIR/config.json"

if [[ "$TARGET" = ubuntu ]]; then
	CONFIG_PATH="${CONFIG_PATH:-$INSTALL_DIR/conf/shadowsocks-client.json}"
	CONFIG_FALLBACK="$ROOT_DIR/deploy/ubuntu/conf/shadowsocks-client.json"
else
	CONFIG_PATH="${CONFIG_PATH:-$REMOTE_DIR/conf/shadowsocks-client.json}"
	CONFIG_FALLBACK="$ROOT_DIR/deploy/openwrt/conf/shadowsocks-client.json"
fi

if ! read_target_file "$CONFIG_PATH" >"$CONFIG_JSON" || ! jq -e . "$CONFIG_JSON" >/dev/null 2>&1; then
	log "could not parse deployed config at $CONFIG_PATH; using repo fallback $CONFIG_FALLBACK for port discovery"
	cp "$CONFIG_FALLBACK" "$CONFIG_JSON"
fi

SOCKS_PORT="$(json_first_local_port socks 1080)"
HTTP_PORT="$(json_first_local_port http 1081)"
REDIR_PORT="$(json_first_local_port redir 12345)"
DNS_PORT="$(json_first_local_port dns 1053)"
ADMIN_LISTEN="$(json_value '.web_admin.listen' '127.0.0.1:9090')"
ADMIN_TOKEN="$(json_value '.web_admin.token' '')"
DNS_INTERCEPT_MODE="$(json_value '.route_rules.dns_intercept_mode' '')"
ADMIN_PORT="$(admin_port_from_listen "$ADMIN_LISTEN")"
ADMIN_ENDPOINT="${ADMIN_ENDPOINT:-http://127.0.0.1:${ADMIN_PORT}}"

log "target=$TARGET report=$REPORT"
log "ports: socks=$SOCKS_PORT http=$HTTP_PORT redir=$REDIR_PORT dns=$DNS_PORT admin=$ADMIN_ENDPOINT"

REDIR_READY=1
REDIR_REASON=
FIREWALL_STATUS="$(target_firewall_status | head -1)"
if ! json_has_local_protocol redir; then
	REDIR_READY=0
	REDIR_REASON="config has no protocol=redir listener"
elif ! json_has_local_protocol dns; then
	REDIR_READY=0
	REDIR_REASON="config has no protocol=dns listener"
elif [[ "$DNS_INTERCEPT_MODE" != "firewall" && "$DNS_INTERCEPT_MODE" != "both" ]]; then
	REDIR_READY=0
	REDIR_REASON="route_rules.dns_intercept_mode is ${DNS_INTERCEPT_MODE:-unset}"
elif [[ "$FIREWALL_STATUS" != "nft" ]]; then
	REDIR_READY=0
	REDIR_REASON="transparent nft table ssrust_redir is $FIREWALL_STATUS"
fi

failure_count=0
probe_files=()
debug_files=()
declare -A debug_file_by_key=()

for i in "${!URLS[@]}"; do
	url="${URLS[$i]}"
	for mode in redir http socks; do
		debug_file="$TMP_DIR/debug_${i}_${mode}.json"
		log "admin debug-$mode url=$url"
		admin_debug "$mode" "$url" "$debug_file"
		debug_files+=("$i:$mode:$debug_file")
		debug_file_by_key["$i:$mode"]="$debug_file"
		if [[ "$(json_field "$debug_file" '.admin_request_exit_code')" != 0 ]]; then
			failure_count=$((failure_count + 1))
		elif [[ "$(json_field "$debug_file" '.response_received')" != true ]]; then
			failure_count=$((failure_count + 1))
		fi

		outfile="$TMP_DIR/probe_${i}_${mode}.kv"
		log "curl probe mode=$mode url=$url"
		curl_probe "$mode" "$url" "$outfile"
		probe_files+=("$i:$mode:$outfile")
		exit_code="$(kv_get "$outfile" exit_code)"
		http_code="$(kv_get "$outfile" http_code)"
		if ! ok_from_http_code "$exit_code" "$http_code"; then
			failure_count=$((failure_count + 1))
		fi
	done
done

generated_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

{
	printf '# Shadowsocks Test Report\n\n'
	printf -- '- Generated: `%s`\n' "$generated_at"
	printf -- '- Target: `%s`\n' "$TARGET"
	printf -- '- Config: `%s`\n' "$CONFIG_PATH"
	printf -- '- Admin endpoint used by tester: `%s`\n' "$ADMIN_ENDPOINT"
	printf -- '- DNS intercept mode: `%s`\n' "${DNS_INTERCEPT_MODE:-unknown}"
	printf -- '- Transparent firewall: `%s`\n' "$FIREWALL_STATUS"
	printf -- '- Redir readiness: `%s`\n' "$([[ "$REDIR_READY" = 1 ]] && printf ready || printf 'not ready')"
	if [[ "$REDIR_READY" != 1 ]]; then
		printf -- '- Redir readiness reason: `%s`\n' "$REDIR_REASON"
	fi
	printf -- '- Ports: socks `%s`, http `%s`, redir `%s`, dns `%s`\n' "$SOCKS_PORT" "$HTTP_PORT" "$REDIR_PORT" "$DNS_PORT"
	if [[ "$TARGET" = openwrt ]]; then
		printf -- '- OpenWrt SSH: `%s -p %s`\n' "$HOST" "$SSH_PORT"
	fi
	printf '\n'

	printf '## Transport Probes\n\n'
	printf '| Mode | Endpoint | Route Decision | Proxy Domain | DNS Intercepted | DNS Cache | Resolved IPs | OK | HTTP | Remote IP | DNS Resolve Time (ms) | Visit Time (ms) | TCP Connect (ms) | TLS Handshake (ms) | First Byte (ms) | Exit | Error |\n'
	printf '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |\n'
	for entry in "${probe_files[@]}"; do
		IFS=':' read -r idx mode file <<<"$entry"
		url="${URLS[$idx]}"
		debug_file="${debug_file_by_key["$idx:$mode"]:-}"
		case "$mode" in
			redir) endpoint="transparent redir:${REDIR_PORT}" ;;
			http) endpoint="http://127.0.0.1:${HTTP_PORT}" ;;
			socks) endpoint="socks5h://127.0.0.1:${SOCKS_PORT}" ;;
		esac
		exit_code="$(kv_get "$file" exit_code)"
		http_code="$(kv_get "$file" http_code)"
		if ok_from_http_code "$exit_code" "$http_code"; then ok=yes; else ok=no; fi
		if [[ "$mode" = redir ]]; then
			dns_intercepted="$(json_label_bool "$debug_file" '.dns_intercepted')"
			dns_cache="$(json_label_cache "$debug_file")"
			resolved_ips="$(json_field "$debug_file" '.resolved_ips')"
		else
			dns_intercepted=-
			dns_cache=-
			resolved_ips=-
		fi
		printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
			"$(md_cell "$mode")" \
			"$(md_cell "$endpoint")" \
			"$(md_cell "$(json_field "$debug_file" '.route_decision')")" \
			"$(md_cell "$(json_label_bool "$debug_file" '.proxy_domain')")" \
			"$(md_cell "$dns_intercepted")" \
			"$(md_cell "$dns_cache")" \
			"$(md_cell "$resolved_ips")" \
			"$(md_cell "$ok")" \
			"$(md_cell "$http_code")" \
			"$(md_cell "$(kv_get "$file" remote_ip)")" \
			"$(md_cell "$(seconds_to_ms "$(kv_get "$file" time_namelookup)")")" \
			"$(md_cell "$(seconds_to_ms "$(kv_get "$file" time_total)")")" \
			"$(md_cell "$(seconds_to_ms "$(kv_get "$file" time_connect)")")" \
			"$(md_cell "$(seconds_to_ms "$(kv_get "$file" time_appconnect)")")" \
			"$(md_cell "$(seconds_to_ms "$(kv_get "$file" time_starttransfer)")")" \
			"$(md_cell "$exit_code")" \
			"$(error_cell "$(kv_get "$file" curl_error)")"
	done
	printf '\n'

	printf '## Admin Debug redir/http/socks\n\n'
	for section_mode in redir http socks; do
		case "$section_mode" in
			redir) port_header="Transparent Port" ;;
			http) port_header="Http Port" ;;
			socks) port_header="Socks Port" ;;
		esac
		printf '### Debug %s\n\n' "$section_mode"
		printf '```text\n'
		for entry in "${debug_files[@]}"; do
			IFS=':' read -r idx mode file <<<"$entry"
			[[ "$mode" = "$section_mode" ]] || continue
			printf '%s: %s\n' "${URLS[$idx]}" "$(json_field "$file" '.curl_command')"
		done
		printf '```\n\n'

		if [[ "$section_mode" = redir ]]; then
			printf '| Route Decision | Proxy Domain | DNS Intercepted | DNS Cache | Resolved IPs | NFT Proxy | NFT Matches | %s | Response | HTTP | DNS Resolve Time (ms) | TCP Connect (ms) | TLS Handshake (ms) | First Byte (ms) | Curl Exit | Error |\n' "$port_header"
			printf '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |\n'
		else
			printf '| Route Decision | Proxy Domain | %s | Response | HTTP | DNS Resolve Time (ms) | TCP Connect (ms) | TLS Handshake (ms) | First Byte (ms) | Curl Exit | Error |\n' "$port_header"
			printf '| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |\n'
		fi

		for entry in "${debug_files[@]}"; do
			IFS=':' read -r idx mode file <<<"$entry"
			[[ "$mode" = "$section_mode" ]] || continue
			if [[ "$section_mode" = redir ]]; then
				printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
					"$(md_cell "$(json_field "$file" '.route_decision')")" \
					"$(md_cell "$(json_label_bool "$file" '.proxy_domain')")" \
					"$(md_cell "$(json_label_bool "$file" '.dns_intercepted')")" \
					"$(md_cell "$(json_label_cache "$file")")" \
					"$(md_cell "$(json_field "$file" '.resolved_ips')")" \
					"$(md_cell "$(json_label_bool "$file" '.nft_proxy')")" \
					"$(md_cell "$(json_field "$file" '.nft_matches')")" \
					"$(md_cell "$(json_port_status "$file")")" \
					"$(md_cell "$(json_field "$file" '.response_received')")" \
					"$(md_cell "$(json_field "$file" '.http_code')")" \
					"$(md_cell "$(seconds_to_ms "$(json_field "$file" '.time_namelookup')")")" \
					"$(md_cell "$(seconds_to_ms "$(json_field "$file" '.time_connect')")")" \
					"$(md_cell "$(seconds_to_ms "$(json_field "$file" '.time_appconnect')")")" \
					"$(md_cell "$(seconds_to_ms "$(json_field "$file" '.time_starttransfer')")")" \
					"$(md_cell "$(json_field "$file" '.curl_exit_code // .admin_request_exit_code')")" \
					"$(error_cell "$(json_field "$file" '.curl_error // .admin_request_error // .error')")"
			else
				printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
					"$(md_cell "$(json_field "$file" '.route_decision')")" \
					"$(md_cell "$(json_label_bool "$file" '.proxy_domain')")" \
					"$(md_cell "$(json_port_status "$file")")" \
					"$(md_cell "$(json_field "$file" '.response_received')")" \
					"$(md_cell "$(json_field "$file" '.http_code')")" \
					"$(md_cell "$(seconds_to_ms "$(json_field "$file" '.time_namelookup')")")" \
					"$(md_cell "$(seconds_to_ms "$(json_field "$file" '.time_connect')")")" \
					"$(md_cell "$(seconds_to_ms "$(json_field "$file" '.time_appconnect')")")" \
					"$(md_cell "$(seconds_to_ms "$(json_field "$file" '.time_starttransfer')")")" \
					"$(md_cell "$(json_field "$file" '.curl_exit_code // .admin_request_exit_code')")" \
					"$(error_cell "$(json_field "$file" '.curl_error // .admin_request_error // .error')")"
			fi
		done
		printf '\n'
	done

	printf '## Raw Admin Debug JSON\n\n'
	for entry in "${debug_files[@]}"; do
		IFS=':' read -r idx mode file <<<"$entry"
		printf '### %s %s\n\n' "$mode" "${URLS[$idx]}"
		printf '```json\n'
		jq . "$file"
		printf '\n```\n\n'
	done

	if [[ "$failure_count" -eq 0 ]]; then
		printf '## Result\n\nAll required probes passed.\n'
	else
		printf '## Result\n\n%d required probe(s) failed. See tables above for exit codes and errors.\n' "$failure_count"
	fi
} >"$REPORT"

log "wrote $REPORT"

if [[ "$failure_count" -ne 0 ]]; then
	exit 1
fi
