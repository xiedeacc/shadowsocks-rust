#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

HOST="${HOST:-root@openwrt}"
SSH_PORT="${SSH_PORT:-}"
REMOTE_DIR="${REMOTE_DIR:-/usr/local/shadowsocks}"
REMOTE_BIN_DIR="${REMOTE_BIN_DIR:-$REMOTE_DIR/bin}"
# Upstream-master build: distinct binary name + config + service so it coexists
# with the config_dns fork install (/usr/local/shadowsocks/bin/sslocal,
# conf/shadowsocks-client.json, /etc/init.d/shadowsocks).
SSLOCAL_BIN="${SSLOCAL_BIN:-sslocal-master}"
REMOTE_CONFIG="${REMOTE_CONFIG:-$REMOTE_DIR/conf/shadowsocks-client-master.json}"
LOCAL_CONFIG="${LOCAL_CONFIG:-$ROOT_DIR/deploy/openwrt/conf/shadowsocks-client-master.json}"
REMOTE_TMP="${REMOTE_TMP:-/tmp/ssrust-master-deploy}"
SERVICE_NAME="${SERVICE_NAME:-shadowsocks-rust}"
NFT_HELPER_NAME="${NFT_HELPER_NAME:-ssrust-redir-nft.sh}"
NFT_TEMPLATE_NAME="${NFT_TEMPLATE_NAME:-ssrust-redir.nft}"
NFT_TEMPLATE_PATH="${NFT_TEMPLATE_PATH:-$ROOT_DIR/deploy/openwrt/conf/$NFT_TEMPLATE_NAME}"
# Master runs as /etc/init.d/shadowsocks-rust; the config_dns service
# (/etc/init.d/shadowsocks) is stopped+disabled first so they don't fight over
# the redir ports and the shared `inet ssrust_redir` nft table.
STOP_CONFLICTING_SERVICES="${STOP_CONFLICTING_SERVICES:-shadowsocks}"

TARGET_TRIPLE="${TARGET_TRIPLE:-}"
OPENWRT_TOOLCHAIN="${OPENWRT_TOOLCHAIN:-}"
FEATURES="${FEATURES:-logging hickory-dns local local-http local-http-rustls local-socks4 local-dns local-redir multi-threaded aead-cipher}"

DEFAULT_REDIR_PORT="${DEFAULT_REDIR_PORT:-12345}"
DEFAULT_DNS_PORT="${DEFAULT_DNS_PORT:-1053}"
DEFAULT_SS_SERVER_IP="${DEFAULT_SS_SERVER_IP:-54.179.191.126}"
TPROXY_MARK="${TPROXY_MARK:-0x1}"
OUTBOUND_FWMARK="${OUTBOUND_FWMARK:-255}"
OUTBOUND_MARK_HEX="${OUTBOUND_MARK_HEX:-0xff}"
TPROXY_TABLE="${TPROXY_TABLE:-100}"
NFT_TABLE="${NFT_TABLE:-ssrust_redir}"

SKIP_BUILD=0
NO_START=0
CLEANUP_ONLY=0

usage() {
	cat <<EOF
Usage: $(basename "$0") [--skip-build] [--no-start] [--cleanup]

Build upstream-master sslocal for OpenWrt, install it as:
  $REMOTE_BIN_DIR/$SSLOCAL_BIN
managed by /etc/init.d/$SERVICE_NAME (stops+disables: $STOP_CONFLICTING_SERVICES).

Pushes $REMOTE_CONFIG (from $LOCAL_CONFIG). Does not replace xray-plugin.

Environment knobs:
  HOST=root@openwrt
  SSH_PORT=22
  REMOTE_DIR=/usr/local/shadowsocks
  REMOTE_BIN_DIR=\$REMOTE_DIR/bin
  REMOTE_CONFIG=\$REMOTE_DIR/conf/shadowsocks-client.json
  SERVICE_NAME=shadowsocks
  NFT_TEMPLATE_PATH=$ROOT_DIR/deploy/openwrt/conf/$NFT_TEMPLATE_NAME
  STOP_CONFLICTING_SERVICES=""
  TARGET_TRIPLE=aarch64-unknown-linux-musl
  OPENWRT_TOOLCHAIN=/path/to/openwrt/toolchain
  FEATURES="$FEATURES"

Transparent proxy defaults, overridden by jsonfilter when possible:
  DEFAULT_REDIR_PORT=$DEFAULT_REDIR_PORT
  DEFAULT_DNS_PORT=$DEFAULT_DNS_PORT
  DEFAULT_SS_SERVER_IP=$DEFAULT_SS_SERVER_IP

Flags:
  --skip-build  Upload an existing target/<target>/release/sslocal.
  --no-start    Install files and service hook, but do not enable/restart it.
  --cleanup     Stop the service and remove nft/ip-rule state on OpenWrt.
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--skip-build)
			SKIP_BUILD=1
			shift
			;;
		--no-start)
			NO_START=1
			shift
			;;
		--cleanup|--cleanup-nft)
			CLEANUP_ONLY=1
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			printf 'unknown arg: %s\n' "$1" >&2
			usage >&2
			exit 2
			;;
	esac
done

ssh_cmd() {
	local ssh_args=(-o ConnectTimeout=8)
	if [[ -n "$SSH_PORT" ]]; then
		ssh_args+=(-p "$SSH_PORT")
	fi
	ssh "${ssh_args[@]}" "$HOST" "$@"
}

scp_cmd() {
	local scp_args=(-O)
	if [[ -n "$SSH_PORT" ]]; then
		scp_args+=(-P "$SSH_PORT")
	fi
	scp "${scp_args[@]}" "$@"
}

detect_target() {
	local arch
	arch="$(ssh_cmd 'uname -m')"
	case "$arch" in
		aarch64|arm64)
			printf '%s\n' aarch64-unknown-linux-musl
			;;
		x86_64)
			printf '%s\n' x86_64-unknown-linux-musl
			;;
		armv7l)
			printf '%s\n' armv7-unknown-linux-musleabihf
			;;
		*)
			printf 'Unsupported OpenWrt arch "%s"; set TARGET_TRIPLE manually.\n' "$arch" >&2
			exit 1
			;;
	esac
}

auto_detect_toolchain() {
	local target="$1"
	local root dir
	local roots=(/root/src/toolchains /opt)

	case "$target" in
		aarch64-unknown-linux-musl)
			for root in "${roots[@]}"; do
				[[ -d "$root" ]] || continue
				dir="$(find "$root" -maxdepth 4 -type d -name 'toolchain-aarch64_*_musl' -exec ls -dt {} + 2>/dev/null | head -1)"
				if [[ -n "$dir" && -x "$dir/bin/aarch64-openwrt-linux-musl-gcc" ]]; then
					printf '%s\n' "$dir"
					return
				fi
				dir="$root/aarch64-linux-musl-cross"
				if [[ -x "$dir/bin/aarch64-linux-musl-gcc" ]]; then
					printf '%s\n' "$dir"
					return
				fi
			done
			;;
		armv7-unknown-linux-musleabihf)
			for root in "${roots[@]}"; do
				[[ -d "$root" ]] || continue
				dir="$(find "$root" -maxdepth 4 -type d -name 'toolchain-arm_*_musl*' -exec ls -dt {} + 2>/dev/null | head -1)"
				if [[ -n "$dir" && -x "$dir/bin/arm-openwrt-linux-musleabi-gcc" ]]; then
					printf '%s\n' "$dir"
					return
				fi
				dir="$root/arm-linux-musleabihf-cross"
				if [[ -x "$dir/bin/arm-linux-musleabihf-gcc" ]]; then
					printf '%s\n' "$dir"
					return
				fi
			done
			;;
		x86_64-unknown-linux-musl)
			for root in "${roots[@]}"; do
				[[ -d "$root" ]] || continue
				dir="$(find "$root" -maxdepth 4 -type d -name 'toolchain-x86_64_*_musl' -exec ls -dt {} + 2>/dev/null | head -1)"
				if [[ -n "$dir" && -x "$dir/bin/x86_64-openwrt-linux-musl-gcc" ]]; then
					printf '%s\n' "$dir"
					return
				fi
				dir="$root/x86_64-linux-musl-cross"
				if [[ -x "$dir/bin/x86_64-linux-musl-gcc" ]]; then
					printf '%s\n' "$dir"
					return
				fi
			done
			;;
	esac
}

apply_toolchain() {
	local tc_root="$1"
	local tc_bin="$tc_root/bin"
	local cc ar
	export PATH="$tc_bin:$PATH"

	case "$TARGET_TRIPLE" in
		aarch64-unknown-linux-musl)
			if [[ -x "$tc_bin/aarch64-openwrt-linux-musl-gcc" ]]; then
				cc="$tc_bin/aarch64-openwrt-linux-musl-gcc"
				ar="$tc_bin/aarch64-openwrt-linux-musl-gcc-ar"
			else
				cc="$tc_bin/aarch64-linux-musl-gcc"
				ar="$tc_bin/aarch64-linux-musl-ar"
			fi
			export CC_aarch64_unknown_linux_musl="${CC_aarch64_unknown_linux_musl:-$cc}"
			export AR_aarch64_unknown_linux_musl="${AR_aarch64_unknown_linux_musl:-$ar}"
			export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER:-$cc}"
			;;
		armv7-unknown-linux-musleabihf)
			if [[ -x "$tc_bin/arm-openwrt-linux-musleabi-gcc" ]]; then
				cc="$tc_bin/arm-openwrt-linux-musleabi-gcc"
				ar="$tc_bin/arm-openwrt-linux-musleabi-gcc-ar"
			else
				cc="$tc_bin/arm-linux-musleabihf-gcc"
				ar="$tc_bin/arm-linux-musleabihf-ar"
			fi
			export CC_armv7_unknown_linux_musleabihf="${CC_armv7_unknown_linux_musleabihf:-$cc}"
			export AR_armv7_unknown_linux_musleabihf="${AR_armv7_unknown_linux_musleabihf:-$ar}"
			export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER="${CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER:-$cc}"
			;;
		x86_64-unknown-linux-musl)
			if [[ -x "$tc_bin/x86_64-openwrt-linux-musl-gcc" ]]; then
				cc="$tc_bin/x86_64-openwrt-linux-musl-gcc"
				ar="$tc_bin/x86_64-openwrt-linux-musl-gcc-ar"
			else
				cc="$tc_bin/x86_64-linux-musl-gcc"
				ar="$tc_bin/x86_64-linux-musl-ar"
			fi
			export CC_x86_64_unknown_linux_musl="${CC_x86_64_unknown_linux_musl:-$cc}"
			export AR_x86_64_unknown_linux_musl="${AR_x86_64_unknown_linux_musl:-$ar}"
			export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="${CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER:-$cc}"
			;;
	esac

	printf 'Using toolchain: %s\n' "$tc_root"
	printf 'Using compiler: %s\n' "$cc"
}

build_sslocal() {
	if [[ -z "$TARGET_TRIPLE" ]]; then
		TARGET_TRIPLE="$(detect_target)"
	fi

	if ! rustup target list --installed | grep -qx "$TARGET_TRIPLE"; then
		rustup target add "$TARGET_TRIPLE"
	fi

	if [[ -n "$OPENWRT_TOOLCHAIN" ]]; then
		if [[ ! -d "$OPENWRT_TOOLCHAIN/bin" ]]; then
			printf 'OpenWrt toolchain bin directory not found: %s\n' "$OPENWRT_TOOLCHAIN/bin" >&2
			exit 1
		fi
		apply_toolchain "$OPENWRT_TOOLCHAIN"
	else
		local detected
		detected="$(auto_detect_toolchain "$TARGET_TRIPLE")"
		if [[ -n "$detected" ]]; then
			apply_toolchain "$detected"
		else
			printf 'Warning: no cross compiler found for %s; relying on PATH.\n' "$TARGET_TRIPLE" >&2
			printf 'Set OPENWRT_TOOLCHAIN=/path/to/toolchain to override.\n' >&2
		fi
	fi

	if [[ "$SKIP_BUILD" = 0 ]]; then
		cargo build \
			--release \
			--target "$TARGET_TRIPLE" \
			--no-default-features \
			--features "$FEATURES" \
			--bin sslocal
	fi

	if [[ ! -x "$ROOT_DIR/target/$TARGET_TRIPLE/release/sslocal" ]]; then
		printf 'Missing built sslocal: %s\n' "$ROOT_DIR/target/$TARGET_TRIPLE/release/sslocal" >&2
		exit 1
	fi

	if [[ ! -s "$NFT_TEMPLATE_PATH" ]]; then
		printf 'Missing nft template: %s\n' "$NFT_TEMPLATE_PATH" >&2
		exit 1
	fi
}

cleanup_remote() {
	ssh_cmd "set -eu
		if [ -x /etc/init.d/$SERVICE_NAME ]; then
			/etc/init.d/$SERVICE_NAME stop 2>/dev/null || true
		fi
		if [ -x '$REMOTE_BIN_DIR/$NFT_HELPER_NAME' ]; then
			'$REMOTE_BIN_DIR/$NFT_HELPER_NAME' stop || true
		else
			nft delete table inet '$NFT_TABLE' 2>/dev/null || true
			while ip rule del fwmark '$TPROXY_MARK' table '$TPROXY_TABLE' 2>/dev/null; do :; done
			ip route del local 0.0.0.0/0 dev lo table '$TPROXY_TABLE' 2>/dev/null || true
			ip -6 route del local ::/0 dev lo table '$TPROXY_TABLE' 2>/dev/null || true
		fi
	"
}

write_remote_files() {
	ssh_cmd "rm -rf '$REMOTE_TMP' && mkdir -p '$REMOTE_TMP'"

	scp_cmd "$ROOT_DIR/target/$TARGET_TRIPLE/release/sslocal" "$HOST:$REMOTE_TMP/$SSLOCAL_BIN"
	scp_cmd "$NFT_TEMPLATE_PATH" "$HOST:$REMOTE_TMP/$NFT_TEMPLATE_NAME"
	if [[ ! -s "$LOCAL_CONFIG" ]]; then
		printf 'Missing local master config: %s\n' "$LOCAL_CONFIG" >&2
		exit 1
	fi
	scp_cmd "$LOCAL_CONFIG" "$HOST:$REMOTE_TMP/$(basename "$REMOTE_CONFIG")"

	ssh_cmd "cat > '$REMOTE_TMP/$NFT_HELPER_NAME' <<'EOS'
#!/bin/sh
set -eu

CONF='$REMOTE_CONFIG'
NFT_TABLE='$NFT_TABLE'
NFT_TEMPLATE='$REMOTE_BIN_DIR/$NFT_TEMPLATE_NAME'
REDIR_PORT='$DEFAULT_REDIR_PORT'
DNS_PORT='$DEFAULT_DNS_PORT'
SS_SERVER_IP='$DEFAULT_SS_SERVER_IP'
TPROXY_MARK='$TPROXY_MARK'
OUTBOUND_MARK='$OUTBOUND_MARK_HEX'
TPROXY_TABLE='$TPROXY_TABLE'

json_first() {
	local expr value
	expr=\"\$1\"
	command -v jsonfilter >/dev/null 2>&1 || return 0
	[ -s \"\$CONF\" ] || return 0
	value=\"\$(jsonfilter -i \"\$CONF\" -e \"\$expr\" 2>/dev/null | sed -n '1p' || true)\"
	printf '%s' \"\$value\"
}

is_ipv4() {
	case \"\$1\" in
		*.*) return 0 ;;
		*) return 1 ;;
	esac
}

require_ipv4() {
	local name value
	name=\"\$1\"
	value=\"\$2\"
	if ! is_ipv4 \"\$value\"; then
		echo \"\$name must be an IPv4 address for this nft template: \$value\" >&2
		exit 1
	fi
}

load_config() {
	local value
	value=\"\$(json_first '@.locals[@.protocol=\"redir\"].local_port')\"
	case \"\$value\" in ''|*[!0-9]*) ;; *) REDIR_PORT=\"\$value\" ;; esac

	value=\"\$(json_first '@.locals[@.protocol=\"dns\"].local_port')\"
	case \"\$value\" in ''|*[!0-9]*) ;; *) DNS_PORT=\"\$value\" ;; esac

	value=\"\$(json_first '@.servers[0].server')\"
	[ -n \"\$value\" ] && SS_SERVER_IP=\"\$value\"

	require_ipv4 'ssserver address' \"\$SS_SERVER_IP\"
}

cleanup() {
	nft delete table inet \"\$NFT_TABLE\" 2>/dev/null || true
	while ip rule del fwmark \"\$TPROXY_MARK\" table \"\$TPROXY_TABLE\" 2>/dev/null; do :; done
	ip route del local 0.0.0.0/0 dev lo table \"\$TPROXY_TABLE\" 2>/dev/null || true
	ip -6 route del local ::/0 dev lo table \"\$TPROXY_TABLE\" 2>/dev/null || true
}

render_rules() {
	local output
	if [ ! -s \"\$NFT_TEMPLATE\" ]; then
		echo \"missing nft template: \$NFT_TEMPLATE\" >&2
		exit 1
	fi
	output=\"/tmp/\$NFT_TABLE.rendered.\$\$.nft\"
	sed \\
		-e \"s#__NFT_TABLE__#\$NFT_TABLE#g\" \\
		-e \"s#__REDIR_PORT__#\$REDIR_PORT#g\" \\
		-e \"s#__DNS_PORT__#\$DNS_PORT#g\" \\
		-e \"s#__SS_SERVER_IP__#\$SS_SERVER_IP#g\" \\
		-e \"s#__TPROXY_MARK__#\$TPROXY_MARK#g\" \\
		-e \"s#__OUTBOUND_MARK__#\$OUTBOUND_MARK#g\" \\
		\"\$NFT_TEMPLATE\" > \"\$output\"
	printf '%s' \"\$output\"
}

install_rules() {
	load_config
	cleanup

	modprobe nft_tproxy 2>/dev/null || true
	modprobe nf_tproxy_ipv4 2>/dev/null || true
	modprobe nf_tproxy_ipv6 2>/dev/null || true

	ip rule add fwmark \"\$TPROXY_MARK\" table \"\$TPROXY_TABLE\" priority 100 2>/dev/null || true
	ip route replace local 0.0.0.0/0 dev lo table \"\$TPROXY_TABLE\"
	ip -6 rule add fwmark \"\$TPROXY_MARK\" table \"\$TPROXY_TABLE\" priority 100 2>/dev/null || true
	ip -6 route replace local ::/0 dev lo table \"\$TPROXY_TABLE\" 2>/dev/null || true

	rules_file=\"\$(render_rules)\"
	nft -f \"\$rules_file\"
	rm -f \"\$rules_file\"

	echo \"installed nft table \$NFT_TABLE: redir=\$REDIR_PORT dns=\$DNS_PORT server_ip=\$SS_SERVER_IP\"
}

case \"\${1:-start}\" in
	start)
		install_rules
		;;
	stop|cleanup)
		cleanup
		;;
	restart)
		install_rules
		;;
	status)
		nft list table inet \"\$NFT_TABLE\"
		;;
	*)
		echo \"usage: \$0 {start|stop|restart|status}\" >&2
		exit 2
		;;
esac
EOS
chmod 755 '$REMOTE_TMP/$NFT_HELPER_NAME'"

	ssh_cmd "cat > '$REMOTE_TMP/$SERVICE_NAME.init' <<'EOS'
#!/bin/sh /etc/rc.common

START=95
STOP=10
USE_PROCD=1

NAME='$SERVICE_NAME'
PROG='$REMOTE_BIN_DIR/$SSLOCAL_BIN'
CONF='$REMOTE_CONFIG'
NFT_HELPER='$REMOTE_BIN_DIR/$NFT_HELPER_NAME'
OUTBOUND_FWMARK='$OUTBOUND_FWMARK'

start_service() {
	if [ ! -x \"\$PROG\" ]; then
		echo \"missing \$PROG\" >&2
		return 1
	fi
	if [ ! -s \"\$CONF\" ]; then
		echo \"missing \$CONF\" >&2
		return 1
	fi

	procd_open_instance
	procd_set_param command \"\$PROG\" -c \"\$CONF\" --outbound-fwmark \"\$OUTBOUND_FWMARK\" --nofile 1048576
	procd_set_param respawn 3600 5 5
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_set_param file \"\$CONF\"
	procd_close_instance

	sleep 1
	if [ -x \"\$NFT_HELPER\" ]; then
		\"\$NFT_HELPER\" start
	fi
}

stop_service() {
	if [ -x \"\$NFT_HELPER\" ]; then
		\"\$NFT_HELPER\" stop || true
	fi
}

reload_service() {
	stop
	start
}

restart_service() {
	stop
	start
}
EOS
chmod 755 '$REMOTE_TMP/$SERVICE_NAME.init'"
}

install_remote() {
	ssh_cmd "set -eu
		mkdir -p '$REMOTE_BIN_DIR' '$(dirname "$REMOTE_CONFIG")'
		if command -v nft >/dev/null 2>&1; then
			:
		else
			echo 'missing nft command on OpenWrt' >&2
			exit 1
		fi
		cp -f '$REMOTE_TMP/$(basename "$REMOTE_CONFIG")' '$REMOTE_CONFIG'
		chmod 644 '$REMOTE_CONFIG'
		cp -f '$REMOTE_TMP/$SSLOCAL_BIN' '$REMOTE_BIN_DIR/$SSLOCAL_BIN'
		cp -f '$REMOTE_TMP/$NFT_HELPER_NAME' '$REMOTE_BIN_DIR/$NFT_HELPER_NAME'
		cp -f '$REMOTE_TMP/$NFT_TEMPLATE_NAME' '$REMOTE_BIN_DIR/$NFT_TEMPLATE_NAME'
		if [ -f '/etc/init.d/$SERVICE_NAME' ] && [ ! -f '/etc/init.d/$SERVICE_NAME.codex-backup' ]; then
			cp -f '/etc/init.d/$SERVICE_NAME' '/etc/init.d/$SERVICE_NAME.codex-backup'
		fi
		cp -f '$REMOTE_TMP/$SERVICE_NAME.init' '/etc/init.d/$SERVICE_NAME'
		chmod 755 '$REMOTE_BIN_DIR/$SSLOCAL_BIN' '$REMOTE_BIN_DIR/$NFT_HELPER_NAME' '/etc/init.d/$SERVICE_NAME'
		chmod 644 '$REMOTE_BIN_DIR/$NFT_TEMPLATE_NAME'
		if [ '$NO_START' = 0 ]; then
			for service in $STOP_CONFLICTING_SERVICES; do
				if [ \"\$service\" != '$SERVICE_NAME' ] && [ -x \"/etc/init.d/\$service\" ]; then
					\"/etc/init.d/\$service\" stop 2>/dev/null || true
					\"/etc/init.d/\$service\" disable 2>/dev/null || true
				fi
			done
			/etc/init.d/$SERVICE_NAME enable
			/etc/init.d/$SERVICE_NAME restart
			sleep 2
			/etc/init.d/$SERVICE_NAME status || true
			'$REMOTE_BIN_DIR/$NFT_HELPER_NAME' status >/dev/null
		fi
	"
}

configure_dnsmasq() {
	# The router's OWN resolver must use the split-DNS listener (sslocal :$DNS_PORT),
	# not the upstream ISP DNS. Upstream (e.g. 192.168.0.1) is GFW-poisoned, so router
	# self-traffic (which IS proxied) would resolve foreign names to fake IPs and fail
	# intermittently. Point dnsmasq at 127.0.0.1#$DNS_PORT and stop using the poisoned
	# upstream. Idempotent.
	ssh_cmd "set -eu
		if command -v uci >/dev/null 2>&1; then
			uci -q delete dhcp.@dnsmasq[0].server || true
			uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#$DEFAULT_DNS_PORT'
			uci set dhcp.@dnsmasq[0].noresolv='1'
			uci commit dhcp
			/etc/init.d/dnsmasq restart >/dev/null 2>&1 || true
			echo 'configured dnsmasq -> 127.0.0.1#$DEFAULT_DNS_PORT (split-DNS), noresolv=1'
		else
			echo 'uci not found; skipped dnsmasq split-DNS configuration' >&2
		fi
	"
}

if [[ "$CLEANUP_ONLY" = 1 ]]; then
	cleanup_remote
	printf 'Cleaned %s on %s\n' "$SERVICE_NAME" "$HOST"
	exit 0
fi

build_sslocal
write_remote_files
install_remote
if [[ "$NO_START" = 0 ]]; then
	configure_dnsmasq
fi

printf 'Deployed %s to %s:%s/%s\n' "$SSLOCAL_BIN" "$HOST" "$REMOTE_BIN_DIR" "$SSLOCAL_BIN"
printf 'Service: /etc/init.d/%s (stopped+disabled: %s)\n' "$SERVICE_NAME" "$STOP_CONFLICTING_SERVICES"
printf 'Config: %s:%s\n' "$HOST" "$REMOTE_CONFIG"
