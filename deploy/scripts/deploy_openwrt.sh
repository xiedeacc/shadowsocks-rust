#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPLOY_DIR="$ROOT_DIR/deploy"
DEPLOY_BIN_DIR="$DEPLOY_DIR/bin"
DEPLOY_CONF_DIR="$DEPLOY_DIR/conf"
DEPLOY_DATA_DIR="$DEPLOY_DIR/data"

HOST="${HOST:-root@openwrt}"
SSH_PORT="${SSH_PORT:-}"
REMOTE_DIR="${REMOTE_DIR:-/usr/local/shadowsocks}"
SERVICE_NAME="${SERVICE_NAME:-shadowsocks}"
REMOTE_TMP="${REMOTE_TMP:-/tmp/shadowsocks-rust-deploy}"
FEATURES="${FEATURES:-full local-web-admin local-http-rustls}"
TARGET_TRIPLE="${TARGET_TRIPLE:-}"
OPENWRT_TOOLCHAIN="${OPENWRT_TOOLCHAIN:-}"
DISABLE_LEGACY="${DISABLE_LEGACY:-0}"
CLEANUP_ONLY=0

while [[ $# -gt 0 ]]; do
	case "$1" in
		--cleanup|--cleanup-nft)
			CLEANUP_ONLY=1; shift ;;
		-h|--help)
			cat <<'EOF'
deploy_openwrt.sh — cross-build sslocal and push it to the OpenWrt router.

Flags:
  --cleanup    SSH to the router, stop /etc/init.d/shadowsocks,
               flush the inet ssrust_redir nft table,
               then exit without rebuilding/redeploying.

Env knobs:
  HOST=root@openwrt        SSH_PORT=10022
  REMOTE_DIR=/usr/local/shadowsocks
  SERVICE_NAME=shadowsocks
  TARGET_TRIPLE / OPENWRT_TOOLCHAIN / FEATURES / DISABLE_LEGACY
EOF
			exit 0 ;;
		*) printf 'unknown arg: %s\n' "$1" >&2; exit 2 ;;
	esac
done

# Known toolchain search roots, in preference order:
#   1. OpenWrt SDK toolchain (exact ABI match for the target device)
#   2. Generic musl cross-compiler (broader compatibility)
TOOLCHAIN_SEARCH_ROOTS=(
	/root/src/toolchains
	/opt
)

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

# Best-effort cleanup of leftover sslocal firewall state on the router:
#   * stop /etc/init.d/shadowsocks so it can't recreate the table
#     while we're flushing,
#   * delete `inet ssrust_redir` (the single nft table holds the entire
#     redirect/tproxy/DNS-redirect firewall).
# Idempotent; missing services / tables are silently ignored.
cleanup_remote_firewall() {
	ssh_cmd "set -e
		if [ -x /etc/init.d/$SERVICE_NAME ]; then
			echo '[cleanup] stopping $SERVICE_NAME'
			/etc/init.d/$SERVICE_NAME stop 2>/dev/null || true
		fi
		if command -v nft >/dev/null 2>&1; then
			if nft list table inet ssrust_redir >/dev/null 2>&1; then
				echo '[cleanup] deleting nft table inet ssrust_redir'
				nft delete table inet ssrust_redir || true
			else
				echo '[cleanup] no stale nft table inet ssrust_redir'
			fi
		fi
		if command -v ip >/dev/null 2>&1; then
			while ip rule del fwmark 0x1 table 100 2>/dev/null; do
				echo '[cleanup] deleted tproxy ip rule fwmark 0x1 table 100'
			done
			while ip -6 rule del fwmark 0x1 table 100 2>/dev/null; do
				echo '[cleanup] deleted tproxy ip -6 rule fwmark 0x1 table 100'
			done
			ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null || true
			ip -6 route del local ::/0 dev lo table 100 2>/dev/null || true
		fi
		echo '[cleanup] done'
	"
}

if [[ "$CLEANUP_ONLY" = 1 ]]; then
	cleanup_remote_firewall
	printf 'Cleanup complete on %s. Run without --cleanup to redeploy.\n' "$HOST"
	exit 0
fi

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

# Auto-detect the toolchain root for a given target triple.
# Prints the toolchain root directory (not the bin/ subdirectory).
# Search order: OpenWrt SDK toolchain dirs, then generic musl cross dirs.
auto_detect_toolchain() {
	local target="$1"
	local root dir

	case "$target" in
		aarch64-unknown-linux-musl)
			# OpenWrt SDK toolchains ship a subdirectory named
			# toolchain-aarch64_*_musl inside the unpacked tarball.
			for root in "${TOOLCHAIN_SEARCH_ROOTS[@]}"; do
				[[ -d "$root" ]] || continue
				# Pick the most-recently-modified match (newest SDK first).
				dir="$(find "$root" -maxdepth 3 -type d \
					-name 'toolchain-aarch64_*_musl' \
					-exec ls -dt {} + 2>/dev/null | head -1)"
				if [[ -n "$dir" && -x "$dir/bin/aarch64-openwrt-linux-musl-gcc" ]]; then
					printf '%s\n' "$dir"
					return
				fi
				# Generic musl cross under the same root.
				dir="$root/aarch64-linux-musl-cross"
				if [[ -x "$dir/bin/aarch64-linux-musl-gcc" ]]; then
					printf '%s\n' "$dir"
					return
				fi
			done
			;;
		armv7-unknown-linux-musleabihf)
			for root in "${TOOLCHAIN_SEARCH_ROOTS[@]}"; do
				[[ -d "$root" ]] || continue
				dir="$(find "$root" -maxdepth 3 -type d \
					-name 'toolchain-arm_*_musl*' \
					-exec ls -dt {} + 2>/dev/null | head -1)"
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
	esac
}

# Set up compiler env vars for the toolchain directory.
apply_toolchain() {
	local tc_root="$1"
	local tc_bin="$tc_root/bin"
	export PATH="$tc_bin:$PATH"

	case "$TARGET_TRIPLE" in
		aarch64-unknown-linux-musl)
			# Prefer the OpenWrt-branded compiler; fall back to generic musl.
			local cc
			if [[ -x "$tc_bin/aarch64-openwrt-linux-musl-gcc" ]]; then
				cc="$tc_bin/aarch64-openwrt-linux-musl-gcc"
				local ar="$tc_bin/aarch64-openwrt-linux-musl-gcc-ar"
			else
				cc="$tc_bin/aarch64-linux-musl-gcc"
				local ar="$tc_bin/aarch64-linux-musl-ar"
			fi
			export CC_aarch64_unknown_linux_musl="${CC_aarch64_unknown_linux_musl:-$cc}"
			export AR_aarch64_unknown_linux_musl="${AR_aarch64_unknown_linux_musl:-$ar}"
			export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER:-$cc}"
			;;
		armv7-unknown-linux-musleabihf)
			local cc
			if [[ -x "$tc_bin/arm-openwrt-linux-musleabi-gcc" ]]; then
				cc="$tc_bin/arm-openwrt-linux-musleabi-gcc"
				local ar="$tc_bin/arm-openwrt-linux-musleabi-gcc-ar"
			else
				cc="$tc_bin/arm-linux-musleabihf-gcc"
				local ar="$tc_bin/arm-linux-musleabihf-ar"
			fi
			export CC_armv7_unknown_linux_musleabihf="${CC_armv7_unknown_linux_musleabihf:-$cc}"
			export AR_armv7_unknown_linux_musleabihf="${AR_armv7_unknown_linux_musleabihf:-$ar}"
			export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER="${CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER:-$cc}"
			;;
	esac

	printf 'Using toolchain: %s\n' "$tc_root"
	printf '  CC  = %s\n' "${CC_aarch64_unknown_linux_musl:-${CC_armv7_unknown_linux_musleabihf:-<native>}}"
}

if [[ -z "$TARGET_TRIPLE" ]]; then
	TARGET_TRIPLE="$(detect_target)"
fi

if ! rustup target list --installed | grep -qx "$TARGET_TRIPLE"; then
	rustup target add "$TARGET_TRIPLE"
fi

# Resolve toolchain: explicit OPENWRT_TOOLCHAIN > auto-detect > error.
if [[ -n "$OPENWRT_TOOLCHAIN" ]]; then
	if [[ ! -d "$OPENWRT_TOOLCHAIN/bin" ]]; then
		printf 'OpenWrt toolchain bin directory not found: %s\n' "$OPENWRT_TOOLCHAIN/bin" >&2
		exit 1
	fi
	apply_toolchain "$OPENWRT_TOOLCHAIN"
else
	detected="$(auto_detect_toolchain "$TARGET_TRIPLE")"
	if [[ -n "$detected" ]]; then
		apply_toolchain "$detected"
	else
		printf 'Warning: no cross-compiler found for %s; relying on PATH.\n' "$TARGET_TRIPLE" >&2
		printf 'Set OPENWRT_TOOLCHAIN=/path/to/toolchain to override.\n' >&2
	fi
fi

cargo build \
	--release \
	--target "$TARGET_TRIPLE" \
	--no-default-features \
	--features "$FEATURES" \
	--bin sslocal

mkdir -p "$DEPLOY_BIN_DIR" "$DEPLOY_CONF_DIR" "$DEPLOY_DATA_DIR" "$DEPLOY_DIR/logs"
install -m 755 "$ROOT_DIR/target/$TARGET_TRIPLE/release/sslocal" "$DEPLOY_BIN_DIR/sslocal_openwrt"

LOCAL_CLIENT_CONFIG="$DEPLOY_CONF_DIR/shadowsocks-client.json"
if [[ ! -s "$LOCAL_CLIENT_CONFIG" ]]; then
	if ssh_cmd "test -s '$REMOTE_DIR/conf/shadowsocks-client.json'"; then
		printf 'Local client config missing; keeping existing remote %s/conf/shadowsocks-client.json.\n' "$REMOTE_DIR"
	else
		printf 'Missing local %s and remote %s/conf/shadowsocks-client.json\n' "$LOCAL_CLIENT_CONFIG" "$REMOTE_DIR" >&2
		exit 1
	fi
fi

DATA_SOURCE_DIR="$DEPLOY_DATA_DIR"

ssh_cmd "rm -rf '$REMOTE_TMP' && mkdir -p '$REMOTE_TMP' '$REMOTE_DIR/bin' '$REMOTE_DIR/conf' '$REMOTE_DIR/data' '$REMOTE_DIR/logs'"
scp_cmd "$DEPLOY_BIN_DIR/sslocal_openwrt" "$HOST:$REMOTE_TMP/sslocal"
REMOTE_HAS_XRAY_PLUGIN="$(ssh_cmd "test -x '$REMOTE_DIR/bin/xray-plugin' && printf yes || printf no")"
if [[ "$REMOTE_HAS_XRAY_PLUGIN" = yes ]]; then
	printf 'Remote xray-plugin already exists at %s/bin/xray-plugin; skipping copy.\n' "$REMOTE_DIR"
elif [[ -x "$DEPLOY_BIN_DIR/xray-plugin" ]]; then
	scp_cmd "$DEPLOY_BIN_DIR/xray-plugin" "$HOST:$REMOTE_TMP/xray-plugin"
fi
if [[ -d "$DEPLOY_CONF_DIR" ]]; then
	tar -C "$DEPLOY_CONF_DIR" -cf - . | ssh_cmd "mkdir -p '$REMOTE_TMP/conf' && tar -C '$REMOTE_TMP/conf' -xf -"
fi

if [[ -d "$DATA_SOURCE_DIR" ]]; then
	tar -C "$DATA_SOURCE_DIR" -cf - . | ssh_cmd "mkdir -p '$REMOTE_TMP/data' && tar -C '$REMOTE_TMP/data' -xf -"
fi

ssh_cmd "cat > '$REMOTE_TMP/install.sh' <<'EOS'
set -eu
REMOTE_DIR='$REMOTE_DIR'
SERVICE_NAME='$SERVICE_NAME'
REMOTE_TMP='$REMOTE_TMP'
DISABLE_LEGACY='$DISABLE_LEGACY'

copy_missing_tree() {
	src_dir="\$1"
	dst_dir="\$2"
	[ -d "\$src_dir" ] || return 0
	mkdir -p "\$dst_dir"
	find "\$src_dir" -type d | while IFS= read -r src_subdir; do
		rel="\${src_subdir#\$src_dir}"
		rel="\${rel#/}"
		[ -n "\$rel" ] || continue
		mkdir -p "\$dst_dir/\$rel"
	done
	find "\$src_dir" -type f | while IFS= read -r src_file; do
		rel="\${src_file#\$src_dir}"
		rel="\${rel#/}"
		dst_file="\$dst_dir/\$rel"
		if [ ! -e "\$dst_file" ]; then
			dst_parent="\${dst_file%/*}"
			mkdir -p "\$dst_parent"
			cp -f "\$src_file" "\$dst_file"
		fi
	done
}

mkdir -p \"\$REMOTE_DIR/bin\" \"\$REMOTE_DIR/conf\" \"\$REMOTE_DIR/data\" \"\$REMOTE_DIR/data/temp\" \"\$REMOTE_DIR/logs\"
cp -f \"\$REMOTE_TMP/sslocal\" \"\$REMOTE_DIR/bin/sslocal\"
chmod 755 \"\$REMOTE_DIR/bin/sslocal\"
if [ -x \"\$REMOTE_TMP/xray-plugin\" ]; then
	cp -f \"\$REMOTE_TMP/xray-plugin\" \"\$REMOTE_DIR/bin/xray-plugin\"
	chmod 755 \"\$REMOTE_DIR/bin/xray-plugin\"
fi
rm -f \"\$REMOTE_DIR/bin/ssrust-watchdog.sh\"
copy_missing_tree \"\$REMOTE_TMP/conf\" \"\$REMOTE_DIR/conf\"
if [ -s \"\$REMOTE_DIR/conf/shadowsocks-client.json\" ]; then
	chmod 644 \"\$REMOTE_DIR/conf/shadowsocks-client.json\"
else
	echo \"missing \$REMOTE_DIR/conf/shadowsocks-client.json\" >&2
	exit 1
fi
copy_missing_tree \"\$REMOTE_TMP/data\" \"\$REMOTE_DIR/data\"
cp -f \"\$REMOTE_TMP/conf/shadowsocks-rust.init\" \"/etc/init.d/\$SERVICE_NAME\"
chmod 755 \"/etc/init.d/\$SERVICE_NAME\"

for removed_service in sslocal-watch sslocal-probe; do
	if [ -x \"/etc/init.d/\$removed_service\" ]; then
		\"/etc/init.d/\$removed_service\" stop || true
		\"/etc/init.d/\$removed_service\" disable || true
	fi
	rm -f \"/etc/init.d/\$removed_service\" /etc/rc.d/*\"\$removed_service\"* \"\$REMOTE_DIR/bin/\$removed_service.sh\"
done

detect_sslocal_process() {
	if pgrep -f '(^|/)sslocal-master([[:space:]]|$)' >/dev/null 2>&1 || ps w 2>/dev/null | grep -q '[s]slocal-master'; then
		printf 'sslocal-master'
		return 0
	fi
	if pgrep -f '(^|/)sslocal([[:space:]]|$)' >/dev/null 2>&1 || ps w 2>/dev/null | grep -q '[s]slocal '; then
		printf 'sslocal'
		return 0
	fi
	return 1
}

running_local=\"\$(detect_sslocal_process || true)\"
if [ -n \"\$running_local\" ]; then
	echo \"[deploy] detected running local process: \$running_local\"
fi
if [ \"\$SERVICE_NAME\" = shadowsocks ] && [ \"\$running_local\" = sslocal-master ] && [ -x /etc/init.d/shadowsocks-rust ]; then
	echo '[deploy] sslocal-master belongs to shadowsocks-rust; switching to /etc/init.d/shadowsocks'
	/etc/init.d/shadowsocks-rust disable || true
	/etc/init.d/shadowsocks-rust stop || true
fi

if command -v apk >/dev/null 2>&1 && ! lsmod | grep -q '^nft_tproxy'; then
	apk update || true
	apk add kmod-nft-tproxy || true
fi

if [ \"\$DISABLE_LEGACY\" = 1 ] && [ \"\$SERVICE_NAME\" != shadowsocks ] && [ -x /etc/init.d/shadowsocks ]; then
	/etc/init.d/shadowsocks stop || true
	/etc/init.d/shadowsocks disable || true
fi

/etc/init.d/\$SERVICE_NAME enable
if [ \"\$running_local\" = sslocal-master ]; then
	# Was running the upstream-master build (handed off above: shadowsocks-rust
	# disabled+stopped), so shadowsocks isn't up yet -> plain start.
	/etc/init.d/\$SERVICE_NAME start
else
	# Already on shadowsocks (or nothing running) -> restart to load the new build.
	/etc/init.d/\$SERVICE_NAME restart
fi
sleep 2
/etc/init.d/\$SERVICE_NAME status || true

EOS
sh '$REMOTE_TMP/install.sh'"

printf 'Deployed %s to %s:%s with service %s\n' "$TARGET_TRIPLE" "$HOST" "$REMOTE_DIR" "$SERVICE_NAME"
if [[ "$DISABLE_LEGACY" = 1 && "$SERVICE_NAME" != shadowsocks ]]; then
	printf 'Legacy /etc/init.d/shadowsocks was stopped and disabled if present.\n'
elif [[ "$SERVICE_NAME" != shadowsocks ]]; then
	printf 'Legacy /etc/init.d/shadowsocks was not touched. Set DISABLE_LEGACY=1 to stop and disable it during deploy.\n'
fi
