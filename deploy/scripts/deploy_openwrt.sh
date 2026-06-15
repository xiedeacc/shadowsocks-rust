#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OPENWRT_DIR="$ROOT_DIR/deploy/openwrt"
UBUNTU_DATA_FALLBACK="$ROOT_DIR/deploy/ubuntu/arm64/data"

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
               flush the inet ssrust_dns nft table + iptables remnants,
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
#   * delete `inet ssrust_dns` (the only nft table sslocal ever creates),
#   * delete any iptables nat rules redirecting dport 53 to localhost
#     (the iptables fallback path uses these).
# Idempotent; missing services / tables / rules are silently ignored.
cleanup_remote_firewall() {
	ssh_cmd "set -e
		if [ -x /etc/init.d/$SERVICE_NAME ]; then
			echo '[cleanup] stopping $SERVICE_NAME'
			/etc/init.d/$SERVICE_NAME stop 2>/dev/null || true
		fi
		if command -v nft >/dev/null 2>&1; then
			if nft list table inet ssrust_dns >/dev/null 2>&1; then
				echo '[cleanup] deleting nft table inet ssrust_dns'
				nft delete table inet ssrust_dns || true
			else
				echo '[cleanup] no stale nft table inet ssrust_dns'
			fi
		fi
		if command -v iptables >/dev/null 2>&1; then
			for chain in OUTPUT PREROUTING; do
				while iptables -t nat -L \$chain -n --line-numbers 2>/dev/null \
					| awk '/dpt:53/ && (/REDIRECT|DNAT/) {print \$1; exit}' | grep -q .; do
					line=\$(iptables -t nat -L \$chain -n --line-numbers 2>/dev/null \
						| awk '/dpt:53/ && (/REDIRECT|DNAT/) {print \$1; exit}')
					[ -z \"\$line\" ] && break
					echo \"[cleanup] iptables -t nat -D \$chain \$line\"
					iptables -t nat -D \$chain \$line || break
				done
			done
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

mkdir -p "$OPENWRT_DIR/bin" "$OPENWRT_DIR/conf" "$OPENWRT_DIR/data" "$OPENWRT_DIR/logs"
install -m 755 "$ROOT_DIR/target/$TARGET_TRIPLE/release/sslocal" "$OPENWRT_DIR/bin/sslocal"

if [[ ! -s "$OPENWRT_DIR/conf/shadowsocks-client.json" ]]; then
	printf 'Missing %s\n' "$OPENWRT_DIR/conf/shadowsocks-client.json" >&2
	exit 1
fi

DATA_SOURCE_DIR="$OPENWRT_DIR/data"
if [[ -d "$UBUNTU_DATA_FALLBACK" ]] && ! find "$DATA_SOURCE_DIR" -type f -print -quit | grep -q .; then
	DATA_SOURCE_DIR="$UBUNTU_DATA_FALLBACK"
fi

ssh_cmd "mkdir -p '$REMOTE_TMP' '$REMOTE_DIR/bin' '$REMOTE_DIR/conf' '$REMOTE_DIR/data' '$REMOTE_DIR/logs'"
scp_cmd "$OPENWRT_DIR/bin/sslocal" "$HOST:$REMOTE_TMP/sslocal"
scp_cmd "$OPENWRT_DIR/conf/shadowsocks-client.json" "$HOST:$REMOTE_TMP/shadowsocks-client.json"
scp_cmd "$OPENWRT_DIR/conf/shadowsocks-rust.init" "$HOST:$REMOTE_TMP/$SERVICE_NAME.init"

if [[ -d "$DATA_SOURCE_DIR" ]]; then
	tar -C "$DATA_SOURCE_DIR" -cf - . | ssh_cmd "tar -C '$REMOTE_TMP' -xf -"
fi

ssh_cmd "cat > '$REMOTE_TMP/install.sh' <<'EOS'
set -eu
REMOTE_DIR='$REMOTE_DIR'
SERVICE_NAME='$SERVICE_NAME'
REMOTE_TMP='$REMOTE_TMP'
DISABLE_LEGACY='$DISABLE_LEGACY'

mkdir -p \"\$REMOTE_DIR/bin\" \"\$REMOTE_DIR/conf\" \"\$REMOTE_DIR/data\" \"\$REMOTE_DIR/data/temp\" \"\$REMOTE_DIR/logs\"
cp -f \"\$REMOTE_TMP/sslocal\" \"\$REMOTE_DIR/bin/sslocal\"
chmod 755 \"\$REMOTE_DIR/bin/sslocal\"
if [ ! -s \"\$REMOTE_DIR/conf/shadowsocks-client.json\" ]; then
	cp -f \"\$REMOTE_TMP/shadowsocks-client.json\" \"\$REMOTE_DIR/conf/shadowsocks-client.json\"
fi
chmod 644 \"\$REMOTE_DIR/conf/shadowsocks-client.json\"
find \"\$REMOTE_TMP\" -maxdepth 1 -type f \\
	! -name sslocal \\
	! -name shadowsocks-client.json \\
	! -name \"\$SERVICE_NAME.init\" \\
	! -name install.sh \\
	! -name direct_ip.txt \\
	! -name direct_domain.txt \\
	! -name proxy_ip.txt \\
	! -name proxy_domain.txt \\
	! -name direct_ip.temp \\
	! -name direct_domain.temp \\
	! -name proxy_ip.temp \\
	! -name proxy_domain.temp \\
	! -name record.txt \\
	-exec cp -f {} \"\$REMOTE_DIR/data/\" \\;
for rule_file in direct_ip.txt direct_domain.txt proxy_ip.txt proxy_domain.txt \\
	direct_ip.temp direct_domain.temp proxy_ip.temp proxy_domain.temp record.txt; do
	if [ ! -e \"\$REMOTE_DIR/data/\$rule_file\" ] && [ -e \"\$REMOTE_TMP/\$rule_file\" ]; then
		cp -f \"\$REMOTE_TMP/\$rule_file\" \"\$REMOTE_DIR/data/\$rule_file\"
	fi
done
if [ -d \"\$REMOTE_TMP/temp\" ]; then
	mkdir -p \"\$REMOTE_DIR/data/temp\"
	find \"\$REMOTE_TMP/temp\" -maxdepth 1 -type f | while IFS= read -r temp_file; do
		temp_name=\$(basename \"\$temp_file\")
		if [ ! -e \"\$REMOTE_DIR/data/temp/\$temp_name\" ]; then
			cp -f \"\$temp_file\" \"\$REMOTE_DIR/data/temp/\$temp_name\"
		fi
	done
fi
if [ -d \"\$REMOTE_TMP/source\" ]; then
	mkdir -p \"\$REMOTE_DIR/data/source\"
	cp -rf \"\$REMOTE_TMP/source/.\" \"\$REMOTE_DIR/data/source/\"
fi
cp -f \"\$REMOTE_TMP/\$SERVICE_NAME.init\" \"/etc/init.d/\$SERVICE_NAME\"
chmod 755 \"/etc/init.d/\$SERVICE_NAME\"

for removed_service in sslocal-watch sslocal-probe; do
	if [ -x \"/etc/init.d/\$removed_service\" ]; then
		\"/etc/init.d/\$removed_service\" stop || true
		\"/etc/init.d/\$removed_service\" disable || true
	fi
	rm -f \"/etc/init.d/\$removed_service\" /etc/rc.d/*\"\$removed_service\"* \"\$REMOTE_DIR/bin/\$removed_service.sh\"
done

for legacy_service in shadowsocks-rust; do
	if [ \"\$SERVICE_NAME\" != \"\$legacy_service\" ] && [ -x \"/etc/init.d/\$legacy_service\" ]; then
		\"/etc/init.d/\$legacy_service\" stop || true
		\"/etc/init.d/\$legacy_service\" disable || true
	fi
done

if [ \"\$DISABLE_LEGACY\" = 1 ] && [ \"\$SERVICE_NAME\" != shadowsocks ] && [ -x /etc/init.d/shadowsocks ]; then
	/etc/init.d/shadowsocks stop || true
	/etc/init.d/shadowsocks disable || true
fi

/etc/init.d/\$SERVICE_NAME enable
/etc/init.d/\$SERVICE_NAME restart
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
