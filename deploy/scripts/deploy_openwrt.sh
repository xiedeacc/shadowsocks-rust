#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OPENWRT_DIR="$ROOT_DIR/deploy/openwrt"
UBUNTU_DATA_FALLBACK="$ROOT_DIR/deploy/ubuntu/arm64/data"

HOST="${HOST:-root@192.168.2.1}"
SSH_PORT="${SSH_PORT:-10022}"
REMOTE_DIR="${REMOTE_DIR:-/usr/local/shadowsocks}"
SERVICE_NAME="${SERVICE_NAME:-shadowsocks-rust}"
REMOTE_TMP="${REMOTE_TMP:-/tmp/shadowsocks-rust-deploy}"
FEATURES="${FEATURES:-full local-web-admin local-http-rustls}"
TARGET_TRIPLE="${TARGET_TRIPLE:-}"
OPENWRT_TOOLCHAIN="${OPENWRT_TOOLCHAIN:-}"
DISABLE_LEGACY="${DISABLE_LEGACY:-0}"

ssh_cmd() {
	ssh -o ConnectTimeout=8 -p "$SSH_PORT" "$HOST" "$@"
}

scp_cmd() {
	scp -O -P "$SSH_PORT" "$@"
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

if [[ -z "$TARGET_TRIPLE" ]]; then
	TARGET_TRIPLE="$(detect_target)"
fi

if ! rustup target list --installed | grep -qx "$TARGET_TRIPLE"; then
	rustup target add "$TARGET_TRIPLE"
fi

if [[ -n "$OPENWRT_TOOLCHAIN" ]]; then
	TOOLCHAIN_BIN="$OPENWRT_TOOLCHAIN/bin"
	if [[ ! -d "$TOOLCHAIN_BIN" ]]; then
		printf 'OpenWrt toolchain bin directory not found: %s\n' "$TOOLCHAIN_BIN" >&2
		exit 1
	fi
	export PATH="$TOOLCHAIN_BIN:$PATH"
	case "$TARGET_TRIPLE" in
		aarch64-unknown-linux-musl)
			export CC_aarch64_unknown_linux_musl="${CC_aarch64_unknown_linux_musl:-$TOOLCHAIN_BIN/aarch64-openwrt-linux-musl-gcc}"
			export AR_aarch64_unknown_linux_musl="${AR_aarch64_unknown_linux_musl:-$TOOLCHAIN_BIN/aarch64-openwrt-linux-musl-gcc-ar}"
			export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER:-$TOOLCHAIN_BIN/aarch64-openwrt-linux-musl-gcc}"
			;;
	esac
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

mkdir -p \"\$REMOTE_DIR/bin\" \"\$REMOTE_DIR/conf\" \"\$REMOTE_DIR/data\" \"\$REMOTE_DIR/logs\"
cp -f \"\$REMOTE_TMP/sslocal\" \"\$REMOTE_DIR/bin/sslocal\"
chmod 755 \"\$REMOTE_DIR/bin/sslocal\"
cp -f \"\$REMOTE_TMP/shadowsocks-client.json\" \"\$REMOTE_DIR/conf/shadowsocks-client.json\"
chmod 644 \"\$REMOTE_DIR/conf/shadowsocks-client.json\"
find \"\$REMOTE_TMP\" -maxdepth 1 -type f \\
	! -name sslocal \\
	! -name shadowsocks-client.json \\
	! -name \"\$SERVICE_NAME.init\" \\
	! -name install.sh \\
	-exec cp -f {} \"\$REMOTE_DIR/data/\" \\;
if [ -d \"\$REMOTE_TMP/source\" ]; then
	mkdir -p \"\$REMOTE_DIR/data/source\"
	cp -rf \"\$REMOTE_TMP/source/.\" \"\$REMOTE_DIR/data/source/\"
fi
cp -f \"\$REMOTE_TMP/\$SERVICE_NAME.init\" \"/etc/init.d/\$SERVICE_NAME\"
chmod 755 \"/etc/init.d/\$SERVICE_NAME\"

if [ \"\$DISABLE_LEGACY\" = 1 ] && [ -x /etc/init.d/shadowsocks ]; then
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
printf 'Legacy /etc/init.d/shadowsocks was not touched. Set DISABLE_LEGACY=1 to stop and disable it during deploy.\n'
