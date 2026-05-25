#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UBUNTU_DIR="$ROOT_DIR/deploy/ubuntu"

INSTALL_DIR="${INSTALL_DIR:-/usr/local/shadowsocks}"
SERVICE_NAME="${SERVICE_NAME:-shadowsocks-client}"
FEATURES="${FEATURES:-full local-web-admin local-http-rustls}"
COPY_DATA="${COPY_DATA:-1}"
RESTART_SERVICE="${RESTART_SERVICE:-1}"
SKIP_BUILD="${SKIP_BUILD:-0}"
XRAY_PLUGIN="${XRAY_PLUGIN:-}"

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
	SUDO=()
else
	SUDO=(sudo)
fi

if [[ "$SKIP_BUILD" != 1 ]]; then
	cargo build \
		--release \
		--no-default-features \
		--features "$FEATURES" \
		--bin sslocal
fi

"${SUDO[@]}" mkdir -p "$INSTALL_DIR/bin" "$INSTALL_DIR/conf" "$INSTALL_DIR/data" "$INSTALL_DIR/logs"
"${SUDO[@]}" install -m 755 "$ROOT_DIR/target/release/sslocal" "$INSTALL_DIR/bin/sslocal"

if [[ -n "$XRAY_PLUGIN" ]]; then
	if [[ ! -x "$XRAY_PLUGIN" ]]; then
		printf 'XRAY_PLUGIN is not executable: %s\n' "$XRAY_PLUGIN" >&2
		exit 1
	fi
	"${SUDO[@]}" install -m 755 "$XRAY_PLUGIN" "$INSTALL_DIR/bin/xray-plugin"
elif [[ -x "$UBUNTU_DIR/bin/xray-plugin" ]]; then
	"${SUDO[@]}" install -m 755 "$UBUNTU_DIR/bin/xray-plugin" "$INSTALL_DIR/bin/xray-plugin"
fi

if [[ ! -s "$UBUNTU_DIR/conf/shadowsocks-client.json" ]]; then
	printf 'Missing %s\n' "$UBUNTU_DIR/conf/shadowsocks-client.json" >&2
	exit 1
fi
"${SUDO[@]}" install -m 644 "$UBUNTU_DIR/conf/shadowsocks-client.json" "$INSTALL_DIR/conf/shadowsocks-client.json"

if [[ "$COPY_DATA" = 1 && -d "$UBUNTU_DIR/data" ]]; then
	tar -C "$UBUNTU_DIR/data" -cf - . | "${SUDO[@]}" tar -C "$INSTALL_DIR/data" -xf -
fi

unit_file="$(mktemp)"
cat > "$unit_file" <<EOF
[Unit]
Description=shadowsocks-rust local client
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/bin/sslocal -c $INSTALL_DIR/conf/shadowsocks-client.json --log-without-time
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
PrivateTmp=false

[Install]
WantedBy=multi-user.target
EOF

"${SUDO[@]}" install -m 644 "$unit_file" "/etc/systemd/system/$SERVICE_NAME.service"
rm -f "$unit_file"

"${SUDO[@]}" systemctl daemon-reload
"${SUDO[@]}" systemctl enable "$SERVICE_NAME.service"

if [[ "$RESTART_SERVICE" = 1 ]]; then
	"${SUDO[@]}" systemctl restart "$SERVICE_NAME.service"
	"${SUDO[@]}" systemctl --no-pager --full status "$SERVICE_NAME.service" || true
fi

printf 'Deployed sslocal to %s with systemd service %s.service\n' "$INSTALL_DIR" "$SERVICE_NAME"
