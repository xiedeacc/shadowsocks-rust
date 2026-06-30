#!/usr/bin/env bash
# deploy_ubuntu.sh — rebuild and redeploy the locally-modified
# shadowsocks-rust binary on this Ubuntu workstation, then wipe the
# logs/ directory so the next session starts on a clean slate.
#
# Design contract (per user instruction):
#   * sslocal binary  — rebuilt and OVERWRITTEN every invocation.
#   * everything else — installed ONLY IF MISSING. Conf, data,
#                       xray-plugin, and systemd units are all treated
#                       as one-time setup. The script never clobbers
#                       them once the operator has touched them.
#   * logs/           — cleaned at the end (after service restart) so
#                       each deploy starts with empty
#                       $INSTALL_DIR/logs/*.log and dumps/.
#
# Subcommands & env knobs are kept minimal on purpose. Override via
# environment, e.g. SKIP_BUILD=1 ./deploy_ubuntu.sh to redeploy the
# already-built binary without rerunning cargo.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPLOY_DIR="$ROOT_DIR/deploy"
DEPLOY_BIN_DIR="$DEPLOY_DIR/bin"
DEPLOY_CONF_DIR="$DEPLOY_DIR/conf"
DEPLOY_DATA_DIR="$DEPLOY_DIR/data"

INSTALL_DIR="${INSTALL_DIR:-/usr/local/shadowsocks}"
SERVICE_NAME="${SERVICE_NAME:-shadowsocks-client}"
FEATURES="${FEATURES:-full local-web-admin local-http-rustls}"
SKIP_BUILD="${SKIP_BUILD:-0}"
RESTART_SERVICE="${RESTART_SERVICE:-1}"
APPLY_SYSCTL="${APPLY_SYSCTL:-1}"
NOFILE_LIMIT="${NOFILE_LIMIT:-1048576}"
CLEAN_LOGS="${CLEAN_LOGS:-1}"

CLEANUP_ONLY=0
while [[ $# -gt 0 ]]; do
	case "$1" in
		--cleanup|--cleanup-nft)
			CLEANUP_ONLY=1; shift ;;
		-h|--help)
			sed -n '2,/^set -euo pipefail/p' "$0"
			printf '\nFlags:\n  --cleanup    stop services and wipe the inet ssrust_redir nft table, then exit.\n'
			exit 0 ;;
		*) printf 'unknown arg: %s\n' "$1" >&2; exit 2 ;;
	esac
done

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
	SUDO=()
else
	SUDO=(sudo)
fi

log() { printf '[deploy] %s\n' "$*"; }

# Best-effort wipe of any firewall remnants left behind by a previous
# sslocal run (the single nft table inet ssrust_redir). Safe to run any
# number of times; a missing table is silently ignored. We stop the
# services first so the running process cannot recreate the table mid-flush.
cleanup_firewall_state() {
	log "stopping services before firewall cleanup"
	"${SUDO[@]}" systemctl stop "$SERVICE_NAME.service"       >/dev/null 2>&1 || true

	if command -v nft >/dev/null 2>&1; then
		if "${SUDO[@]}" nft list table inet ssrust_redir >/dev/null 2>&1; then
			log "deleting nft table: inet ssrust_redir"
			"${SUDO[@]}" nft delete table inet ssrust_redir || true
		else
			log "no stale nft table inet ssrust_redir"
		fi
	else
		log "nft not installed; skipping nftables cleanup"
	fi
}

if [[ "$CLEANUP_ONLY" = 1 ]]; then
	cleanup_firewall_state
	log "cleanup complete; not redeploying. Run without --cleanup to redeploy."
	exit 0
fi

# Install if missing — never overwrite. Used for everything except the
# sslocal binary itself.
install_if_missing() {
	local src="$1" dst="$2" mode="${3:-755}"
	if [[ ! -e "$src" ]]; then
		log "  skip $dst (source $src not present)"
		return 0
	fi
	if [[ -e "$dst" ]]; then
		log "  keep $dst (already present)"
		return 0
	fi
	"${SUDO[@]}" install -m "$mode" "$src" "$dst"
	log "  installed $dst"
}

# 1) Build sslocal.
if [[ "$SKIP_BUILD" != 1 ]]; then
	log "building sslocal (features: $FEATURES)"
	cargo build \
		--release \
		--no-default-features \
		--features "$FEATURES" \
		--bin sslocal
fi

mkdir -p "$DEPLOY_BIN_DIR"
BUILD_BINARY="$ROOT_DIR/target/release/sslocal"
STAGED_BINARY="$DEPLOY_BIN_DIR/sslocal_ubuntu"
if [[ ! -x "$BUILD_BINARY" ]]; then
	log "ERROR: $BUILD_BINARY not found; run without SKIP_BUILD=1 first" >&2
	exit 1
fi
install -m 755 "$BUILD_BINARY" "$STAGED_BINARY"

# 2) Layout — make dirs only.
"${SUDO[@]}" mkdir -p \
	"$INSTALL_DIR/bin" \
	"$INSTALL_DIR/conf" \
	"$INSTALL_DIR/data" \
	"$INSTALL_DIR/logs" \
	"$INSTALL_DIR/logs/dumps"

# 3) sslocal binary — ALWAYS reinstall.
"${SUDO[@]}" install -m 755 "$STAGED_BINARY" "$INSTALL_DIR/bin/sslocal"
log "installed $INSTALL_DIR/bin/sslocal ($("$STAGED_BINARY" --version 2>&1))"

# 4) Everything else — install-if-missing only.
log "syncing auxiliary files (install-if-missing)"
install_if_missing "$DEPLOY_BIN_DIR/xray-plugin" "$INSTALL_DIR/bin/xray-plugin" 755
install_if_missing "$DEPLOY_CONF_DIR/shadowsocks-client.json" "$INSTALL_DIR/conf/shadowsocks-client.json" 644

# Conf is the source of truth — refuse to start without it.
if [[ ! -s "$INSTALL_DIR/conf/shadowsocks-client.json" ]]; then
	log "ERROR: $INSTALL_DIR/conf/shadowsocks-client.json missing and no template at $DEPLOY_CONF_DIR/" >&2
	exit 1
fi

# Data dir — seed only if completely empty.
if [[ -d "$DEPLOY_DATA_DIR" && -z "$(ls -A "$INSTALL_DIR/data" 2>/dev/null)" ]]; then
	log "data dir empty — seeding from $DEPLOY_DATA_DIR"
	tar -C "$DEPLOY_DATA_DIR" -cf - . | "${SUDO[@]}" tar -C "$INSTALL_DIR/data" -xf -
fi

# 5) Sysctl tuning — mirrors deploy/conf/shadowsocks-rust.init
#    apply_network_tuning(). Volatile (no /etc/sysctl.d) on purpose:
#    this is a debugging workstation, not a permanent gateway.
if [[ "$APPLY_SYSCTL" = 1 ]]; then
	log "applying sysctl tuning"
	"${SUDO[@]}" sysctl -w net.ipv4.tcp_fastopen=3                   >/dev/null 2>&1 || true
	"${SUDO[@]}" sysctl -w net.core.rmem_max=16777216                >/dev/null 2>&1 || true
	"${SUDO[@]}" sysctl -w net.core.wmem_max=16777216                >/dev/null 2>&1 || true
	"${SUDO[@]}" sysctl -w 'net.ipv4.tcp_rmem=4096 262144 16777216'  >/dev/null 2>&1 || true
	"${SUDO[@]}" sysctl -w 'net.ipv4.tcp_wmem=4096 262144 16777216'  >/dev/null 2>&1 || true
	"${SUDO[@]}" sysctl -w net.ipv4.tcp_slow_start_after_idle=0      >/dev/null 2>&1 || true
	"${SUDO[@]}" sysctl -w net.ipv4.tcp_notsent_lowat=131072         >/dev/null 2>&1 || true
	"${SUDO[@]}" sysctl -w net.ipv4.tcp_mtu_probing=1                >/dev/null 2>&1 || true
	"${SUDO[@]}" sysctl -w net.core.somaxconn=8192                   >/dev/null 2>&1 || true
	"${SUDO[@]}" sysctl -w net.netfilter.nf_conntrack_max=262144     >/dev/null 2>&1 || true
	"${SUDO[@]}" sysctl -w net.ipv4.tcp_tw_reuse=1                   >/dev/null 2>&1 || true
fi

# 6) Systemd units — install-if-missing. Operator can `systemctl edit`
#    them locally and we won't trample those overrides.
write_unit_if_missing() {
	local path="$1" content="$2" tmp
	if [[ -e "$path" ]]; then
		log "  keep $path (already present)"
		return 0
	fi
	tmp="$(mktemp)"
	printf '%s\n' "$content" >"$tmp"
	"${SUDO[@]}" install -m 644 "$tmp" "$path"
	rm -f "$tmp"
	log "  installed $path"
}

write_unit_if_missing "/etc/systemd/system/$SERVICE_NAME.service" "[Unit]
Description=shadowsocks-rust local client (transparent proxy + dns intercept)
Wants=network-online.target
After=network-online.target nss-lookup.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/bin/sslocal -c $INSTALL_DIR/conf/shadowsocks-client.json --nofile $NOFILE_LIMIT --log-without-time
Restart=on-failure
RestartSec=3
LimitNOFILE=$NOFILE_LIMIT
PrivateTmp=false
StandardOutput=append:$INSTALL_DIR/logs/shadowsocks-client.stdout.log
StandardError=append:$INSTALL_DIR/logs/shadowsocks-client.stderr.log

[Install]
WantedBy=multi-user.target
"

"${SUDO[@]}" systemctl daemon-reload
"${SUDO[@]}" systemctl enable "$SERVICE_NAME.service" >/dev/null 2>&1 || true

# 7) Restart cycle with log wipe in between.
#
# Order matters: stop everything first, then wipe logs, then start
# again — this guarantees the new run's first log line is the first
# entry in $INSTALL_DIR/logs/* (no stale "[deploy] tail" left over
# from a previous run).
if [[ "$RESTART_SERVICE" = 1 ]]; then
	log "stopping services"
	"${SUDO[@]}" systemctl stop "$SERVICE_NAME.service"       >/dev/null 2>&1 || true
fi

if [[ "$CLEAN_LOGS" = 1 ]]; then
	log "cleaning logs dir $INSTALL_DIR/logs"
	# Wipe regular files in $INSTALL_DIR/logs/ but keep the dumps/
	# subdirectory layout. Then wipe its contents too. The two-step
	# form is paranoia: a `rm -rf $INSTALL_DIR/logs/*` with the wrong
	# var would be catastrophic, so we sanity-check the prefix first.
	if [[ "$INSTALL_DIR" = "/" || -z "$INSTALL_DIR" ]]; then
		log "refusing to clean logs: INSTALL_DIR='$INSTALL_DIR' looks unsafe" >&2
	else
		"${SUDO[@]}" find "$INSTALL_DIR/logs" -mindepth 1 -maxdepth 1 -type f -delete 2>/dev/null || true
		"${SUDO[@]}" find "$INSTALL_DIR/logs/dumps" -mindepth 1 -delete 2>/dev/null || true
		"${SUDO[@]}" mkdir -p "$INSTALL_DIR/logs/dumps"
	fi
fi

if [[ "$RESTART_SERVICE" = 1 ]]; then
	log "starting $SERVICE_NAME"
	"${SUDO[@]}" systemctl start "$SERVICE_NAME.service"
	sleep 2
	"${SUDO[@]}" systemctl --no-pager --full status "$SERVICE_NAME.service" || true
fi

cat <<EOF

Deployed sslocal binary to $INSTALL_DIR/bin/sslocal.
Auxiliary files (conf, data, scripts, systemd units) were only created
if missing — existing copies were left untouched.

Logs were wiped: $INSTALL_DIR/logs/

Tail / inspect:
  journalctl -u $SERVICE_NAME.service -f
  ls -lt $INSTALL_DIR/logs/dumps/ | head
  curl -sS http://127.0.0.1:9090/api/dns/cache/stats | jq .
EOF
