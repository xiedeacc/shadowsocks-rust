#!/bin/sh
# Renders deploy/openwrt/conf/ssrust-redir.nft (the static redir table) and
# applies it on OpenWrt, plus the tproxy policy routing. Installed by
# deploy/scripts/deploy_openwrt.sh, which substitutes the @@...@@ markers below
# with deploy-time values. Invoked by /etc/init.d/shadowsocks-rust on
# start/stop/restart/status.
set -eu

CONF='/usr/local/shadowsocks/conf/shadowsocks-client-master.json'
NFT_TABLE='ssrust_redir'
NFT_TEMPLATE='/usr/local/shadowsocks/conf/ssrust-redir.nft'
REDIR_PORT='12345'
DNS_PORT='1053'
SS_SERVER_IP='54.179.191.126'
TPROXY_MARK='0x1'
OUTBOUND_MARK='0xff'
TPROXY_TABLE='100'

json_first() {
	local expr value
	expr="$1"
	command -v jsonfilter >/dev/null 2>&1 || return 0
	[ -s "$CONF" ] || return 0
	value="$(jsonfilter -i "$CONF" -e "$expr" 2>/dev/null | sed -n '1p' || true)"
	printf '%s' "$value"
}

is_ipv4() {
	case "$1" in
		*.*) return 0 ;;
		*) return 1 ;;
	esac
}

require_ipv4() {
	local name value
	name="$1"
	value="$2"
	if ! is_ipv4 "$value"; then
		echo "$name must be an IPv4 address for this nft template: $value" >&2
		exit 1
	fi
}

load_config() {
	local value
	value="$(json_first '@.locals[@.protocol="redir"].local_port')"
	case "$value" in ''|*[!0-9]*) ;; *) REDIR_PORT="$value" ;; esac

	value="$(json_first '@.locals[@.protocol="dns"].local_port')"
	case "$value" in ''|*[!0-9]*) ;; *) DNS_PORT="$value" ;; esac

	value="$(json_first '@.servers[0].server')"
	[ -n "$value" ] && SS_SERVER_IP="$value"

	require_ipv4 'ssserver address' "$SS_SERVER_IP"
}

cleanup() {
	nft delete table inet "$NFT_TABLE" 2>/dev/null || true
	while ip rule del fwmark "$TPROXY_MARK" table "$TPROXY_TABLE" 2>/dev/null; do :; done
	ip route del local 0.0.0.0/0 dev lo table "$TPROXY_TABLE" 2>/dev/null || true
	ip -6 route del local ::/0 dev lo table "$TPROXY_TABLE" 2>/dev/null || true
}

render_rules() {
	local output
	if [ ! -s "$NFT_TEMPLATE" ]; then
		echo "missing nft template: $NFT_TEMPLATE" >&2
		exit 1
	fi
	output="/tmp/$NFT_TABLE.rendered.$$.nft"
	sed \
		-e "s#__NFT_TABLE__#$NFT_TABLE#g" \
		-e "s#__REDIR_PORT__#$REDIR_PORT#g" \
		-e "s#__DNS_PORT__#$DNS_PORT#g" \
		-e "s#__SS_SERVER_IP__#$SS_SERVER_IP#g" \
		-e "s#__TPROXY_MARK__#$TPROXY_MARK#g" \
		-e "s#__OUTBOUND_MARK__#$OUTBOUND_MARK#g" \
		"$NFT_TEMPLATE" > "$output"
	printf '%s' "$output"
}

install_rules() {
	cleanup
	load_config

	modprobe nft_tproxy 2>/dev/null || true
	modprobe nf_tproxy_ipv4 2>/dev/null || true
	modprobe nf_tproxy_ipv6 2>/dev/null || true

	ip rule add fwmark "$TPROXY_MARK" table "$TPROXY_TABLE" priority 100 2>/dev/null || true
	ip route replace local 0.0.0.0/0 dev lo table "$TPROXY_TABLE"
	ip -6 rule add fwmark "$TPROXY_MARK" table "$TPROXY_TABLE" priority 100 2>/dev/null || true
	ip -6 route replace local ::/0 dev lo table "$TPROXY_TABLE" 2>/dev/null || true

	rules_file="$(render_rules)"
	nft -f "$rules_file"
	rm -f "$rules_file"

	echo "installed nft table $NFT_TABLE: redir=$REDIR_PORT dns=$DNS_PORT server_ip=$SS_SERVER_IP"
}

case "${1:-start}" in
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
		nft list table inet "$NFT_TABLE"
		;;
	*)
		echo "usage: $0 {start|stop|restart|status}" >&2
		exit 2
		;;
esac
