#!/bin/sh
# ssrust firewall watchdog.
#
# The custom sslocal installs an `inet ssrust_redir` nftables table that redirects
# DNS (dport 53 -> :1053) and transparently proxies traffic (-> redir/tproxy
# port). On a graceful shutdown sslocal's Drop handler removes that table, and a
# panic hook removes it on panic=abort. But a SIGKILL / OOM / power loss, or
# procd giving up after the respawn budget is exhausted, leaves the table
# installed with NO process listening — which black-holes the whole LAN's DNS
# (and, under global_proxy, all LAN traffic).
#
# This loop is the backstop for those cases: whenever sslocal is not running but
# the table is still present, it deletes the table + tproxy policy routing,
# restoring the pristine pre-sslocal firewall state (LAN/router stay reachable;
# DNS falls back to the normal resolver). It is started as a second procd
# instance by /etc/init.d/shadowsocks-rust and is stopped together with the
# service, so it only acts while the service is meant to be running.

NFT_TABLE=ssrust_redir
TPROXY_MARK=0x1
TPROXY_TABLE=100
PROG=/usr/local/shadowsocks/bin/sslocal
INTERVAL=5
GRACE=3

flush_firewall() {
	command -v nft >/dev/null 2>&1 && nft delete table inet "$NFT_TABLE" 2>/dev/null
	if command -v ip >/dev/null 2>&1; then
		while ip rule del fwmark "$TPROXY_MARK" table "$TPROXY_TABLE" 2>/dev/null; do :; done
		ip route del local 0.0.0.0/0 dev lo table "$TPROXY_TABLE" 2>/dev/null
		ip -6 route del local ::/0 dev lo table "$TPROXY_TABLE" 2>/dev/null
	fi
}

sslocal_running() {
	pgrep -f "$PROG" >/dev/null 2>&1
}

table_present() {
	command -v nft >/dev/null 2>&1 && nft list table inet "$NFT_TABLE" >/dev/null 2>&1
}

while :; do
	sleep "$INTERVAL"
	sslocal_running && continue
	table_present || continue
	# sslocal absent + table present. It may merely be mid-restart, in which
	# case sslocal's own setup_nft rebuilds the table; wait out a grace period
	# and re-check before flushing to avoid racing a healthy restart.
	sleep "$GRACE"
	sslocal_running && continue
	logger -t ssrust-watchdog "sslocal not running but inet ${NFT_TABLE} present; flushing orphan firewall to restore reachability" 2>/dev/null
	flush_firewall
done
