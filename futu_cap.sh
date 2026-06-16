#!/bin/sh
# 路由器侧抓包启停器(配合 futu_classify.sh)。用法: futu_cap.sh start|stop|status
# 用 start-stop-daemon 守护(OpenWrt busybox 无 nohup)。
W=/tmp/futu
CLIENT="${CLIENT:-192.168.2.166}"
LAN="${LAN:-br-lan}"
WAN="${WAN:-eth0}"

start() {
    mkdir -p "$W"
    : > "$W/ssrust_dns.log"
    # LAN: DNS(53)+下单(443),需 53 载荷做 A 记录解析,故 -s0
    start-stop-daemon -S -b -m -p "$W/lan.pid" -x /usr/bin/tcpdump -- \
        -i "$LAN" -nn -s0 -U -w "$W/lan.pcap" host "$CLIENT" and \( port 53 or port 443 \)
    # WAN: 只需 IP 头判直连/代理,-s 96 省空间
    start-stop-daemon -S -b -m -p "$W/wan.pid" -x /usr/bin/tcpdump -- \
        -i "$WAN" -nn -s 96 -U -w "$W/wan.pcap" tcp port 443
    # ss-rust DNS 决策日志(持续跟随)
    start-stop-daemon -S -b -m -p "$W/dns.pid" -x /bin/sh -- \
        -c "logread -f >> $W/ssrust_dns.log 2>&1"
    sleep 2
    status
}

stop() {
    # 先补一份 ring buffer 快照,防止 -f 流的尾块丢失
    logread >> "$W/ssrust_dns.log" 2>&1
    for f in lan wan dns; do
        [ -f "$W/$f.pid" ] && start-stop-daemon -K -p "$W/$f.pid" 2>/dev/null
        rm -f "$W/$f.pid"
    done
    # logread 子进程可能成孤儿,补刀
    for p in $(pgrep logread 2>/dev/null); do kill "$p" 2>/dev/null; done
    sleep 1
    echo "stopped."
    ls -l "$W" 2>/dev/null
}

status() {
    echo "--- tcpdump procs ---"; pgrep -a tcpdump || echo "(none)"
    echo "--- files ---"; ls -l "$W" 2>/dev/null
    echo "--- dns log lines ---"; wc -l < "$W/ssrust_dns.log" 2>/dev/null
}

case "$1" in
    start)  start ;;
    stop)   stop ;;
    status) status ;;
    *) echo "usage: $0 start|stop|status" ;;
esac
