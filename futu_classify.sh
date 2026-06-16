#!/bin/sh
# futu_classify.sh — 判定富途下单服务器 IP 是「DNS 驱动」还是「API 驱动」获取的,
# 并判定每个下单 IP 最终是否走了代理。整套在 OpenWrt 路由器上跑。
#
# 原理:
#   下单 IP 来源三档 ——
#     SS-DNS   : 该 IP 作为 A 记录出现在 ss-rust 的 DNS 决策日志里
#                → DNS 驱动,且经过了 ss-rust,域名规则可学习 → 域名方案可行
#     OTHER-DNS: 该 IP 出现在 LAN 抓到的明文 :53 应答里,但 ss-rust 日志没有
#                → 是 DNS,但客户端绕过了 ss-rust(用了别的解析器)→ 该修「客户端 DNS 指向」
#     NON-DNS  : 两边都查不到该 IP
#                → API 下发(TLS 体内,明文 grep 不到)/ DoH / 硬编码 → 只能 IP 路由
#   是否走代理 ——
#     WAN 上还能直接看到去这个下单 IP 的包  → DIRECT(没走代理)
#     WAN 上看不到(只看到去 SS server 的)   → PROXIED(走了隧道)
#
# 用法:
#   ./futu_classify.sh deps      # 安装依赖(apk add tcpdump)
#   ./futu_classify.sh capture   # 起采集,提示你操作富途,回车后停采集
#   ./futu_classify.sh analyze   # 对已采集文件做分类,打印报告
#   ./futu_classify.sh run       # = capture 然后 analyze(推荐)
#
# 可用环境变量覆盖(都可选):
#   CLIENT      Windows 客户端 IP            (默认 192.168.2.166)
#   LAN_IF      LAN 桥接口                   (默认 br-lan)
#   WAN_IF      WAN 接口                     (默认自动探测)
#   WORKDIR     采集/中间文件目录            (默认 /tmp/futu)
#   SSRUST_LOG  ss-rust 日志文件路径;留空则用 logread
#   NFT_TABLE   nft 表名                     (默认 "inet ssrust_dns")
#   NFT_SET4    nft proxy IPv4 set 名        (默认 proxy4)
#   FOCUS_IPS   逗号/空格分隔的下单 IP 列表;给了就只重点分析这些
#               (来自 Windows 的 futu_conns.log;不给则用 LAN 抓包自动推断)
#   DURATION    采集秒数;给了就 sleep 这么久而不是等回车(便于无人值守)
#
# 注意:OpenWrt 25.12 用 apk,本脚本已按 apk 处理。

CLIENT="${CLIENT:-192.168.2.166}"
LAN_IF="${LAN_IF:-br-lan}"
WAN_IF="${WAN_IF:-$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)}"
WORKDIR="${WORKDIR:-/tmp/futu}"
SSRUST_LOG="${SSRUST_LOG:-}"
NFT_TABLE="${NFT_TABLE:-inet ssrust_dns}"
NFT_SET4="${NFT_SET4:-proxy4}"
FOCUS_IPS="${FOCUS_IPS:-}"
DURATION="${DURATION:-}"

LAN_PCAP="$WORKDIR/lan.pcap"
WAN_PCAP="$WORKDIR/wan.pcap"
DNS_LOG="$WORKDIR/ssrust_dns.log"
PID_FILE="$WORKDIR/pids"

IPV4RE='[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'

log() { printf '%s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

need_tcpdump() {
    command -v tcpdump >/dev/null 2>&1 && return 0
    log "tcpdump 未安装,尝试 apk add tcpdump ..."
    apk add tcpdump 2>/dev/null || apk add tcpdump-mini 2>/dev/null \
        || die "tcpdump 安装失败,请手动 'apk add tcpdump'"
}

cmd_deps() {
    need_tcpdump
    log "tcpdump: $(command -v tcpdump)"
    command -v nft >/dev/null 2>&1 && log "nft: $(command -v nft)" || log "警告: 无 nft,proxy4 检查将跳过"
}

start_dns_log() {
    if [ -n "$SSRUST_LOG" ]; then
        [ -f "$SSRUST_LOG" ] || die "SSRUST_LOG 指定的文件不存在: $SSRUST_LOG"
        log "DNS 日志来源: tail -F $SSRUST_LOG"
        ( tail -n0 -F "$SSRUST_LOG" 2>/dev/null | grep -i 'dns ' > "$DNS_LOG" ) &
    else
        command -v logread >/dev/null 2>&1 || die "无 logread,且未设 SSRUST_LOG"
        log "DNS 日志来源: logread -f (过滤 'dns ')"
        ( logread -f 2>/dev/null | grep -i 'dns ' > "$DNS_LOG" ) &
    fi
    echo "$!" >> "$PID_FILE"
}

cmd_capture() {
    need_tcpdump
    [ -n "$WAN_IF" ] || log "警告: 未能自动探测 WAN_IF,请用 WAN_IF=... 指定(否则无法判定是否走代理)"
    mkdir -p "$WORKDIR"
    : > "$PID_FILE"
    : > "$DNS_LOG"

    log "================ 采集配置 ================"
    log "  CLIENT = $CLIENT"
    log "  LAN_IF = $LAN_IF   WAN_IF = ${WAN_IF:-<未设>}"
    log "  WORKDIR= $WORKDIR"
    log "=========================================="

    # LAN 侧:DNS(53) + 下单(443),留全量证据
    tcpdump -i "$LAN_IF" -nn -s0 -U -w "$LAN_PCAP" \
        "host $CLIENT and (port 53 or port 443)" >/dev/null 2>&1 &
    echo "$!" >> "$PID_FILE"

    # WAN 侧:443,判定是否走代理的决定性证据
    if [ -n "$WAN_IF" ]; then
        tcpdump -i "$WAN_IF" -nn -s0 -U -w "$WAN_PCAP" \
            "tcp port 443" >/dev/null 2>&1 &
        echo "$!" >> "$PID_FILE"
    fi

    # ss-rust DNS 决策日志
    start_dns_log

    sleep 1
    log ""
    log ">>> 采集已启动。现在请在 Windows 上按顺序操作:"
    log "      1) 彻底退出富途(杀掉所有 FTNN 进程)"
    log "      2) ipconfig /flushdns"
    log "      3) 启动富途 → 登录 → 进交易"
    log "      4) 挂一笔远离现价、可立即撤销的限价单,然后撤单"
    log "    (建议同时在 Windows 跑 futu_conn_logger.ps1 记录下单 IP)"
    log ""

    if [ -n "$DURATION" ]; then
        log ">>> 无人值守模式:采集 $DURATION 秒 ..."
        sleep "$DURATION"
    else
        log ">>> 操作完成后,在这里按【回车】停止采集。"
        read _dummy
    fi

    stop_capture
    log ">>> 采集已停止。"
    log "    LAN pcap : $LAN_PCAP ($(wc -c < "$LAN_PCAP" 2>/dev/null) bytes)"
    [ -n "$WAN_IF" ] && log "    WAN pcap : $WAN_PCAP ($(wc -c < "$WAN_PCAP" 2>/dev/null) bytes)"
    log "    DNS log  : $DNS_LOG ($(wc -l < "$DNS_LOG" 2>/dev/null) lines)"
}

stop_capture() {
    [ -f "$PID_FILE" ] || return 0
    while read p; do
        [ -n "$p" ] && kill "$p" 2>/dev/null
    done < "$PID_FILE"
    # 给 tcpdump 落盘的时间
    sleep 1
    # tail -F / logread 可能有子进程,补一刀
    pkill -f "tail -n0 -F $SSRUST_LOG" 2>/dev/null
    rm -f "$PID_FILE"
}

# 从 ss-rust 日志提取  "IP<TAB>domain"  (经过 ss-rust 的 DNS 结果)
build_ssrust_dns() {
    [ -s "$DNS_LOG" ] || { : > "$WORKDIR/ssrust_ip_domain.txt"; return; }
    awk '
      /results=\[/ {
        dom="?"
        for (i=1;i<=NF;i++) if ($i=="result"||$i=="hit") { dom=$(i+1); break }
        sub(/\.$/,"",dom)
        line=$0
        while (match(line, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) {
          ip=substr(line,RSTART,RLENGTH)
          print ip "\t" dom
          line=substr(line, RSTART+RLENGTH)
        }
      }
    ' "$DNS_LOG" | sort -u > "$WORKDIR/ssrust_ip_domain.txt"
}

# 从 LAN pcap 的 :53 应答里提取所有 A 记录 IP(可能含绕过 ss-rust 的解析)
build_lan_dns() {
    [ -s "$LAN_PCAP" ] || { : > "$WORKDIR/landns_ips.txt"; return; }
    tcpdump -nnr "$LAN_PCAP" "udp port 53 or tcp port 53" 2>/dev/null | awk '
      {
        line=$0
        # tcpdump 把 A 记录打印成 " A 1.2.3.4"; 用前导空格/逗号排除 AAAA
        while (match(line, /[ ,]A [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) {
          seg=substr(line,RSTART,RLENGTH)
          if (match(seg, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/))
            print substr(seg,RSTART,RLENGTH)
          line=substr(line, RSTART+RLENGTH)
        }
      }
    ' | sort -u > "$WORKDIR/landns_ips.txt"
}

# 候选下单 IP 集合 O:优先用 FOCUS_IPS,否则从 LAN pcap 推断(客户端 -> 远端:443 的 SYN)
build_order_ips() {
    if [ -n "$FOCUS_IPS" ]; then
        printf '%s\n' "$FOCUS_IPS" \
            | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u > "$WORKDIR/order_ips.txt"
        return
    fi
    [ -s "$LAN_PCAP" ] || { : > "$WORKDIR/order_ips.txt"; return; }
    tcpdump -nnr "$LAN_PCAP" \
        "src $CLIENT and tcp dst port 443 and (tcp[tcpflags] & (tcp-syn|tcp-ack)) == tcp-syn" 2>/dev/null \
      | awk '{ for (i=1;i<=NF;i++) if ($i==">") { d=$(i+1); sub(/:$/,"",d); sub(/\.[0-9]+$/,"",d);
               if (d ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print d } }' \
      | sort -u > "$WORKDIR/order_ips.txt"
}

# WAN 上出现过的远端 IP(用于判 DIRECT)
build_wan_ips() {
    if [ -n "$WAN_IF" ] && [ -s "$WAN_PCAP" ]; then
        tcpdump -nnr "$WAN_PCAP" "tcp port 443" 2>/dev/null \
          | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u > "$WORKDIR/wan_ips.txt"
    else
        : > "$WORKDIR/wan_ips.txt"
    fi
}

# nft proxy4 集合里的精确 IP(CIDR 行单独提示)
build_nft_proxy4() {
    if command -v nft >/dev/null 2>&1; then
        nft list set $NFT_TABLE $NFT_SET4 2>/dev/null \
          | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | sort -u > "$WORKDIR/nft_proxy4.txt"
    else
        : > "$WORKDIR/nft_proxy4.txt"
    fi
}

cmd_analyze() {
    [ -s "$LAN_PCAP" ] || [ -s "$DNS_LOG" ] || die "找不到采集数据,请先跑 capture(WORKDIR=$WORKDIR)"
    build_ssrust_dns
    build_lan_dns
    build_order_ips
    build_wan_ips
    build_nft_proxy4

    ORDER="$WORKDIR/order_ips.txt"
    n_order=$(wc -l < "$ORDER" 2>/dev/null)
    [ "${n_order:-0}" -gt 0 ] 2>/dev/null || die "未发现任何候选下单 IP。请确认采集期间确实触发了富途连接,或用 FOCUS_IPS= 指定。"

    wan_seen=$( [ -s "$WORKDIR/wan_ips.txt" ] && echo yes || echo no )
    nft_seen=$( [ -s "$WORKDIR/nft_proxy4.txt" ] && echo yes || echo no )

    echo
    echo "================== 富途下单 IP 分类报告 =================="
    echo "候选下单 IP 数: $n_order   来源: $( [ -n "$FOCUS_IPS" ] && echo 'FOCUS_IPS(Windows 实测)' || echo 'LAN 抓包推断' )"
    echo "WAN 抓包: $wan_seen    nft $NFT_SET4: $nft_seen"
    echo "---------------------------------------------------------"
    printf '%-18s %-10s %-9s %-7s %s\n' "下单IP" "来源" "出口" "proxy4" "DNS域名"
    echo "---------------------------------------------------------"

    c_ssdns=0; c_otherdns=0; c_nondns=0; c_direct=0; c_proxied=0; c_unknown_egress=0

    while read ip; do
        [ -n "$ip" ] || continue

        # 来源分档
        dom=$(awk -v ip="$ip" -F'\t' '$1==ip{print $2; exit}' "$WORKDIR/ssrust_ip_domain.txt")
        if [ -n "$dom" ]; then
            src="SS-DNS"; c_ssdns=$((c_ssdns+1))
        elif grep -qxF "$ip" "$WORKDIR/landns_ips.txt"; then
            src="OTHER-DNS"; dom="(绕过ss-rust)"; c_otherdns=$((c_otherdns+1))
        else
            src="NON-DNS"; dom="-"; c_nondns=$((c_nondns+1))
        fi

        # 出口判定
        if [ "$wan_seen" = "no" ]; then
            egress="?"; c_unknown_egress=$((c_unknown_egress+1))
        elif grep -qxF "$ip" "$WORKDIR/wan_ips.txt"; then
            egress="DIRECT"; c_direct=$((c_direct+1))
        else
            egress="PROXIED"; c_proxied=$((c_proxied+1))
        fi

        # proxy4 精确命中
        if grep -qxF "$ip" "$WORKDIR/nft_proxy4.txt" 2>/dev/null; then p4="YES"; else p4="no"; fi

        printf '%-18s %-10s %-9s %-7s %s\n' "$ip" "$src" "$egress" "$p4" "$dom"
    done < "$ORDER"

    echo "---------------------------------------------------------"
    echo "来源统计: SS-DNS=$c_ssdns  OTHER-DNS=$c_otherdns  NON-DNS=$c_nondns"
    [ "$wan_seen" = "yes" ] \
        && echo "出口统计: DIRECT=$c_direct  PROXIED=$c_proxied" \
        || echo "出口统计: 未抓 WAN,无法判定(设 WAN_IF= 后重抓)"
    echo "========================================================="
    echo
    echo "结论判读:"
    if [ "$c_nondns" -gt 0 ] && [ "$c_nondns" -ge "$c_ssdns" ]; then
        echo "  • 多数/全部下单 IP 为 NON-DNS → 富途很可能用【私有 API 下发 IP】。"
        echo "    域名规则救不了下单连接,需把这些 IP 所在的精准网段放进 Proxy IP。"
    elif [ "$c_otherdns" -gt 0 ]; then
        echo "  • 存在 OTHER-DNS → 这些是 DNS 解析的,但客户端【绕过了 ss-rust】。"
        echo "    应让 Windows 的 DNS 真正指向路由器/ss-rust,域名规则才有机会生效。"
    elif [ "$c_ssdns" -gt 0 ]; then
        echo "  • 多数下单 IP 为 SS-DNS → 【DNS 驱动且经过 ss-rust】。"
        echo "    把上表 DNS域名 列出现的前端域名加入 Proxy Domain 即可。"
    fi
    if [ "$wan_seen" = "yes" ] && [ "$c_direct" -gt 0 ]; then
        echo "  • 有 DIRECT 出口的下单 IP = 当前没走代理(富途会看到大陆 IP → 可能拒单)。"
    fi
    echo
    echo "中间文件(可自行核对): $WORKDIR/{ssrust_ip_domain,landns_ips,order_ips,wan_ips,nft_proxy4}.txt"
}

cmd_run() {
    cmd_capture
    cmd_analyze
}

trap 'stop_capture' INT TERM

case "${1:-run}" in
    deps)    cmd_deps ;;
    capture) cmd_capture ;;
    analyze) cmd_analyze ;;
    run)     cmd_run ;;
    *) die "未知子命令: $1 (deps|capture|analyze|run)" ;;
esac
