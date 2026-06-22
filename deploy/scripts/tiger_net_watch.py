#!/usr/bin/env python3
"""Tiger network watchdog / capture harness.

Two complementary checks each cycle:

1. SERVER reachability canary -- raw TCP connect to the SS server :443 over EACH interface
   using SO_BINDTODEVICE (true egress-interface binding; plain source-IP binding does NOT
   change the route on a dual-homed host). Tests pure network connectivity:
     enp5s0 -> openwrt -> 192.168.0.1 -> server   (the proxied/forward path)
     wlp4s0 -> 192.168.0.1 -> server              (direct, bypasses openwrt -- like the phone)
   NOTE: the server IP is EXEMPT from redir, so this is a DIRECT connect, not the proxy path.

2. 翻墙/direct URL checks -- curl is explicitly bound to PRIMARY_IFACE and disables
   proxy environment variables. This host can also run a local upstream sslocal and
   has a Wi-Fi default route, so plain curl would be contaminated by wlp4s0 or a
   local proxy and could report false OKs while enp5s0 is actually broken.

On trouble (all foreign sites fail, OR the server canary fails on the primary interface) it
SSHes the router for a full snapshot. Requires root for SO_BINDTODEVICE.

Root cause history (2026-06-22): the router's OWN 翻墙 failed intermittently because it
resolved foreign names via the ::1 nameserver -> dnsmasq -> upstream 192.168.0.1 (GFW-poisoned,
e.g. google -> 157.240.x). Fixed by pointing dnsmasq at sslocal:1053 split-DNS.
"""
import datetime as dt
import random
import os
import re
import socket
import subprocess
import time
from urllib.parse import urlsplit


PROXY_ENV_KEYS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
)
for key in PROXY_ENV_KEYS:
    os.environ.pop(key, None)

SSSERVER_HOST = os.environ.get("SSSERVER_HOST", "54.179.191.126")
SSSERVER_PORT = int(os.environ.get("SSSERVER_PORT", "443"))
SS_PLUGIN_HOST = os.environ.get("SS_PLUGIN_HOST", "forsimple.youkechat.net")
GATEWAY = os.environ.get("GATEWAY", "192.168.0.1")
PRIMARY_DNS_SERVER = os.environ.get("PRIMARY_DNS_SERVER", "192.168.2.1")

# Server-canary interfaces; the PRIMARY one (through openwrt) gates the failure state.
SERVER_IFACES = os.environ.get("SERVER_IFACES", "enp5s0,wlp4s0").split(",")
PRIMARY_IFACE = os.environ.get("PRIMARY_IFACE", "enp5s0")

# URL targets must go through the primary wired path. fanqiang/direct are considered
# down independently when all targets in that list fail.
FOREIGN_URLS = os.environ.get(
    "FOREIGN_URLS",
    "https://www.google.com/generate_204",
).split(",")
DIRECT_URLS = os.environ.get("DIRECT_URLS", "https://www.baidu.com/").split(",")

INTERVAL_SECONDS = int(os.environ.get("INTERVAL_SECONDS", "15"))
TIMEOUT_SECONDS = int(os.environ.get("TIMEOUT_SECONDS", "8"))
FAIL_FILE = os.environ.get("FAIL_FILE", "/tmp/netfail")
SNAP_DIR = os.environ.get("SNAP_DIR", "/tmp/netfail_snaps")
SSH_TARGET = os.environ.get("SSH_TARGET", "root@openwrt")

SO_BINDTODEVICE = 25
SSH_BASE = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", SSH_TARGET]
NO_PROXY_ENV = os.environ.copy()

ROUTER_GAUGE = (
    'echo udp=$(grep -cE "udp.*%(s)s.*dport=443" /proc/net/nf_conntrack) '
    'tcp=$(grep -cE "tcp.*%(s)s.*dport=443" /proc/net/nf_conntrack) '
    'ct=$(cat /proc/sys/net/netfilter/nf_conntrack_count)'
) % {"s": SSSERVER_HOST}

ROUTER_SNAPSHOT = r"""
echo "== openwrt own 翻墙 (resolve + tunnel) =="
for u in https://www.google.com/generate_204 https://github.com/ ; do
  printf "  %s -> " "$u"; curl -s -o /dev/null -m5 -w "code=%{http_code} ip=%{remote_ip} t=%{time_total}s\n" "$u" 2>&1 || echo "rc=$?"
done
echo "== server transport (fresh) =="
EG=$(curl -k -sS -m4 -o /dev/null -w 'http=%{http_code} connect=%{time_connect}s' --resolve __PLUGIN__:443:__SERVER__ https://__PLUGIN__/ 2>&1); EGRC=$?
[ "$EGRC" -eq 0 ] && echo "EGRESS_RESULT=OK $EG" || echo "EGRESS_RESULT=FAIL rc=$EGRC $EG"
echo "== split-DNS check: google via ::1(dnsmasq) vs 127.0.0.1(1053) =="
echo "  ::1:       $(nslookup www.google.com ::1 2>/dev/null | grep -iE '^Address' | grep -vE '::1|#53' | head -1)"
echo "  127.0.0.1: $(nslookup www.google.com 127.0.0.1 2>/dev/null | grep -iE '^Address' | grep -vE '127.0.0.1|#53' | head -1)"
echo "== conntrack =="
echo "count=$(cat /proc/sys/net/netfilter/nf_conntrack_count) udp_to_server=$(grep -cE 'udp.*__SERVER__.*dport=443' /proc/net/nf_conntrack) tcp_to_server=$(grep -cE 'tcp.*__SERVER__.*dport=443' /proc/net/nf_conntrack)"
echo "== ping server/gw =="; ping -c2 -W2 __SERVER__ 2>&1 | tail -1; ping -c2 -W1 __GW__ 2>&1 | tail -1
echo "== recent sslocal/xray errors =="
logread 2>/dev/null | grep -iE 'sslocal|xray' | grep -iE 'error|fail|reset|refused|broken|timeout|reconnect' | tail -8
""".replace("__SERVER__", SSSERVER_HOST).replace("__PLUGIN__", SS_PLUGIN_HOST).replace("__GW__", GATEWAY)


CST = dt.timezone(dt.timedelta(hours=8))
USE_COLOR = os.environ.get("TIGER_NET_WATCH_COLOR", "1") != "0"
_GREEN, _RED, _RESET = "\033[1;92m", "\033[1;91m", "\033[0m"


def now_str() -> str:
    return dt.datetime.now(CST).strftime("%Y-%m-%d %H:%M:%S CST")


def colorize(line: str) -> str:
    if not USE_COLOR:
        return line
    line = re.sub(r"\bOK\b", _GREEN + "OK" + _RESET, line)
    line = re.sub(r"\bFAIL\b", _RED + "FAIL" + _RESET, line)
    return line


def append_line(path: str, line: str) -> None:
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def emit(line: str, record_fail_file: bool = True) -> None:
    colored = colorize(line)
    print(colored, flush=True)
    if record_fail_file:
        append_line(FAIL_FILE, line)


def server_ok(ifname: str) -> bool:
    """Raw TCP connect to the SS server bound to a specific egress interface."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT_SECONDS)
    try:
        sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, (ifname + "\0").encode())
        sock.connect((SSSERVER_HOST, SSSERVER_PORT))
        return True
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _read_dns_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels = []
    jumped = False
    next_offset = offset
    seen = set()
    while True:
        if offset >= len(packet):
            raise ValueError("dns name exceeds packet")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated dns pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer in seen:
                raise ValueError("dns pointer loop")
            seen.add(pointer)
            if not jumped:
                next_offset = offset + 2
                jumped = True
            offset = pointer
            continue
        if length == 0:
            if not jumped:
                next_offset = offset + 1
            break
        offset += 1
        labels.append(packet[offset : offset + length].decode("ascii", "ignore"))
        offset += length
    return ".".join(labels), next_offset


def resolve_a_via_primary_dns(host: str, ifname: str = PRIMARY_IFACE) -> str | None:
    query_id = random.randrange(0, 65536)
    qname = b"".join(bytes([len(label)]) + label.encode("ascii") for label in host.rstrip(".").split(".")) + b"\0"
    packet = (
        query_id.to_bytes(2, "big")
        + b"\x01\x00"
        + b"\x00\x01"
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x00\x00"
        + qname
        + b"\x00\x01\x00\x01"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT_SECONDS)
    try:
        sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, (ifname + "\0").encode())
        sock.sendto(packet, (PRIMARY_DNS_SERVER, 53))
        data, _ = sock.recvfrom(1500)
    except Exception:
        return None
    finally:
        sock.close()

    if len(data) < 12 or int.from_bytes(data[:2], "big") != query_id:
        return None
    qdcount = int.from_bytes(data[4:6], "big")
    ancount = int.from_bytes(data[6:8], "big")
    offset = 12
    try:
        for _ in range(qdcount):
            _, offset = _read_dns_name(data, offset)
            offset += 4
        for _ in range(ancount):
            _, offset = _read_dns_name(data, offset)
            rtype = int.from_bytes(data[offset : offset + 2], "big")
            rclass = int.from_bytes(data[offset + 2 : offset + 4], "big")
            rdlength = int.from_bytes(data[offset + 8 : offset + 10], "big")
            offset += 10
            rdata = data[offset : offset + rdlength]
            offset += rdlength
            if rtype == 1 and rclass == 1 and rdlength == 4:
                return socket.inet_ntoa(rdata)
    except Exception:
        return None
    return None


def curl_ok(url: str, ifname: str = PRIMARY_IFACE) -> bool:
    """curl bound to the primary interface, bypassing proxy env vars and host DNS."""
    parsed = urlsplit(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    resolved_ip = resolve_a_via_primary_dns(host, ifname) if host else None
    if host and not resolved_ip:
        return False
    args = [
        "curl",
        "--interface",
        ifname,
        "--noproxy",
        "*",
    ]
    if host and resolved_ip:
        args += ["--resolve", f"{host}:{port}:{resolved_ip}"]
    args += [
        "-k",
        "-s",
        "-o",
        "/dev/null",
        "--connect-timeout",
        str(TIMEOUT_SECONDS),
        "-m",
        str(TIMEOUT_SECONDS),
        "-w",
        "%{http_code}",
        url,
    ]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=TIMEOUT_SECONDS + 3, env=NO_PROXY_ENV)
        return proc.returncode == 0
    except Exception:
        return False


def router_gauge() -> str:
    try:
        proc = subprocess.run(SSH_BASE + [ROUTER_GAUGE], capture_output=True, text=True, timeout=10)
        return (proc.stdout or "").strip() or "gauge?"
    except Exception:
        return "gauge-ssh-fail"


def capture_snapshot(reason: str) -> str:
    ts = dt.datetime.now(CST).strftime("%Y%m%dT%H%M%S_CST")
    path = os.path.join(SNAP_DIR, f"snap_{ts}.txt")
    os.makedirs(SNAP_DIR, exist_ok=True)
    try:
        proc = subprocess.run(SSH_BASE + [ROUTER_SNAPSHOT], capture_output=True, text=True, timeout=40)
        body = proc.stdout + (("\n[stderr]\n" + proc.stderr) if proc.stderr else "")
    except Exception as exc:
        body = f"[snapshot ssh failed] {type(exc).__name__}: {exc}\n"
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(f"# snapshot {now_str()} reason={reason}\n" + body)
    egress = "FAIL" if "EGRESS_RESULT=FAIL" in body else ("OK" if "EGRESS_RESULT=OK" in body else "?")
    return f"{path} server_transport={egress}"


def main() -> int:
    open(FAIL_FILE, "w", encoding="utf-8").close()
    emit(
        f"{now_str()} START server={SSSERVER_HOST}:{SSSERVER_PORT} via={SERVER_IFACES} "
        f"primary={PRIMARY_IFACE} foreign={FOREIGN_URLS} direct={DIRECT_URLS} "
        f"proxy_env=cleared interval={INTERVAL_SECONDS}s"
    )

    down = False
    down_since = None

    while True:
        srv = {ifc: server_ok(ifc) for ifc in SERVER_IFACES}
        sdetail = " ".join(f"{ifc}={'OK' if ok else 'FAIL'}" for ifc, ok in srv.items())
        primary_ok = srv.get(PRIMARY_IFACE, True)

        fan = [(u, curl_ok(u, PRIMARY_IFACE)) for u in FOREIGN_URLS]
        fanqiang_ok = any(ok for _, ok in fan)
        fdetail = " ".join(f"{n}={'OK' if ok else 'FAIL'}" for n, ok in fan)
        direct = [(u, curl_ok(u, PRIMARY_IFACE)) for u in DIRECT_URLS]
        direct_ok = any(ok for _, ok in direct)
        ddetail = " ".join(f"{n}={'OK' if ok else 'FAIL'}" for n, ok in direct)

        status = f"server[{sdetail}] fanqiang[{fdetail}] direct[{ddetail}] router[{router_gauge()}]"

        reasons = []
        if not primary_ok:
            reasons.append(f"server-{PRIMARY_IFACE}-fail")
        if not fanqiang_ok:
            reasons.append("fanqiang-all-fail")
        if not direct_ok:
            reasons.append("direct-all-fail")

        if reasons:
            snap = capture_snapshot(",".join(reasons))
            emit(f"{now_str()} FAIL {status} SNAPSHOT {snap}")
            if not down:
                down, down_since = True, time.monotonic()
        else:
            if down:
                dur = time.monotonic() - down_since if down_since else 0
                emit(f"{now_str()} RECOVER after {dur:.0f}s | {status}")
                down, down_since = False, None
            else:
                emit(f"{now_str()} OK {status}", record_fail_file=False)

        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())
