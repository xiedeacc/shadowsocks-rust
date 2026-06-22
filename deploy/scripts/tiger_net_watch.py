#!/usr/bin/env python3
"""Tiger network watchdog / capture harness.

Two complementary checks each cycle:

1. SERVER reachability canary -- raw TCP connect to the SS server :443 over EACH interface
   using SO_BINDTODEVICE (true egress-interface binding; plain source-IP binding does NOT
   change the route on a dual-homed host). Tests pure network connectivity:
     enp5s0 -> openwrt -> 192.168.0.1 -> server   (the proxied/forward path)
     wlp4s0 -> 192.168.0.1 -> server              (direct, bypasses openwrt -- like the phone)
   NOTE: the server IP is EXEMPT from redir, so this is a DIRECT connect, not the proxy path.

2. 翻墙 (proxy path) -- plain default-route curl (NO --interface; SO_BINDTODEVICE on curl
   breaks routing here and yields false failures) to foreign sites that should be reachable
   only through the tunnel.

On trouble (all foreign sites fail, OR the server canary fails on the primary interface) it
SSHes the router for a full snapshot. Requires root for SO_BINDTODEVICE.

Root cause history (2026-06-22): the router's OWN 翻墙 failed intermittently because it
resolved foreign names via the ::1 nameserver -> dnsmasq -> upstream 192.168.0.1 (GFW-poisoned,
e.g. google -> 157.240.x). Fixed by pointing dnsmasq at sslocal:1053 split-DNS.
"""
import datetime as dt
import os
import re
import socket
import subprocess
import time


SSSERVER_HOST = os.environ.get("SSSERVER_HOST", "54.179.191.126")
SSSERVER_PORT = int(os.environ.get("SSSERVER_PORT", "443"))
SS_PLUGIN_HOST = os.environ.get("SS_PLUGIN_HOST", "forsimple.youkechat.net")
GATEWAY = os.environ.get("GATEWAY", "192.168.0.1")

# Server-canary interfaces; the PRIMARY one (through openwrt) gates the failure state.
SERVER_IFACES = os.environ.get("SERVER_IFACES", "enp5s0,wlp4s0").split(",")
PRIMARY_IFACE = os.environ.get("PRIMARY_IFACE", "enp5s0")

# Foreign targets reachable through the tunnel; 翻墙 is "down" only if ALL fail.
FOREIGN_URLS = os.environ.get(
    "FOREIGN_URLS",
    "https://www.google.com/generate_204,https://github.com/,https://www.youtube.com/",
).split(",")

INTERVAL_SECONDS = int(os.environ.get("INTERVAL_SECONDS", "15"))
TIMEOUT_SECONDS = int(os.environ.get("TIMEOUT_SECONDS", "8"))
FAIL_FILE = os.environ.get("FAIL_FILE", "/tmp/netfail")
SNAP_DIR = os.environ.get("SNAP_DIR", "/tmp/netfail_snaps")
SSH_TARGET = os.environ.get("SSH_TARGET", "root@openwrt")

SO_BINDTODEVICE = 25
SSH_BASE = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", SSH_TARGET]

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
USE_COLOR = os.environ.get("NO_COLOR") is None
_GREEN, _RED, _RESET = "\033[1;92m", "\033[1;91m", "\033[0m"


def now_str() -> str:
    return dt.datetime.now(CST).strftime("%Y-%m-%d %H:%M:%S CST")


def colorize(line: str) -> str:
    if not USE_COLOR:
        return line
    line = re.sub(r"\bOK\b", _GREEN + "OK" + _RESET, line)
    line = re.sub(r"\bFAIL\b", _RED + "FAIL" + _RESET, line)
    return line


def emit(line: str) -> None:
    colored = colorize(line)
    print(colored, flush=True)
    with open(FAIL_FILE, "a", encoding="utf-8") as handle:
        handle.write(colored + "\n")


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


def curl_ok(url: str) -> bool:
    """Plain default-route curl (no interface binding)."""
    args = ["curl", "-k", "-s", "-o", "/dev/null", "-m", str(TIMEOUT_SECONDS), "-w", "%{http_code}", url]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=TIMEOUT_SECONDS + 3)
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
        f"primary={PRIMARY_IFACE} foreign={FOREIGN_URLS} interval={INTERVAL_SECONDS}s"
    )

    down = False
    down_since = None

    while True:
        srv = {ifc: server_ok(ifc) for ifc in SERVER_IFACES}
        sdetail = " ".join(f"{ifc}={'OK' if ok else 'FAIL'}" for ifc, ok in srv.items())
        primary_ok = srv.get(PRIMARY_IFACE, True)

        fan = [(u, curl_ok(u)) for u in FOREIGN_URLS]
        fanqiang_ok = any(ok for _, ok in fan)
        fdetail = " ".join(f"{n}={'OK' if ok else 'FAIL'}" for n, ok in fan)

        status = f"server[{sdetail}] fanqiang[{fdetail}] router[{router_gauge()}]"

        reasons = []
        if not primary_ok:
            reasons.append(f"server-{PRIMARY_IFACE}-fail")
        if not fanqiang_ok:
            reasons.append("fanqiang-all-fail")

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
                print(colorize(f"{now_str()} OK {status}"), flush=True)

        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())
