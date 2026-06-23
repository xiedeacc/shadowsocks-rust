#!/usr/bin/env python3
import argparse
import concurrent.futures
import os
import socket
import tempfile
import time
from dataclasses import dataclass


DEFAULT_FILE = "/usr/local/shadowsocks/data/direct_domain.txt"
DEFAULT_MARK = 0xFF
SO_MARK = getattr(socket, "SO_MARK", 36)


@dataclass
class DomainResult:
    line_no: int
    original: str
    domain: str
    reachable: bool
    reason: str


def parse_args():
    parser = argparse.ArgumentParser(
        description="Remove direct_domain.txt entries that are not reachable by direct TCP connect."
    )
    parser.add_argument("--file", default=DEFAULT_FILE, help=f"domain file to prune (default: {DEFAULT_FILE})")
    parser.add_argument("--ports", default="443,80", help="comma-separated ports to test (default: 443,80)")
    parser.add_argument("--timeout", type=float, default=3.0, help="connect timeout per address/port (default: 3s)")
    parser.add_argument("--workers", type=int, default=16, help="parallel workers (default: 16)")
    parser.add_argument("--mark", type=lambda value: int(value, 0), default=DEFAULT_MARK, help="SO_MARK value (default: 0xff)")
    parser.add_argument("--dry-run", action="store_true", help="report removals without editing the file")
    return parser.parse_args()


def active_domain(line):
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    token = stripped.split()[0].strip().rstrip(".").lower()
    for prefix in ("domain:", "full:"):
        if token.startswith(prefix):
            token = token[len(prefix):]
    if token.startswith(("keyword:", "regexp:")) or "*" in token:
        return None
    return token if token else None


def resolve(domain):
    try:
        infos = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
    except OSError as err:
        return [], f"dns: {err}"
    addresses = []
    seen = set()
    for family, _socktype, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        key = (family, ip)
        if key in seen:
            continue
        seen.add(key)
        addresses.append((family, ip))
    return addresses, "" if addresses else "dns: no A/AAAA answers"


def can_connect(family, ip, port, timeout, mark):
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        try:
            sock.setsockopt(socket.SOL_SOCKET, SO_MARK, mark)
        except OSError:
            pass
        sock.connect((ip, port))
        return True, f"{ip}:{port}"
    except OSError as err:
        return False, f"{ip}:{port} {err}"
    finally:
        sock.close()


def check_domain(line_no, original, domain, ports, timeout, mark):
    addresses, dns_error = resolve(domain)
    if not addresses:
        return DomainResult(line_no, original, domain, False, dns_error)

    failures = []
    for family, ip in addresses:
        for port in ports:
            ok, detail = can_connect(family, ip, port, timeout, mark)
            if ok:
                return DomainResult(line_no, original, domain, True, detail)
            failures.append(detail)
    return DomainResult(line_no, original, domain, False, "; ".join(failures[:6]))


def read_lines(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.readlines()


def write_lines_atomic(path, lines):
    directory = os.path.dirname(path) or "."
    mode = os.stat(path).st_mode & 0o777
    fd, tmp_path = tempfile.mkstemp(prefix=".direct_domain.", dir=directory, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.writelines(lines)
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def main():
    args = parse_args()
    ports = [int(part) for part in args.ports.split(",") if part.strip()]
    lines = read_lines(args.file)
    jobs = []
    preserved = set()
    for index, line in enumerate(lines):
        domain = active_domain(line)
        if domain is None:
            preserved.add(index)
            continue
        jobs.append((index + 1, line, domain))

    removals = []
    kept = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = [
            executor.submit(check_domain, line_no, original, domain, ports, args.timeout, args.mark)
            for line_no, original, domain in jobs
        ]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result.reachable:
                kept += 1
                print(f"KEEP   line={result.line_no} domain={result.domain} via={result.reason}")
            else:
                removals.append(result)
                print(f"REMOVE line={result.line_no} domain={result.domain} reason={result.reason}")

    removal_indexes = {result.line_no - 1 for result in removals}
    print(f"SUMMARY checked={len(jobs)} kept={kept} remove={len(removals)} dry_run={args.dry_run}")

    if args.dry_run or not removals:
        return 0

    timestamp = time.strftime("%Y%m%d-%H%M%S")
    backup = f"{args.file}.bak.{timestamp}"
    with open(backup, "w", encoding="utf-8") as handle:
        handle.writelines(lines)
    write_lines_atomic(args.file, [line for index, line in enumerate(lines) if index not in removal_indexes])
    print(f"WROTE {args.file}")
    print(f"BACKUP {backup}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
