#!/bin/bash
set -u
echo "=== systemd units (shadowsocks/xray/nginx) ==="
systemctl list-units --all --no-pager 2>/dev/null | grep -E -i 'shadow|ssserver|xray|nginx' || true
echo
echo "=== running procs ==="
ps -ef | grep -E 'ssserver|xray|nginx' | grep -v grep || true
echo
echo "=== TCP listeners ==="
sudo ss -tlnp 2>/dev/null | head -40
echo
echo "=== UDP listeners ==="
sudo ss -ulnp 2>/dev/null | head -40
echo
echo "=== AWS security group ports open? (inferred from listening) ==="
sudo iptables -L INPUT -n -v --line-numbers 2>/dev/null | head -30
sudo ip6tables -L INPUT -n -v --line-numbers 2>/dev/null | head -10
echo
echo "=== nginx config sample ==="
test -f /etc/nginx/nginx.conf && sudo cat /etc/nginx/nginx.conf | head -60 || echo "no /etc/nginx/nginx.conf"
ls /etc/nginx/sites-enabled/ 2>/dev/null || true
ls /etc/nginx/conf.d/ 2>/dev/null || true
echo "--- nginx -T (excerpt) ---"
sudo nginx -T 2>/dev/null | sed -n '/listen\|server_name\|location\|upstream/p' | head -60
echo
echo "=== xray-plugin and ssserver binaries ==="
which ssserver xray-plugin xray sslocal 2>/dev/null
echo "--- ssserver --version ---"
/usr/local/bin/ssserver --version 2>/dev/null || ssserver --version 2>/dev/null || true
echo "--- xray-plugin (server) --version ---"
xray-plugin --version 2>/dev/null || /usr/local/bin/xray-plugin --version 2>/dev/null || true
echo
echo "=== config files (best guess) ==="
sudo find /etc -maxdepth 4 -type f \( -name '*ssserver*' -o -name '*shadowsocks*' -o -name '*xray*' \) 2>/dev/null | head -20
echo
echo "=== systemd unit content (ssserver / xray-plugin) ==="
for u in $(systemctl list-unit-files --no-pager 2>/dev/null | awk '/(shadow|ssserver|xray|nginx)/{print $1}'); do
    echo "--- unit: $u ---"
    systemctl cat "$u" 2>/dev/null | head -30
done
