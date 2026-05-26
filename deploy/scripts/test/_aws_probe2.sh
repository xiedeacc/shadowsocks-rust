#!/bin/bash
set -u
echo "=== full nginx -T dump ==="
sudo nginx -T 2>/dev/null > /tmp/_nginx_full.txt
ls -la /tmp/_nginx_full.txt
echo
echo "=== forsimple server block ==="
awk '/server_name.*forsimple/,/^[[:space:]]*}[[:space:]]*$/' /tmp/_nginx_full.txt
echo
echo "=== ALL nginx confs referencing sspath ==="
sudo grep -rEn 'sspath' /etc/nginx 2>/dev/null
echo
echo "=== xray-plugin binary ==="
ls -la /usr/local/bin/xray-plugin* 2>/dev/null
file /usr/local/bin/xray-plugin_linux_arm64 2>/dev/null
echo "--- plugin --version / --help ---"
/usr/local/bin/xray-plugin_linux_arm64 --version 2>&1 | head -5
/usr/local/bin/xray-plugin_linux_arm64 --help 2>&1 | head -40 || true
echo
echo "=== ssserver process command line (catches the plugin invocation) ==="
ps -ef | grep -E 'ssserver|xray-plugin' | grep -v grep
echo
echo "=== plugin listening port (whichever local port ssserver picks for the plugin) ==="
sudo ss -tlnp 2>/dev/null | grep -E 'xray-plugin|ssserver'
sudo ss -ulnp 2>/dev/null | grep -E 'xray-plugin|ssserver'
echo
echo "=== firewall info (cloud and host) ==="
echo "--- ufw ---"
sudo ufw status verbose 2>/dev/null | head -30
echo "--- nft ---"
sudo nft list ruleset 2>/dev/null | head -30
echo "--- listening on ALL :443 / :8388 ---"
sudo ss -tlnpu | awk '/:443|:8388|:1080/'
