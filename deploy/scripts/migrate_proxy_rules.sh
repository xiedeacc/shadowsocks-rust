#!/bin/sh
set -eu

DEPLOY_DIR="${1:-/usr/local/shadowsocks}"
CONF_FILE="$DEPLOY_DIR/conf/shadowsocks-client.json"
DATA_DIR="$DEPLOY_DIR/data"
TEMP_DIR="$DATA_DIR/temp"

move_rule_file() {
	old="$1"
	new="$2"
	if [ -e "$old" ]; then
		if [ -e "$new" ]; then
			cat "$old" >> "$new"
			rm -f "$old"
		else
			mv "$old" "$new"
		fi
	fi
}

mkdir -p "$DATA_DIR" "$TEMP_DIR"

move_rule_file "$DATA_DIR/bypass_ip.txt" "$DATA_DIR/proxy_ip.txt"
move_rule_file "$DATA_DIR/bypass_domain.txt" "$DATA_DIR/proxy_domain.txt"
move_rule_file "$DATA_DIR/direct_ip.temp" "$TEMP_DIR/direct_ip.temp"
move_rule_file "$DATA_DIR/direct_domain.temp" "$TEMP_DIR/direct_domain.temp"
move_rule_file "$DATA_DIR/bypass_ip.temp" "$TEMP_DIR/proxy_ip.temp"
move_rule_file "$DATA_DIR/bypass_domain.temp" "$TEMP_DIR/proxy_domain.temp"
move_rule_file "$TEMP_DIR/bypass_ip.temp" "$TEMP_DIR/proxy_ip.temp"
move_rule_file "$TEMP_DIR/bypass_domain.temp" "$TEMP_DIR/proxy_domain.temp"

if [ -f "$CONF_FILE" ]; then
	if command -v python3 >/dev/null 2>&1; then
		python3 - "$CONF_FILE" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
updated = text.replace('"bypass_domain_sources"', '"proxy_domain_sources"')
if updated != text:
    path.write_text(updated)
PY
	else
		sed 's/"bypass_domain_sources"/"proxy_domain_sources"/g' "$CONF_FILE" > "$CONF_FILE.tmp"
		mv "$CONF_FILE.tmp" "$CONF_FILE"
	fi
fi

echo "migrated routing rule names under $DEPLOY_DIR"
