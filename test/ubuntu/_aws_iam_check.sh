#!/bin/bash
set -u
TOKEN=$(curl -sS -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null)
echo "=== iam/info ==="
curl -sS -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/iam/info 2>&1
echo
echo "=== instance-id ==="
curl -sS -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/instance-id 2>&1; echo
echo "=== mac ==="
MAC=$(curl -sS -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/network/interfaces/macs/ 2>/dev/null | head -1)
echo "mac=${MAC}"
echo "=== security-group-ids ==="
curl -sS -H "X-aws-ec2-metadata-token: $TOKEN" \
    "http://169.254.169.254/latest/meta-data/network/interfaces/macs/${MAC}security-group-ids" 2>&1; echo
echo "=== aws cli? ==="
which aws 2>/dev/null && aws --version 2>&1 | head -1
