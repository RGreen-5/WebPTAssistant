#!/usr/bin/env bash
set -euo pipefail

ZAP_NAME="zap"
ZAP_PORT="8080"

echo "[+] Removing old ZAP container if it exists ..."
docker rm -f "$ZAP_NAME" >/dev/null 2>&1 || true

echo "[+] Starting ZAP ..."
docker run -d --name "$ZAP_NAME" -p "${ZAP_PORT}:8080" \
  zaproxy/zap-weekly \
  zap.sh -daemon -host 0.0.0.0 -port 8080 \
  -config api.disablekey=true \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true >/dev/null

echo "[+] Waiting for ZAP to be ready ..."
for i in {1..60}; do
  if curl -s "http://127.0.0.1:${ZAP_PORT}/JSON/core/view/version/" >/dev/null 2>&1; then
    echo "[+] ZAP is ready at http://127.0.0.1:${ZAP_PORT}"
    exit 0
  fi
  sleep 1
done

echo "[!] ZAP did not become ready in time."
exit 1
