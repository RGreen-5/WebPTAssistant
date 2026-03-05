#!/usr/bin/env bash
set -euo pipefail

ZAP_NAME="zap"
MUT_NAME="mutillidae"
ZAP_PORT="8080"
MUT_HOST_PORT="${MUT_HOST_PORT:-8085}"

echo "[+] Removing old containers if they exist..."
docker rm -f "$ZAP_NAME" "$MUT_NAME" >/dev/null 2>&1 || true

echo "[+] Starting ZAP..."
docker run -d --name "$ZAP_NAME" -p "${ZAP_PORT}:8080" \
  zaproxy/zap-weekly \
  zap.sh -daemon -host 0.0.0.0 -port 8080 \
  -config api.disablekey=true \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true >/dev/null

echo "[+] Starting Mutillidae..."
docker run -d --name "$MUT_NAME" -p "${MUT_HOST_PORT}:80" citizenstig/nowasp >/dev/null

echo "[+] Waiting for ZAP to be ready..."
for i in {1..60}; do
  if curl -fsS "http://127.0.0.1:${ZAP_PORT}/JSON/core/view/version/" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

# Get Mutillidae container IP
MUT_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$MUT_NAME")

echo
echo "Mutillidae container internal IP: ${MUT_IP}"
