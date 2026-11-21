#!/usr/bin/env bash
# Create (once) the self-signed loopback certificate the `just workload-smoke` stub issuer serves,
# and a trust bundle (system roots plus that certificate) for the control plane's SSL_CERT_FILE.
# Prints the bundle path. Test material only; the key never leaves the gitignored directory.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dir="${E2E_WORKLOAD_CERT_DIR:-$root/infra/compose/.workload-smoke}"
mkdir -p "$dir"
if [ ! -s "$dir/cert.pem" ] || [ ! -s "$dir/key.pem" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
    -keyout "$dir/key.pem" -out "$dir/cert.pem" -subj "/CN=workload-smoke" \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
    -addext "basicConstraints=critical,CA:FALSE" >/dev/null 2>&1
  chmod 600 "$dir/key.pem"
fi
{
  for f in "${SSL_CERT_FILE:-}" /etc/ssl/certs/ca-certificates.crt; do
    if [ -n "$f" ] && [ -s "$f" ]; then cat "$f"; break; fi
  done
  cat "$dir/cert.pem"
} >"$dir/trust.pem"
echo "$dir/trust.pem"
