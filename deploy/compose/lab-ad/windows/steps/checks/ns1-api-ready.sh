#!/usr/bin/env bash
# Readiness check on ns1, as root: exits 0 when the Tenko API answers ready on
# https://localhost:8443 (verified with root's copy of the CA root that W0 made).
set -euo pipefail
curl -fsS --max-time 10 --cacert /root/lab/ca-root.pem https://localhost:8443/api/v1/health/ready >/dev/null
