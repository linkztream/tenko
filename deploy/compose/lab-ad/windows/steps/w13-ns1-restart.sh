#!/usr/bin/env bash
# W13 on ns1, first: the Tenko service restarts mid-day (README.md section W13), as root.
#
# Expects: every machine registered with Tenko.
# Leaves: the service restarted (its GSS-TSIG contexts, kept in memory, are gone) and ready
# again.
# Keeps: started.txt (when the restart began, for the last W13 entry).
# Checks: the API answers ready again within five minutes.

. /root/lab/run/lab-common.sh || { echo "FAIL: /root/lab/run/lab-common.sh is missing"; exit 1; }
printf '%s\n' "$STARTED" >"$STEP_DIR/started.txt"
systemctl restart tenko
for ((i = 0; i < 60; i++)); do
  curl -fsS --max-time 10 --cacert "$CA" "$TENKO_URL/api/v1/health/ready" >/dev/null && break
  sleep 5
done
curl -fsS --max-time 10 --cacert "$CA" "$TENKO_URL/api/v1/health/ready" >/dev/null || fail "the API is not ready five minutes after the restart"

step "the Tenko service restarted and is ready"
