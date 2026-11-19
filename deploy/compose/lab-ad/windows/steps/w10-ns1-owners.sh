#!/usr/bin/env bash
# W10 on ns1: pc1's names (README.md section W10), as root.
#
# Expects: pc1 registered (the pc1 entries of W10).
# Leaves: nothing changed.
# Keeps: owners-corp.example.test.json, owners-2.0.192.in-addr.arpa.json.
# Checks: pc1.corp.example.test and 30.2.0.192.in-addr.arpa are owned by PC1$ (created).

. /root/lab/run/lab-common.sh || { echo "FAIL: /root/lab/run/lab-common.sh is missing"; exit 1; }
assert_clock
owners corp.example.test "$STEP_DIR/owners-corp.example.test.json"
owners 2.0.192.in-addr.arpa "$STEP_DIR/owners-2.0.192.in-addr.arpa.json"
owned_by "$STEP_DIR/owners-corp.example.test.json" pc1.corp.example.test 'PC1$' created
owned_by "$STEP_DIR/owners-2.0.192.in-addr.arpa.json" 30.2.0.192.in-addr.arpa 'PC1$' created

step "pc1.corp.example.test and 30.2.0.192.in-addr.arpa are owned by PC1\$"
