#!/usr/bin/env bash
# M42 (the denial cache's effect, docs/plans/dns-recursion-plan.md section 6): the queries
# the recursive resolver sends to the authority for 1,000 random names under one range an
# NSEC record covers (and one an NSEC3 record covers), with the denial cache on and off and
# with QNAME minimisation relaxed, strict and off. Threshold: below 50 per 1,000 names (one
# per range) with the denial cache, 1,000 without.
#
# It runs in the compose DNS lab (deploy/compose/lab-dns, the round `recursion`), against the
# lab's own root: the node under test is the lab image (deploy/Dockerfile, the static musl
# release binary, the one that ships) resolving from the authority node, a second Tenko node
# serving the root, the TLD `test` and `example.test` (NSEC) with `nsec3.example.test` (NSEC3,
# no extra iterations). For each of the six settings the node is restarted (its caches empty,
# its data kept), asked one NXDOMAIN whose proof covers the range (`nothing.example.test`,
# whose NSEC runs from `loop2.example.test` to `nsec3.example.test`; `a.nsec3.example.test`,
# whose two NSEC3 records cover every other hash), then the 1,000 names `m<12 random
# characters>.example.test` (all in that range) or `...nsec3.example.test` with `dig -f` from
# the client container, one after the other. The count is the authority's query log: the
# lines for names at or below the zone from the start of the batch, every page read. The
# figures are printed under the heading M42 at the end of the round.
#
# Usage, from the repository root, Docker with the compose plugin (in WSL: as root):
#   bash bench/phase2-dns/scripts/run-m42-denial.sh
#   IMAGE=tenko:lab QUIRK_IMAGE=tenko-quirk:lab bash bench/phase2-dns/scripts/run-m42-denial.sh
# Everything smoke.sh takes applies (IMAGE, QUIRK_IMAGE, KEEP, WAIT_SECS); the round's rows
# run as well, so a run is also a run of the round `recursion`.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$repo"
ROUNDS=recursion M42=1 exec bash deploy/compose/lab-dns/smoke.sh
