# shellcheck shell=bash
# fuzz.sh is sourced by round.sh, which assigns repo and here and reads the row_tool, row_version,
# row_reason and row_skip variables the rows set (lib.sh row helper); shellcheck sees this file alone.
# shellcheck disable=SC2034,SC2154
# The fuzz rows of the security round (SA5 of docs/plans/security-audit-plan.md), sourced by
# round.sh so they share the row helper, the bundle and the node under test:
#
#   fuzz.targets   every in-process target of `cargo fuzz list` for the release budget
#                  (FUZZ_RELEASE_SECS, default 120 s), four at a time, from fuzz/seeds/ and
#                  the corpus the workflow caches; a crash fails the row and its input goes
#                  into the bundle. The targets, seeds, corpus and artifacts are those of
#                  the tree in SOURCE (default: this checkout).
#   fuzz.dns_wire  deploy/security/dnswire.py sends malformed DNS over UDP and TCP to the
#                  node under test while a probe asks a known name once a second; the row
#                  fails on a crash, a hang, a restart of the unit, a listener that stops
#                  answering, or resident memory more than 20 percent above the start.
#
# The budget is documented beside the weekly one in fuzz/README.md.
#
# Settings (environment): FUZZ_RELEASE_SECS, the budget of one target in seconds (default 120);
# SOURCE, a checkout of the source the binary under test was built from, for a binary built
# from another commit than the checkout that holds these scripts (default: this checkout).

# run_fuzz_rows: called from round.sh main().
run_fuzz_rows() {
  row fuzz.targets "no in-process fuzz target crashes in the release budget" row_fuzz_targets
  row fuzz.dns_wire "the running node survives malformed DNS on the wire" row_fuzz_dns_wire
}

row_fuzz_targets() {
  row_tool=cargo-fuzz
  local budget="${FUZZ_RELEASE_SECS:-120}" src="${SOURCE:-$repo}" fuzz_dir="$src/fuzz"
  if ! command -v cargo >/dev/null 2>&1 || ! cargo +nightly fuzz --help >/dev/null 2>&1; then
    row_skip="cargo-fuzz or a nightly toolchain is not available (it runs in CI)"
    return 0
  fi
  row_version="$(cargo +nightly fuzz --version 2>/dev/null | head -n 1)"
  local targets
  targets="$(cd "$fuzz_dir" && cargo +nightly fuzz list 2>/dev/null | LC_ALL=C sort)"
  if [[ -z "$targets" ]]; then
    row_reason="cargo fuzz list printed no targets"
    return 1
  fi
  mkdir -p "$EVIDENCE/fuzz"
  local failed=() target running=0
  # Four at a time, run from the root of the source tree as the weekly smoke does (cargo-fuzz finds
  # the fuzz workspace); the corpus and seed directories are relative to it.
  for target in $targets; do
    (
      cd "$src" || exit 97
      local corpus=("fuzz/corpus/$target")
      mkdir -p "fuzz/corpus/$target"
      [[ -d "fuzz/seeds/$target" ]] && corpus+=("fuzz/seeds/$target")
      TENKO_UI_STUB=1 cargo +nightly fuzz run --target x86_64-unknown-linux-gnu "$target" \
        "${corpus[@]}" -- -max_total_time="$budget" \
        >"$EVIDENCE/fuzz/$target.log" 2>&1
    ) &
    running=$((running + 1))
    if ((running >= 4)); then
      wait -n 2>/dev/null || true
      running=$((running - 1))
    fi
  done
  wait
  # A crash leaves an input under fuzz/artifacts/<target>/.
  for target in $targets; do
    local crashes
    crashes="$(find "$src/fuzz/artifacts/$target" -type f 2>/dev/null | wc -l || echo 0)"
    if ((crashes > 0)); then
      failed+=("$target")
      mkdir -p "$EVIDENCE/fuzz/artifacts/$target"
      cp -r "$src/fuzz/artifacts/$target/." "$EVIDENCE/fuzz/artifacts/$target/" 2>/dev/null || true
      evidence_add "fuzz/artifacts/$target"
    fi
    evidence_add "fuzz/$target.log"
  done
  if ((${#failed[@]} > 0)); then
    row_reason="fuzz targets crashed: ${failed[*]} (inputs in the bundle)"
    return 1
  fi
}

row_fuzz_dns_wire() {
  row_tool=dnswire.py
  local src="${SOURCE:-$repo}"
  local duration="${FUZZ_DNS_WIRE_SECS:-600}" rate="${FUZZ_DNS_WIRE_RATE:-200}"
  local dns_host dns_udp=53 dns_tcp=53 report="$EVIDENCE/fuzz/dnswire.json"
  mkdir -p "$EVIDENCE/fuzz"
  dns_host=127.0.0.1
  # The resident memory of the service and its restart count at the start.
  local main_pid rss_start restarts_start
  main_pid="$(systemctl show -p MainPID --value tenko 2>/dev/null || echo 0)"
  restarts_start="$(systemctl show -p NRestarts --value tenko 2>/dev/null || echo 0)"
  rss_start="$(rss_of "$main_pid")"
  local rc=0
  python3 -I "$here/dnswire.py" --seeds "$src/fuzz/seeds/dns_codec" \
    --duration "$duration" --rate "$rate" \
    --host "$dns_host" --udp "$dns_udp" --tcp "$dns_tcp" \
    --probe-name probe.security.example.test --probe-type 1 --probe-expect 192.0.2.53 \
    --report "$report" >>"$EVIDENCE/rows/fuzz.dns_wire.log" 2>&1 || rc=$?
  evidence_add fuzz/dnswire.json rows/fuzz.dns_wire.log
  local restarts_end rss_end
  restarts_end="$(systemctl show -p NRestarts --value tenko 2>/dev/null || echo 0)"
  main_pid="$(systemctl show -p MainPID --value tenko 2>/dev/null || echo 0)"
  rss_end="$(rss_of "$main_pid")"
  {
    echo "NRestarts: $restarts_start -> $restarts_end"
    echo "RSS kB: $rss_start -> $rss_end"
  } >>"$EVIDENCE/rows/fuzz.dns_wire.log"
  # A panic in the journal during the run.
  if journalctl -u tenko --no-pager 2>/dev/null | grep -qiE 'panic|SIGSEGV|SIGABRT'; then
    row_reason="the journal shows a panic or a fatal signal during the run"
    return 1
  fi
  if [[ "$restarts_end" != "$restarts_start" ]]; then
    row_reason="the unit restarted during the run (NRestarts $restarts_start -> $restarts_end)"
    return 1
  fi
  if ((rc != 0)); then
    row_reason="a probe was not answered correctly during the run (fuzz/dnswire.json in the bundle)"
    return 1
  fi
  if [[ "$rss_start" =~ ^[0-9]+$ && "$rss_end" =~ ^[0-9]+$ && "$rss_start" -gt 0 ]]; then
    if awk -v a="$rss_start" -v b="$rss_end" 'BEGIN{exit !(b > a * 1.2)}'; then
      row_reason="resident memory grew more than 20 percent ($rss_start kB -> $rss_end kB)"
      return 1
    fi
  fi
}

rss_of() {
  local pid="$1"
  [[ "$pid" =~ ^[0-9]+$ && "$pid" != 0 ]] || { echo 0; return; }
  awk '/^VmRSS:/ {print $2}' "/proc/$pid/status" 2>/dev/null || echo 0
}
