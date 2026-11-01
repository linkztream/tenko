# shellcheck shell=bash
# The row helper and the evidence bundle of the security round (deploy/security/README.md),
# sourced by round.sh and fuzz.sh.
#
# A row is one check with one result: `row <name> <description> <check...>` runs the check
# with its output in the bundle (rows/<name>.log) and prints one line, as the weekly lab
# smokes do:
#
#   PASS net.tcp            only 53, 853 and 8443 were added on TCP
#   FAIL tls.api            the API's TLS is current
#   SKIP net.ipv6           the IPv6 surface is the IPv4 one (skipped: no IPv6 on the scan network)
#
# The log of a CI run is public (section 4.6 of docs/plans/security-audit-plan.md): the line
# carries the row's name and description only, and a SKIP its reason. What failed, the raw
# output of the tools and the trace stay in the bundle, which the workflow encrypts. Unlike
# the lab smokes, a failed check is not run a second time with a trace: a scan takes
# minutes and its output is in the bundle already.
#
# A check returns 0 to pass and anything else to fail. It may set, for the row's JSON line:
#   row_tool       the tool, for example "nmap"
#   row_version    the tool's version, or the image it ran from
#   row_evidence   (array) paths inside the bundle of the raw output
#   row_reason     one sentence on why it failed (bundle only)
#   row_skip       a reason: the row is SKIP, whatever the check returned
#   row_findings   the path inside the bundle of a JSON array of the row's findings, each
#                  {tool, rule, location, severity, title}: what a scanner found, one entry
#                  per rule and location (the web rows); scripts/security-report.mjs turns
#                  each into a finding with the fingerprint <tool>:<rule>:<location>
#
# Every row writes one JSON line to rows.jsonl in the bundle: row, state, blocking,
# duration_ms, tool, version, evidence, reason, description, started (UTC), and findings
# (the array row_findings names, empty without it).

# EVIDENCE: the bundle directory; created when missing.
: "${EVIDENCE:?EVIDENCE must name the bundle directory}"
mkdir -p "$EVIDENCE/rows"

rows_failed=0 rows_passed=0 rows_skipped=0 rows_blocking_failed=0
row_tool="" row_version="" row_evidence=() row_reason="" row_skip="" row_findings=""

# The rows that do not block a release (SA-Q1 (b)): the ZAP baselines of the web group
# report until their rule file has been through two releases without a new finding of High
# or above (section 4.4 of the plan); priv.* (SA6) will be listed here until ADR 0023 is
# built. A failing reporting row is a finding in the report, not a stop.
SEC_REPORTING_ROWS="${SEC_REPORTING_ROWS:-web.ui_baseline web.api_baseline}"

# wanted <row name>: the row is selected by ROWS ("net tls", "net.tcp fuzz", empty: all).
wanted() {
  local name="$1" group="${1%%.*}" w
  [[ -z "${ROWS:-}" ]] && return 0
  for w in $ROWS; do
    [[ "$w" == "$name" || "$w" == "$group" ]] && return 0
  done
  return 1
}

# evidence_add <path inside the bundle>...: adds to the current row's evidence.
evidence_add() {
  local p
  for p in "$@"; do row_evidence+=("$p"); done
}

# sec_now_ms: milliseconds since the epoch.
sec_now_ms() { date +%s%3N; }

# row <name> <description> <check...>
row() {
  local name="$1" what="$2" began ended rc state blocking=true reason_line="" line
  shift 2
  wanted "$name" || return 0
  row_tool="" row_version="" row_evidence=() row_reason="" row_skip="" row_findings=""
  began="$(sec_now_ms)"
  {
    printf '== %s: %s\n' "$name" "$what"
    printf '== started %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >>"$EVIDENCE/rows/$name.log"
  if "$@" >>"$EVIDENCE/rows/$name.log" 2>&1; then rc=0; else rc=$?; fi
  ended="$(sec_now_ms)"
  if [[ -n "$row_skip" ]]; then
    state=SKIP
    rows_skipped=$((rows_skipped + 1))
    reason_line=" (skipped: $row_skip)"
  elif ((rc == 0)); then
    state=PASS
    rows_passed=$((rows_passed + 1))
  else
    state=FAIL
    rows_failed=$((rows_failed + 1))
    [[ -n "$row_reason" ]] || row_reason="the check exited with status $rc"
  fi
  case " $SEC_REPORTING_ROWS " in *" $name "*) blocking=false ;; esac
  if [[ "$state" == FAIL && "$blocking" == true ]]; then
    rows_blocking_failed=$((rows_blocking_failed + 1))
  fi
  printf '== %s %s in %d ms%s\n' "$state" "$name" "$((ended - began))" "${row_reason:+: $row_reason}" \
    >>"$EVIDENCE/rows/$name.log"
  evidence_add "rows/$name.log"
  local evidence_json findings_file=/dev/null
  evidence_json="$(printf '%s\n' ${row_evidence[@]+"${row_evidence[@]}"} | jq -R . | jq -sc 'map(select(length > 0))')"
  if [[ -n "$row_findings" && -s "$EVIDENCE/$row_findings" ]] &&
    jq -e 'type == "array"' "$EVIDENCE/$row_findings" >/dev/null 2>&1; then
    findings_file="$EVIDENCE/$row_findings"
  fi
  jq -cn \
    --arg row "$name" --arg state "$state" --argjson blocking "$blocking" \
    --argjson duration_ms "$((ended - began))" --arg tool "$row_tool" --arg version "$row_version" \
    --arg reason "${row_skip:-$row_reason}" --arg description "$what" \
    --arg started "$(date -u -d "@$((began / 1000))" +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson evidence "$evidence_json" --slurpfile findings "$findings_file" \
    '{row: $row, state: $state, blocking: $blocking, duration_ms: $duration_ms, tool: $tool,
      version: $version, evidence: $evidence, reason: $reason, description: $description,
      started: $started, findings: ($findings[0] // [])}' >>"$EVIDENCE/rows.jsonl"
  line="$(printf '%s %-18s %s%s' "$state" "$name" "$what" "$reason_line")"
  printf '%s\n' "$line"
}

# rows_tally: the counts, one line, for the end of a round.
rows_tally() {
  printf 'rows: %d passed, %d failed (%d blocking), %d skipped\n' \
    "$rows_passed" "$rows_failed" "$rows_blocking_failed" "$rows_skipped"
}

# bundle_pack <tar file>: packs the bundle (owner-only file mode). The workflow encrypts it
# with age before anything leaves the runner; nothing here uploads it.
bundle_pack() {
  local out="$1"
  (umask 077 && tar -C "$EVIDENCE" -czf "$out" .)
  if [[ -n "${SUDO_UID:-}" ]]; then
    chown "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$out" 2>/dev/null || true
  fi
}
