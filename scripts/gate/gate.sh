#!/usr/bin/env bash
# The gate: builds the branch merge-<name> in the gate's worktree from origin/main and the items
# of a spec file, regenerates the generated files and runs every check of the project, in order.
# scripts/gate/README.md describes the steps, the configuration and the output.
#
#   scripts/gate/gate.sh <name> <spec file>                    every step
#   scripts/gate/gate.sh <name> [<spec file>] --from <step>    merge-<name> as it stands, from a step on
#   scripts/gate/gate.sh <name> <spec file> --dry-run          print what would run, run nothing
#   scripts/gate/gate.sh --list                                the steps
#
# Exit codes: 0 green, 1 a step failed, 2 bad usage or configuration.

shopt -u patsub_replacement 2>/dev/null # a & in a configured value stays a & in --dry-run
GATE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)

IDS=(apply regenerate spelling test-lint ui ui-build fmt clippy clippy-linux nextest trace changelog deny fuzz build e2e)
TITLES=(
  "apply"
  "regenerate: openapi, ui types, i18n, traces"
  "spelling"
  "test lint"
  "ui typecheck, lint, tests"
  "ui build + size"
  "fmt"
  "clippy"
  "clippy (linux, wsl)"
  "nextest"
  "trace check, script tests"
  "changelog"
  "deny"
  "fuzz check"
  "server build with embedded ui"
  "e2e"
)
REQUIRED=(TENKO_GATE_WORKTREE TENKO_GATE_OUT_DIR TENKO_GATE_TARGET_DIR TENKO_GATE_TESTS_TARGET_DIR
  TENKO_GATE_FUZZ_TARGET_DIR TENKO_GATE_WSL_DISTRO TENKO_GATE_WSL_CHECKOUT)

usage() {
  sed -n '6,9s/^#   //p' "${BASH_SOURCE[0]}" >&2
  exit 2
}
die() {
  echo "gate: $*" >&2
  exit 2
}

# Output: the whole run goes to the log; step headings, the test summaries, the reruns and the
# result also go to the terminal (descriptor 3), and so does the end of a failed step's output.
tell() {
  echo "$*"
  echo "$*" >&3
}
step() {
  tell ""
  tell "=== $1 ($(date +%H:%M:%S)) ==="
  STEP_START=$(($(wc -l < "$LOG") + 1))
}
# The tests that passed only alone, kept across the runs of one name (--from adds to them).
note() {
  echo "$1" >> "$NOTES"
  tell "  $1"
}
finish() {
  if [ -s "$NOTES" ]; then
    tell "failed in a full run, then passed or failed alone:"
    while read -r n; do tell "  $n"; done < "$NOTES"
  fi
  tell "gate $NAME: $1; log $LOG"
}
fail() {
  echo "### FAILED: $1"
  echo "--- the end of the step's output:" >&3
  tail -n +"$STEP_START" "$LOG" | tail -20 >&3
  finish "RED at step $CURRENT ($1)"
  exit 1
}
# The final statuses of a nextest test that did not pass.
NOT_PASSED='FAIL|TIMEOUT|LEAK-FAIL|SIG[A-Z]+|ABORT'

# ---------------------------------------------------------------------------------------------
# The steps, in order. Each runs in the gate's worktree on merge-<name>.

step_apply() {
  node "$GATE_DIR/apply.mjs" "$NAME" "$SPEC" 2>&1 ||
    fail "$(tail -n +"$STEP_START" "$LOG" | sed -n 's/^apply: //p' | tail -1)"
}

step_regenerate() {
  CARGO_TARGET_DIR="$T_MAIN" cargo run -q -p tenko --locked -- openapi > docs/api/openapi.json || fail openapi
  (cd ui && node scripts/api-types.mjs && node scripts/i18n.mjs >/dev/null) || fail ui-regen
  node scripts/requirement-trace.mjs >/dev/null && node scripts/requirement-trace.mjs --phase 2 >/dev/null &&
    node scripts/requirement-trace.mjs --phase 3 >/dev/null && node scripts/requirement-trace.mjs --phase 4 >/dev/null ||
    fail trace-regen
  git add -A docs/api/openapi.json ui/src/api/generated ui/src/i18n/generated docs/plans
  git diff --cached --stat | tail -3
  git commit -q -m "chore: regenerate the OpenAPI document, the UI types and the traces" 2>/dev/null || echo "nothing to regenerate"
}

step_spelling() {
  node scripts/spelling.mjs || fail spelling
}

step_test_lint() {
  node scripts/test-lint.mjs || fail test-lint
  node scripts/test-lint.mjs --grown-since origin/main || fail test-lint-grown
}

# A UI test file that fails in the full run is run again alone: one that passes alone is named
# in the result, one that fails alone too fails the step.
step_ui() {
  local out="$P-ui-tests.txt" rc files f failed=""
  (cd ui && npm run -s typecheck && npm run -s lint) || fail ui
  (cd ui && npm run -s test) > "$out" 2>&1
  rc=$?
  grep -E "×|FAIL |Test Files|Tests |Errors " "$out" | head -40
  grep -E "^\s*(Test Files|Tests|Errors) " "$out" >&3
  [ "$rc" = 0 ] && return 0
  # An error outside a test names no file to run alone; a rerun of the failed files would hide it.
  ! grep -qE "Unhandled (Error|Rejection)|^\s*Errors\s+[0-9]+ error" "$out" || fail "ui (errors outside the tests in $out)"
  files=$(grep -oE "FAIL +src/[^ ]+" "$out" | awk '{print $2}' | sort -u)
  [ -n "$files" ] || fail "ui (no failed test file named in $out)"
  tell "the UI tests failed in the full run; each failed file alone:"
  for f in $files; do
    if (cd ui && npx vitest run "$f" 2>&1 | grep -E "Test Files|Tests |×"; exit "${PIPESTATUS[0]}"); then
      note "ui $f: passed alone"
    else
      note "ui $f: failed alone too"
      failed="$failed $f"
    fi
  done
  [ -z "$failed" ] || fail "ui (failed alone too:$failed)"
}

step_ui_build() {
  (cd ui && { npm run -s build 2>&1 | tail -3; [ "${PIPESTATUS[0]}" = 0 ] || exit 1; } &&
    { npm run -s size 2>&1 | tail -4; exit "${PIPESTATUS[0]}"; }) || fail ui-build
}

step_fmt() {
  cargo fmt --all -- --check || fail fmt
}

step_clippy() {
  CARGO_TARGET_DIR="$T_MAIN" cargo clippy --workspace --all-targets --all-features --locked -- -D warnings 2>&1 |
    grep -v "^\s*Compiling\|^\s*Checking\|^\s*Blocking\|^\s*Finished" | head -80
  [ "${PIPESTATUS[0]}" = 0 ] || fail clippy
}

# The checkout inside WSL fetches merge-<name> from this repository's git directory.
step_clippy_linux() {
  local sha common
  sha=$(git rev-parse HEAD)
  common=$(git rev-parse --path-format=absolute --git-common-dir)
  (wsl -d "$DISTRO" -- bash -lc "cd $WSL_CHECKOUT && git fetch -q \"\$(wslpath -u '$common')\" merge-$NAME && git checkout -q --detach $sha && TENKO_UI_STUB=1 CARGO_INCREMENTAL=0 cargo clippy --workspace --all-targets --locked -- -D warnings 2>&1 | grep -vE '^\s*(Compiling|Checking)' | tail -20; exit \${PIPESTATUS[0]}" 2>&1 |
    grep -v "Failed to translate"; exit "${PIPESTATUS[0]}") || fail clippy-linux
}

# Every test runs; the tests that fail in the full run run again alone, on one thread. One that
# passes alone is named in the result, one that fails alone too fails the step.
step_nextest() {
  local out="$P-nextest.txt" alone="$P-nextest-alone.txt" rc names filter status test
  CARGO_TARGET_DIR="$T_TESTS" cargo nextest run --workspace --all-features --locked --test-threads "$THREADS" --no-fail-fast 2>&1 |
    grep -v "^\s*Compiling\|^\s*Checking\|^\s*Blocking\|^\s*Finished\|^\s*PASS\|^\s*SLOW" > "$out"
  rc=${PIPESTATUS[0]}
  tail -40 "$out"
  echo "nextest exit $rc"
  grep -E '^\s*Summary' "$out" >&3
  cp target/nextest/default/junit.xml "$P-junit.xml" 2>/dev/null || true
  [ "$rc" = 0 ] && return 0
  names=$(grep -E "^\s*($NOT_PASSED) \[" "$out" | sed -E "s/^\s*($NOT_PASSED) \[[^]]*\] \([^)]*\) \S+ //" | sort -u)
  [ -n "$names" ] || fail "nextest (no failed test named in $out)"
  filter=$(printf '%s\n' "$names" | sed -E 's/^(.*)$/test(=\1)/' | paste -sd'|' -)
  tell "nextest failed in the full run; the failed tests alone, one thread:"
  CARGO_TARGET_DIR="$T_TESTS" cargo nextest run --workspace --all-features --locked --test-threads 1 --no-fail-fast -E "$filter" 2>&1 |
    grep -E "^\s*(Summary|PASS|$NOT_PASSED) \[" > "$alone"
  rc=${PIPESTATUS[0]}
  cat "$alone"
  while read -r status test; do
    note "nextest $test: $([ "$status" = PASS ] && echo passed alone || echo "$status alone too")"
  done < <(sed -nE "s/^\s*(PASS|$NOT_PASSED) \[[^]]*\] \([^)]*\) (.*)$/\1 \2/p" "$alone" | sort -u)
  [ "$rc" = 0 ] || fail "nextest (also alone)"
}

step_trace() {
  node scripts/requirement-trace.mjs --check || fail trace1
  node scripts/requirement-trace.mjs --phase 2 --check || fail trace2
  node scripts/requirement-trace.mjs --phase 3 --check || fail trace3
  node scripts/requirement-trace.mjs --phase 4 --check || fail trace4
  node --test "scripts/*.test.mjs" 2>&1 | grep -E "^# (pass|fail)|^not ok"
  [ "${PIPESTATUS[0]}" = 0 ] || fail script-tests
}

step_changelog() {
  node scripts/changelog.mjs validate || fail changelog-validate
  node scripts/changelog.mjs check --base origin/main --head HEAD || fail changelog-check
}

step_deny() {
  cargo deny check 2>&1 | grep -E "advisories|bans|licenses|sources" | tail -2
  [ "${PIPESTATUS[0]}" = 0 ] || fail deny
}

step_fuzz() {
  (cd fuzz && CARGO_TARGET_DIR="$T_FUZZ" cargo check --locked 2>&1 | tail -2; exit "${PIPESTATUS[0]}") || fail fuzz
}

# The server with the real UI, the binary the end-to-end tests drive.
step_build() {
  unset TENKO_UI_STUB
  (CARGO_TARGET_DIR="$T_TESTS" cargo build -p tenko --locked 2>&1 | tail -2; exit "${PIPESTATUS[0]}") || fail build
}

step_e2e() {
  unset TENKO_UI_STUB
  (cd ui && TENKO_BIN="$T_TESTS/debug/tenko.exe" CI=1 npm run -s e2e 2>&1 | tail -15; exit "${PIPESTATUS[0]}") || fail e2e
}

# ---------------------------------------------------------------------------------------------
# The command line

NAME="" SPEC="" FROM=apply DRY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --list)
      for i in "${!IDS[@]}"; do printf '%-13s %s\n' "${IDS[$i]}" "${TITLES[$i]}"; done
      exit 0
      ;;
    --from)
      [ $# -ge 2 ] || usage
      FROM=$2
      shift 2
      ;;
    --dry-run) DRY=1; shift ;;
    -*) usage ;;
    *)
      if [ -z "$NAME" ]; then NAME=$1; elif [ -z "$SPEC" ]; then SPEC=$1; else usage; fi
      shift
      ;;
  esac
done
[ -n "$NAME" ] || usage
[[ "$NAME" =~ ^[A-Za-z0-9._-]+$ ]] || die "a name has letters, digits, dot, dash and underscore only: $NAME"
START=-1
for i in "${!IDS[@]}"; do [ "${IDS[$i]}" = "$FROM" ] && START=$i; done
[ "$START" -ge 0 ] || die "unknown step $FROM; the steps are: ${IDS[*]}"
if [ "$FROM" = apply ]; then
  [ -n "$SPEC" ] || die "a run from the first step needs a spec file"
  [ -r "$SPEC" ] || die "cannot read the spec file $SPEC"
  SPEC="$(cd "$(dirname "$SPEC")" && pwd -P)/$(basename "$SPEC")"
fi

missing=()
for v in "${REQUIRED[@]}"; do [ -n "${!v}" ] || missing+=("$v"); done
[ ${#missing[@]} -eq 0 ] ||
  die "missing configuration: ${missing[*]} (scripts/gate/README.md, example in scripts/gate/gate.env.example)"
WT=$TENKO_GATE_WORKTREE OUT=$TENKO_GATE_OUT_DIR
T_MAIN=$TENKO_GATE_TARGET_DIR T_TESTS=$TENKO_GATE_TESTS_TARGET_DIR T_FUZZ=$TENKO_GATE_FUZZ_TARGET_DIR
DISTRO=$TENKO_GATE_WSL_DISTRO WSL_CHECKOUT=$TENKO_GATE_WSL_CHECKOUT
THREADS=${TENKO_GATE_TEST_THREADS:-6} JOBS=${TENKO_GATE_BUILD_JOBS:-6}
[[ "$THREADS" =~ ^[1-9][0-9]*$ && "$JOBS" =~ ^[1-9][0-9]*$ ]] ||
  die "TENKO_GATE_TEST_THREADS and TENKO_GATE_BUILD_JOBS are positive numbers"
# Relative paths would land inside the worktree or, for the fuzz package, under fuzz/.
for v in TENKO_GATE_WORKTREE TENKO_GATE_OUT_DIR TENKO_GATE_TARGET_DIR TENKO_GATE_TESTS_TARGET_DIR TENKO_GATE_FUZZ_TARGET_DIR; do
  [[ "${!v}" =~ ^([A-Za-z]:)?/ ]] || die "$v is not an absolute path: ${!v}"
done
# The outputs of a run; a run with --from keeps its own beside those of the full run.
P="$OUT/gate-$NAME$([ "$START" -gt 0 ] && echo "-from-$FROM")"
NOTES="$OUT/gate-$NAME-alone.txt"

export CARGO_BUILD_JOBS=$JOBS CARGO_PROFILE_DEV_DEBUG=line-tables-only CARGO_INCREMENTAL=0
export TENKO_DNSSEC_DOCKER=false TENKO_UI_STUB=1

if [ -n "$DRY" ]; then
  echo "cd $WT"
  echo "export CARGO_BUILD_JOBS=$JOBS CARGO_PROFILE_DEV_DEBUG=line-tables-only CARGO_INCREMENTAL=0"
  echo "export TENKO_DNSSEC_DOCKER=false TENKO_UI_STUB=1"
  for ((i = START; i < ${#IDS[@]}; i++)); do
    echo
    echo "=== ${TITLES[$i]} ==="
    if [ "${IDS[$i]}" = apply ]; then
      node "$GATE_DIR/apply.mjs" "$NAME" "$SPEC" --dry-run || exit 2
      continue
    fi
    body=$(declare -f "step_${IDS[$i]//-/_}" | sed '1,2d;$d')
    for v in T_MAIN T_TESTS T_FUZZ P NAME THREADS DISTRO WSL_CHECKOUT; do body=${body//\$$v/${!v}}; done
    echo "$body"
  done
  exit 0
fi

for tool in git node npm npx cargo wsl; do
  command -v "$tool" > /dev/null || die "$tool is not on PATH"
done
for sub in nextest deny; do
  cargo "$sub" --version > /dev/null 2>&1 || die "cargo $sub is not installed"
done
git -C "$WT" rev-parse --is-inside-work-tree > /dev/null 2>&1 || die "TENKO_GATE_WORKTREE is not a git worktree: $WT"
WT_REAL=$(cd "$WT" && pwd -P)
case "$GATE_DIR/" in
  "$WT_REAL"/*) die "run the gate from another checkout than TENKO_GATE_WORKTREE: its first step resets that worktree" ;;
esac
cd "$WT" || die "cannot enter $WT"
if [ "$START" -gt 0 ]; then
  [ "$(git rev-parse --abbrev-ref HEAD)" = "merge-$NAME" ] || die "--from $FROM continues merge-$NAME, which is not checked out in $WT"
fi
mkdir -p "$OUT" || die "cannot create $OUT"
LOG="$P.log"
: > "$LOG" || die "cannot write $LOG"
[ "$START" -gt 0 ] || : > "$NOTES"
exec 3>&1 > "$LOG" 2>&1

for ((i = START; i < ${#IDS[@]}; i++)); do
  CURRENT=${IDS[$i]}
  step "${TITLES[$i]}"
  "step_${CURRENT//-/_}"
done
step "done"
echo "GATE_GREEN"
finish GREEN
