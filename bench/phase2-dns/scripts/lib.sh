# Shared helpers of the Phase 2 DNS procedure scripts. Sourced, never run.
#
# Linux runs measure the static musl binary of tenko, the binary that ships:
#   cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl
# that is target/x86_64-unknown-linux-musl/release/tenko. Windows runs measure the release
# build. Every measurement is a single-node figure (docs/plans/phase-2-plan.md, section 2.10).

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"

say() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$1"; }
die() { printf 'error: %s\n' "$1" >&2; exit 2; }

# Appends to the meta file and prints.
note() { say "$1"; [ -z "${META:-}" ] || printf '%s\n' "$1" >> "$META"; }

# Prints one line "machine: ..." for the meta file: CPU, cores, RAM, OS.
machine_line() {
  case "$(uname -s)" in
    Linux)
      local cpu mem os
      cpu=$(awk -F: '/model name/ { sub(/^ /, "", $2); print $2; exit }' /proc/cpuinfo)
      mem=$(awk '/MemTotal/ { printf "%.1f", $2 / 1048576 }' /proc/meminfo)
      os=$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-Linux}")
      echo "machine: $cpu, $(nproc) logical CPUs, $mem GiB RAM, $os, kernel $(uname -r)"
      ;;
    *)
      echo "machine: $(uname -srm) (Windows or other; read CPU and RAM from the system and record them in the results file)"
      ;;
  esac
}

# Refuses a dynamically linked server binary on Linux. The shipped Linux binary is the static
# musl build; a glibc build is neither shipped nor measured. --allow-dynamic overrides the
# refusal (the run is then marked in the meta file and must not be published).
# Usage: check_linkage BINARY ALLOW_DYNAMIC(0|1)
check_linkage() {
  local bin="$1" allow="$2"
  [ -n "$bin" ] || return 0
  [ -e "$bin" ] || die "server binary not found: $bin"
  [ "$(uname -s)" = Linux ] || return 0
  if ldd "$bin" 2>&1 | grep -Eq 'statically linked|not a dynamic executable'; then
    note "binary: $bin (static)"
    return 0
  fi
  note "WARNING: $bin is dynamically linked; the shipped Linux binary is the static musl build"
  note "         (cargo build -p tenko --release --locked --target x86_64-unknown-linux-musl)"
  if [ "$allow" != 1 ]; then
    die "refusing to measure a dynamically linked binary on Linux (--allow-dynamic overrides, the numbers are then not publishable)"
  fi
  note "NOT PUBLISHABLE: measured with --allow-dynamic"
}

# Windows pid of an MSYS (Git Bash) process; the harness samples by Windows pid.
native_pid() {
  if [ -r "/proc/$1/winpid" ]; then cat "/proc/$1/winpid"; else echo "$1"; fi
}

# Waits until a server answers on UDP: short probe runs of the load generator.
# Usage: wait_ready HARNESS TARGET NAMES [TRIES]
wait_ready() {
  local harness="$1" target="$2" names="$3" tries="${4:-30}" out n
  while [ "$tries" -gt 0 ]; do
    out=$("$harness" load --target "$target" --names "$names" --clients 1 --inflight 1 \
      --duration 1s --warmup 0s --timeout 200ms 2>/dev/null || true)
    n=$(printf '%s\n' "$out" | awk '$1 == "received" { gsub(",", "", $2); print $2 }')
    [ "${n:-0}" -gt 0 ] && return 0
    tries=$((tries - 1))
  done
  return 1
}
