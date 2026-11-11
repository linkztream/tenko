# shellcheck shell=bash
# The driver's side of a compose lab (driver/host.sh has the whole picture): sourced by a
# lab's in-network script, which the host runs in the driver container with lab_run.
#
# The script's standard output and input are its channel to the host: what it prints passes
# through to the host's log (standard error too), and ctl sends one request on it and reads
# the answer. Standard input is closed for every other command, so that no command eats an
# answer.

[[ -n "${LAB_RPC:-}" ]] || {
  printf 'ctl: run by the host (driver/host.sh lab_run), not by hand\n' >&2
  exit 2
}
# The standard error joins the channel, so that a failed row's trace stays in its place in
# the log.
exec 3>&1 4<&0 0</dev/null 2>&1

# ctl <operation> <arguments...>: asks the host for one engine operation (driver/host.sh
# lab_op lists them: up, recreate, restart, stop, start, healthy, logs, disconnect, connect,
# setup-token, fresh, copy-volume, volume-rm, kill, exec, run, and what the lab adds);
# prints the operation's output and returns its status. The whole answer is read before any
# of it is printed: a reader that stops early (grep -q, head) must not leave the rest of it
# on the channel, where the next request would take it for its own.
ctl() {
  # A failed row's trace (set -x) shows the request and its answer, not the channel's reads.
  if [[ $- == *x* ]]; then
    { set +x; } 2>/dev/null
    local status=0
    ctl "$@" || status=$?
    set -x
    return "$status"
  fi
  local IFS=$'\x1f' line
  local -a reply=()
  if [[ "$*" == *$'\n'* ]]; then
    printf 'ctl: a request is one line\n' >&2
    return 2
  fi
  printf '%s %s\n' "$LAB_RPC" "$*" >&3
  while IFS= read -r line <&4; do
    if [[ "$line" == "$LAB_RPC end "* ]]; then
      ((${#reply[@]} == 0)) || printf '%s\n' "${reply[@]}" 2>/dev/null || true
      return "${line##* }"
    fi
    reply+=("$line")
  done
  printf 'ctl: the host closed the channel\n' >&2
  return 2
}

# lab_summary <line>: one line of the summary, which the host prints at the very end.
lab_summary() { printf '%s summary %s\n' "$LAB_RPC" "$1" >&3; }

# lab_rows_failed <count>: tells the host that rows failed in a round that ran to its end
# (the DHCP lab goes on to its next round then, and fails at the end).
lab_rows_failed() { printf '%s rows-failed %s\n' "$LAB_RPC" "$1" >&3; }
