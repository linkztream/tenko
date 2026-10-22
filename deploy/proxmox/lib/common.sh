#!/usr/bin/env bash
# Shared helpers of the Proxmox VE scripts in deploy/proxmox: messages, the STD output
# switch, and the lookup of a GitHub Actions runner release with its SHA-256. Sourced by
# lib/host.sh on the Proxmox host and by lib/container.sh inside a container; it does
# nothing on its own and changes no shell option.
#
# Usage: source "<dir>/common.sh"
#
# License: Business Source License 1.1; see LICENSE.md at the repository root.

[[ -n "${TENKO_COMMON_LOADED:-}" ]] && return 0
TENKO_COMMON_LOADED=1

# ── Messages ────────────────────────────────────────────────────────────────────────────────
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  TENKO_C_RED=$'\e[31m' TENKO_C_GREEN=$'\e[32m' TENKO_C_YELLOW=$'\e[33m'
  TENKO_C_BLUE=$'\e[36m' TENKO_C_BOLD=$'\e[1m' TENKO_C_OFF=$'\e[0m'
else
  TENKO_C_RED="" TENKO_C_GREEN="" TENKO_C_YELLOW="" TENKO_C_BLUE="" TENKO_C_BOLD="" TENKO_C_OFF=""
fi

msg_info() { printf '  %s..%s  %s\n' "$TENKO_C_BLUE" "$TENKO_C_OFF" "$*"; }
msg_ok() { printf '  %sok%s  %s\n' "$TENKO_C_GREEN" "$TENKO_C_OFF" "$*"; }
msg_warn() { printf '  %s!!%s  %s\n' "$TENKO_C_YELLOW" "$TENKO_C_OFF" "$*"; }
msg_error() { printf '  %sxx%s  %s\n' "$TENKO_C_RED" "$TENKO_C_OFF" "$*" >&2; }
msg_bold() { printf '%s%s%s\n' "$TENKO_C_BOLD" "$*" "$TENKO_C_OFF"; }

# ── STD: a command's output goes to the log, unless var_verbose=yes ────────────────────────
# Use as `$STD apt-get install ...`. On failure the last lines of the log are shown.
TENKO_LOG="${TENKO_LOG:-$(mktemp "${TMPDIR:-/tmp}/tenko-XXXXXX.log")}"
tenko_quiet() {
  local rc=0 from
  from=$(($(wc -l <"$TENKO_LOG" 2>/dev/null || echo 0) + 1))
  "$@" >>"$TENKO_LOG" 2>&1 || rc=$?
  if ((rc != 0)); then
    msg_error "Failed (exit ${rc}): $1 ... (log: ${TENKO_LOG})"
    tail -n "+${from}" "$TENKO_LOG" | tail -n 20 | sed 's/^/      /' >&2
  fi
  return "$rc"
}
tenko_set_std() {
  if [[ "${var_verbose:-${TENKO_VERBOSE:-no}}" == "yes" ]]; then
    STD=""
  else
    # shellcheck disable=SC2034 # STD is read by the scripts that source this file.
    STD="tenko_quiet"
  fi
}
tenko_set_std

# ── GitHub Actions runner release ───────────────────────────────────────────────────────────
# tenko_release_json [<tag>]: the JSON of an actions/runner release (the latest without a
# tag) on standard output. GITHUB_TOKEN, when set, goes in the Authorization header through
# standard input (curl -H @-), so that it is in no argument list.
tenko_release_json() {
  local path="releases/latest" auth=()
  [[ -n "${1:-}" ]] && path="releases/tags/${1}"
  [[ -n "${GITHUB_TOKEN:-}" ]] && auth=(-H @-)
  printf 'Authorization: Bearer %s\n' "${GITHUB_TOKEN:-}" |
    curl -fsSL --retry 2 --connect-timeout 10 -H 'Accept: application/vnd.github+json' \
      "${auth[@]}" "https://api.github.com/repos/actions/runner/${path}"
}

# tenko_release_version: the version (tag_name without the v) of the release JSON on
# standard input. jq when present, else a pattern match (a Proxmox host has no jq).
tenko_release_version() {
  local tag
  if command -v jq >/dev/null 2>&1 && [[ -z "${TENKO_NO_JQ:-}" ]]; then
    tag="$(jq -r '.tag_name // empty')"
  else
    tag="$(grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n 1 | sed 's/.*:[[:space:]]*"\(.*\)"$/\1/')"
  fi
  tag="${tag#v}"
  [[ "$tag" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  printf '%s\n' "$tag"
}

# tenko_release_body: the release notes of the release JSON on standard input, one line per
# line. Without jq the escaped line breaks of the JSON string are expanded; the result then
# also holds the other fields, which the anchored match below never confuses with a
# checksum line.
tenko_release_body() {
  if command -v jq >/dev/null 2>&1 && [[ -z "${TENKO_NO_JQ:-}" ]]; then
    jq -r '.body // empty' | tr -d '\r'
  else
    sed -e 's/\\r\\n/\n/g' -e 's/\\n/\n/g' | tr -d '\r'
  fi
}

# tenko_runner_sha256 <version>: the SHA-256 of actions-runner-linux-x64-<version>.tar.gz
# from the release notes on standard input. The notes list one package per line, as
# "- actions-runner-linux-x64-<version>.tar.gz <!-- BEGIN SHA linux-x64 --><sha><!-- ... -->";
# the match is anchored on the file name, so the download lines of the same notes (which
# name the file without a checksum) and the other platforms do not count.
tenko_runner_sha256() {
  local file="actions-runner-linux-x64-${1}.tar.gz" line sum
  line="$(grep -F -- "- ${file} " | head -n 1)" || true
  sum="$(grep -Eo '[0-9a-f]{64}' <<<"$line" | head -n 1)" || true
  [[ -n "$sum" ]] || return 1
  printf '%s\n' "$sum"
}

# tenko_resolve_runner_release: sets RUNNER_VERSION and RUNNER_SHA256. Values already set
# win (a version alone is looked up for its checksum); otherwise the latest release is read
# from the GitHub API. Fails, with the instruction to pass both by hand, when the version or
# the checksum cannot be parsed. Nothing is installed here.
tenko_resolve_runner_release() {
  local json version sum
  RUNNER_VERSION="${RUNNER_VERSION:-}"
  RUNNER_VERSION="${RUNNER_VERSION#v}"
  RUNNER_SHA256="${RUNNER_SHA256:-}"
  RUNNER_SHA256="${RUNNER_SHA256,,}"
  if [[ -n "$RUNNER_SHA256" && -z "$RUNNER_VERSION" ]]; then
    msg_error "A runner SHA-256 was given without a version; give both, or neither"
    return 1
  fi
  if [[ -n "$RUNNER_VERSION" && -n "$RUNNER_SHA256" ]]; then
    TENKO_RUNNER_SOURCE="given"
  else
    if ! json="$(tenko_release_json "${RUNNER_VERSION:+v${RUNNER_VERSION}}")"; then
      msg_error "Could not read the actions/runner release ${RUNNER_VERSION:-latest} from the GitHub API"
      tenko_runner_release_hint
      return 1
    fi
    if ! version="$(tenko_release_version <<<"$json")"; then
      msg_error "Could not parse the runner version from the GitHub API"
      tenko_runner_release_hint
      return 1
    fi
    if ! sum="$(tenko_release_body <<<"$json" | tenko_runner_sha256 "$version")"; then
      msg_error "Could not find the SHA-256 of actions-runner-linux-x64-${version}.tar.gz in the release notes"
      tenko_runner_release_hint
      return 1
    fi
    RUNNER_VERSION="$version"
    RUNNER_SHA256="$sum"
    # shellcheck disable=SC2034 # Read by the callers, for their messages.
    TENKO_RUNNER_SOURCE="the release notes on GitHub"
  fi
  if [[ ! "$RUNNER_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ || ! "$RUNNER_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
    msg_error "Not a runner version and SHA-256: '${RUNNER_VERSION}' '${RUNNER_SHA256}'"
    tenko_runner_release_hint
    return 1
  fi
}

tenko_runner_release_hint() {
  msg_error "Pass both by hand: var_runner_version and var_runner_sha256 (RUNNER_VERSION and RUNNER_SHA256"
  msg_error "for the install script), from the repository's Settings, Actions, Runners, New self-hosted runner"
}
