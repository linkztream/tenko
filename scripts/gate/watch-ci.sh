#!/usr/bin/env bash
# Waits for the GitHub Actions runs of a commit, or for one run, and prints each run's conclusion
# and every job that did not succeed. Needs the GitHub CLI (gh), signed in, and
# TENKO_GATE_GITHUB_REPO=<owner>/<repository> (scripts/gate/README.md).
#
#   scripts/gate/watch-ci.sh <commit>      every run of that commit
#   scripts/gate/watch-ci.sh --run <id>    one run, such as a manually started workflow
#
# Exit codes: 0 every run succeeded (or was skipped), 1 a run did not succeed or none started,
# 2 bad usage or configuration.

repo=$TENKO_GATE_GITHUB_REPO
[ -n "$repo" ] || { echo "watch-ci: missing configuration: TENKO_GATE_GITHUB_REPO" >&2; exit 2; }
command -v gh > /dev/null || { echo "watch-ci: gh is not on PATH" >&2; exit 2; }

# The jobs of one run that neither succeeded nor were skipped.
failed_jobs() {
  gh run view -R "$repo" "$1" --json jobs \
    --jq '.jobs[]|select(.conclusion!="success" and .conclusion!="skipped")|"  FAILED JOB \(.name) (\(.databaseId)): \(.conclusion)"'
}

if [ "$1" = --run ] && [ -n "$2" ]; then
  id=$2
  until [ "$(gh run view -R "$repo" "$id" --json status --jq .status 2>/dev/null)" = completed ]; do sleep 60; done
  conclusion=$(gh run view -R "$repo" "$id" --json conclusion --jq .conclusion)
  gh run view -R "$repo" "$id" --json conclusion,headSha,event,workflowName \
    --jq '"\(.workflowName) \(.event) \(.headSha[0:8]): \(.conclusion)"'
  failed_jobs "$id"
  [ "$conclusion" = success ]
  exit
fi
[ $# -eq 1 ] && [ "${1#-}" = "$1" ] || { sed -n '6,7s/^#   //p' "${BASH_SOURCE[0]}" >&2; exit 2; }

sha=$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --verify --quiet "$1^{commit}") ||
  { echo "watch-ci: unknown commit $1" >&2; exit 2; }
runs() { gh run list -R "$repo" --commit "$sha" --json "$1" --jq "$2" 2>/dev/null; }

# A push starts its runs within seconds; wait up to five minutes for the first.
for _ in $(seq 1 20); do
  n=$(runs databaseId length)
  [ "${n:-0}" -gt 0 ] && break
  sleep 15
done
[ "${n:-0}" -gt 0 ] || { echo "no run for ${sha:0:8}"; exit 1; }
until [ "$(runs status '[.[]|select(.status!="completed")]|length')" = 0 ]; do sleep 60; done

runs databaseId,workflowName,conclusion '.[]|"\(.workflowName) \(.databaseId): \(.conclusion)"'
bad=$(runs databaseId,conclusion '.[]|select(.conclusion!="success" and .conclusion!="skipped")|.databaseId')
for id in $bad; do failed_jobs "$id"; done
[ -z "$bad" ]
