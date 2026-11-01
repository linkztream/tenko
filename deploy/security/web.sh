# shellcheck shell=bash
# shellcheck disable=SC2034,SC2154
# (Sourced by round.sh: here, repo, API_URL, WORK, EVIDENCE and api come from round.sh, and
# the row_* variables set here are read by row() of lib.sh.)
#
# The web rows of the security round (SA4 of docs/plans/security-audit-plan.md), sourced by
# round.sh so they share the row helper, the bundle and the node under test:
#
#   web.unauth        every operation of the OpenAPI document the node serves that
#                     rules/public-operations.txt does not name answers 401 or 403 without a
#                     session or a token, and the operations the document declares public
#                     are exactly that list (nodeapi.py unauth). Blocking (SA-Q1 (b)).
#   web.ui_baseline   the ZAP baseline scan (passive rules, a one-minute spider) of the web
#                     interface, signed in as an account with the role viewer, with
#                     rules/zap-baseline.tsv. Reporting: listed in SEC_REPORTING_ROWS (lib.sh).
#   web.api_baseline  the ZAP API scan of the node's OpenAPI document in safe mode (passive
#                     rules only) with a scoped token of the role viewer, the same rule file.
#                     Reporting.
#
# The account, its session and the token are created through the API at the start of the
# group (nodeapi.py scan-access) and revoked at its end (scan-revoke). Their values live in
# the round's private work directory, reach ZAP through the environment of the container
# and never its command line, and are masked in every file of the bundle before it is
# packed (web_mask_evidence). ZAP runs from compose.yml, pinned by digest, in the job that
# holds no token able to write (section 4.6 of the plan).

# web_wanted: whether a row of the group is selected.
web_wanted() { wanted web.unauth || wanted web.ui_baseline || wanted web.api_baseline; }

# run_web_rows: called from round.sh main().
run_web_rows() {
  WEB_ACCESS="$WORK/web-access"
  WEB_SECRETS="$WORK/web-secrets"
  WEB_ACCESS_OK=0
  mkdir -p "$EVIDENCE/scan" "$EVIDENCE/node"

  row web.unauth "every operation outside the public list answers 401 or 403 without credentials" row_web_unauth

  if wanted web.ui_baseline || wanted web.api_baseline; then
    web_access_open
  fi
  row web.ui_baseline "the web interface has no passive ZAP finding the rules fail" row_web_ui_baseline
  row web.api_baseline "the API has no passive ZAP finding the rules fail" row_web_api_baseline

  # Mask first (the secrets are still known), then revoke, which removes the secret files.
  web_mask_evidence
  web_access_close
}

# ── The scan access: an account with the role viewer, its session, a scoped viewer token ───
web_access_open() {
  install -d -m 0700 "$WEB_ACCESS"
  local ok=0
  api scan-access --dir "$WEB_ACCESS" >"$EVIDENCE/node/web-access.json" 2>"$EVIDENCE/node/web-access.err" && ok=1
  # The values to mask in the bundle, one per line: the token, and the session cookie with
  # and without its name; also after a partial failure, for what was created. WORK is
  # private; the file goes with it at the end.
  (
    umask 077
    if [[ -s "$WEB_ACCESS/token" ]]; then
      tr -d '\n' <"$WEB_ACCESS/token"
      echo
    fi
    if [[ -s "$WEB_ACCESS/cookie" ]]; then
      tr -d '\n' <"$WEB_ACCESS/cookie"
      echo
      cut -d= -f2- "$WEB_ACCESS/cookie" | tr -d '\n'
      echo
    fi
  ) >>"$WEB_SECRETS"
  chmod 0600 "$WEB_SECRETS"
  if ((ok == 1)); then
    WEB_ACCESS_OK=1
  else
    echo "round: the scan account, session or token could not be created (node/web-access.err in the bundle)" >&2
  fi
}

web_access_close() {
  [[ -d "${WEB_ACCESS:-}" ]] || return 0
  if ! api scan-revoke --dir "$WEB_ACCESS" >"$EVIDENCE/node/web-revoke.json" 2>>"$EVIDENCE/node/web-access.err"; then
    echo "round: the scan token was not revoked or is still accepted (node/web-revoke.json in the bundle)" >&2
  fi
  rm -rf "$WEB_ACCESS"
}

# web_mask_evidence: replaces every value of WEB_SECRETS in every file of the bundle with
# "<masked>", then checks that none is left; a file that still holds one (it cannot be
# rewritten) is removed from the bundle and named in node/web-masking.txt. round.sh calls
# it once more just before it packs the bundle, after the node's journal is written.
web_mask_evidence() {
  [[ -s "${WEB_SECRETS:-}" ]] || return 0
  python3 -I - "$WEB_SECRETS" "$EVIDENCE" >"$EVIDENCE/node/web-masking.txt" 2>&1 <<'PY' || true
import os, sys
with open(sys.argv[1], "rb") as f:
    secrets = sorted({s.strip() for s in f.read().splitlines() if len(s.strip()) >= 8}, key=len, reverse=True)
changed = removed = 0
for root, _dirs, files in os.walk(sys.argv[2]):
    for name in files:
        path = os.path.join(root, name)
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            continue
        masked = data
        for secret in secrets:
            masked = masked.replace(secret, b"<masked>")
        if masked != data:
            with open(path, "wb") as f:
                f.write(masked)
            changed += 1
        with open(path, "rb") as f:
            again = f.read()
        if any(secret in again for secret in secrets):
            os.remove(path)
            removed += 1
            print(f"removed, a secret could not be masked: {os.path.relpath(path, sys.argv[2])}")
print(f"masked the scan secrets in {changed} file(s); removed {removed}")
PY
}

# ── web.unauth ────────────────────────────────────────────────────────────────────────────
row_web_unauth() {
  row_tool=nodeapi.py
  row_version="$(python3 --version 2>&1)"
  local rc=0 log="$EVIDENCE/rows/web.unauth.log"
  api unauth --public "$here/rules/public-operations.txt" \
    --out "$EVIDENCE/scan/web.unauth.jsonl" --findings "$EVIDENCE/scan/web.unauth.findings.json" \
    --document-out "$EVIDENCE/scan/openapi.served.json" --fallback "$repo/docs/api/openapi.json" || rc=$?
  evidence_add scan/web.unauth.jsonl scan/openapi.served.json
  [[ -s "$EVIDENCE/scan/web.unauth.findings.json" ]] && row_findings=scan/web.unauth.findings.json
  if ((rc != 0)); then
    row_reason="$(grep '^FAIL ' "$log" | head -n 5 | sed 's/^FAIL //' | tr '\n' ';')"
    [[ -n "$row_reason" ]] || row_reason="the walk did not complete (status $rc)"
    return 1
  fi
}

# ── web.ui_baseline and web.api_baseline: ZAP ─────────────────────────────────────────────

# zap_image: the pinned image, for the row's version field.
zap_image() { sed -nE 's/^ *image: (ghcr\.io\/zaproxy\/[^ ]+).*/\1/p' "$here/compose.yml" | head -n 1; }

# zap_run <tag> <auth header> <auth value> <ZAP script and arguments...>: runs one ZAP scan
# with /zap/wrk at scan/zap-<tag>/ (writable for the image's user), the rule file copied in as
# rules.tsv, and the scan's credential in the environment of the container. Returns ZAP's
# exit status: 0 no alert, 1 an alert of a FAIL rule, 2 alerts of WARN rules, 3 or more the
# scan failed.
zap_run() {
  local tag="$1" header="$2" value="$3" wrk="$EVIDENCE/scan/zap-$1"
  shift 3
  install -d -m 0777 "$wrk"
  install -m 0644 "$here/rules/zap-baseline.tsv" "$wrk/rules.tsv"
  local host="${API_URL#https://}"
  host="${host%%:*}"
  ZAP_AUTH_HEADER="$header" ZAP_AUTH_HEADER_VALUE="$value" ZAP_AUTH_HEADER_SITE="$host" \
    compose_run -v "$wrk:/zap/wrk:rw" -e ZAP_AUTH_HEADER -e ZAP_AUTH_HEADER_VALUE -e ZAP_AUTH_HEADER_SITE \
    zap "$@"
}

# zap_verdict <tag>: reads scan/zap-<tag>/zap-<tag>.json with the rule file and the served
# OpenAPI document, writes scan/zap-<tag>.findings.json (one finding per plugin and path
# template, for the report) and prints one line per alert. Exit status 1 when an alert of a
# FAIL rule was raised, 3 when there is no report.
zap_verdict() {
  local tag="$1"
  python3 -I - "$EVIDENCE/scan/zap-$tag/zap-$tag.json" "$here/rules/zap-baseline.tsv" \
    "$EVIDENCE/scan/openapi.served.json" "$EVIDENCE/scan/zap-$tag.findings.json" <<'PY'
import json, sys, urllib.parse
report, rules_path, doc_path, out_path = sys.argv[1:5]
rules = {}
with open(rules_path, encoding="utf-8") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) >= 2:
            rules[parts[0].strip()] = parts[1].strip().upper()
templates = []
try:
    with open(doc_path, encoding="utf-8") as f:
        templates = [t.split("/") for t in json.load(f).get("paths", {})]
except (OSError, ValueError):
    pass

def template(path):
    """The OpenAPI template a request path belongs to (most literal segments win)."""
    segments = path.split("/")
    best = None
    for t in templates:
        if len(t) != len(segments):
            continue
        if all(a == b or (a.startswith("{") and a.endswith("}")) for a, b in zip(t, segments)):
            literal = sum(1 for a in t if not a.startswith("{"))
            if best is None or literal > best[0]:
                best = (literal, "/".join(t))
    return best[1] if best else path

try:
    with open(report, encoding="utf-8") as f:
        data = json.load(f)
except (OSError, ValueError):
    print("no ZAP report was written")
    sys.exit(3)
severity = {"3": "High", "2": "Medium", "1": "Low", "0": "Info"}
findings, counts, failed = {}, {"FAIL": 0, "WARN": 0, "IGNORE": 0}, []
for site in data.get("site", []):
    for alert in site.get("alerts", []):
        plugin = str(alert.get("pluginid", ""))
        action = rules.get(plugin, "WARN")  # ZAP's own default for a rule not in the file
        action = action if action in counts else "WARN"
        counts[action] += 1
        instances = alert.get("instances") or [{"uri": site.get("@name", "")}]
        name = alert.get("alert") or alert.get("name") or plugin
        print(f"{action} {plugin} {severity.get(str(alert.get('riskcode')), 'Info')} {name} ({len(instances)} instance(s))")
        if action == "IGNORE":
            continue
        if action == "FAIL":
            failed.append(f"{plugin} {name}")
        for instance in instances:
            path = urllib.parse.urlsplit(instance.get("uri", "")).path or "/"
            location = template(path) if path.startswith("/api/") else path
            entry = findings.setdefault(
                (plugin, location),
                {
                    "tool": "zap",
                    "rule": plugin,
                    "location": location,
                    "severity": severity.get(str(alert.get("riskcode")), "Info"),
                    "title": name,
                    "action": action,
                    "count": 0,
                },
            )
            entry["count"] += 1
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(sorted(findings.values(), key=lambda e: (e["rule"], e["location"])), f, indent=1)
print(f"alerts: {counts['FAIL']} FAIL, {counts['WARN']} WARN, {counts['IGNORE']} IGNORE; {len(findings)} finding(s) by plugin and path")
if failed:
    print("FAIL rules raised: " + "; ".join(failed))
    sys.exit(1)
PY
}

# zap_row <tag> <auth header> <auth value> <ZAP script and arguments...>: the body of both
# ZAP rows.
zap_row() {
  # Two declarations: one `local` expands all its words before it assigns, so "$tag" in the
  # same line would be unbound under `set -u`.
  local tag="$1" rc=0 verdict=0
  local log="$EVIDENCE/rows/web.${tag}_baseline.log"
  row_tool=zap
  row_version="$(zap_image)"
  if [[ "$WEB_ACCESS_OK" != 1 ]]; then
    row_reason="the scan account, session or token could not be created (node/web-access.err in the bundle)"
    evidence_add node/web-access.err
    return 1
  fi
  zap_run "$@" || rc=$?
  evidence_add "scan/zap-$tag/zap-$tag.json" "scan/zap-$tag/zap-$tag.html"
  zap_verdict "$tag" || verdict=$?
  [[ -s "$EVIDENCE/scan/zap-$tag.findings.json" ]] && {
    row_findings="scan/zap-$tag.findings.json"
    evidence_add "scan/zap-$tag.findings.json"
  }
  if ((rc >= 3 || verdict == 3)); then
    row_reason="the ZAP scan did not complete (ZAP exit status $rc)"
    return 1
  fi
  if ((verdict != 0)); then
    row_reason="$(grep '^FAIL rules raised: ' "$log" | tail -n 1 | sed 's/^FAIL rules raised: /alerts of FAIL rules: /')"
    return 1
  fi
}

row_web_ui_baseline() {
  # The baseline scan: a one-minute spider from the start page and the passive rules, as the
  # viewer account; -g writes ZAP's full rule list of this version into the bundle, for the
  # review of the rule file.
  zap_row ui Cookie "$(cat "$WEB_ACCESS/cookie" 2>/dev/null)" \
    zap-baseline.py -t "$API_URL/" -c rules.tsv -J zap-ui.json -r zap-ui.html -g rules-default.tsv -m 1 -T 10
  local rc=$?
  evidence_add scan/zap-ui/rules-default.tsv
  return "$rc"
}

row_web_api_baseline() {
  # The API scan in safe mode (-S: the import of the OpenAPI document and the passive rules,
  # no active scan), with the scoped viewer token, so every request the import sends that
  # would change something is refused.
  zap_row api Authorization "Bearer $(cat "$WEB_ACCESS/token" 2>/dev/null)" \
    zap-api-scan.py -t "$API_URL/api/v1/openapi.json" -f openapi -S -c rules.tsv -J zap-api.json -r zap-api.html -T 15
}
