// The DNSSEC tab of the zone page (WP6.3, ADR 0018): the signing state of the zone, the DS
// records to put at the parent (with a copy button), the keys with their states and dates,
// signing switched on and off through the zone's `dnssec` policy, and the key rollover with its
// job. The health findings of the zone (OPS-09) show as warnings. The state follows the `dns`
// topic (the signer writes the zone's rows) and the `jobs` topic (the rollover's steps).
import { A } from "@solidjs/router";
import { createSignal, For, Show, untrack } from "solid-js";
import { createLiveQuery, latest } from "../../api/live";
import { paths } from "../../app/paths";
import { ErrorNotice, Notice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { formatDateTime, t } from "../../i18n";
import { errorMessage } from "../../api/problem";
import { copyValue } from "../../secrets/clipboard";
import type { Zone } from "../api";
import { mayKeys, mayWriteDns } from "../access";
import { DnsProblem, unavailable } from "../Parts";
import {
  ALGORITHMS,
  dsLines,
  getDnssec,
  isNsec3,
  savePolicy,
  startRollover,
  usesCsk,
  type DnssecAlgorithm,
  type DnssecKey,
  type DnssecPolicy,
  type DnssecStatus,
  type KeyRole,
} from "./api";
import "./dnssec.css";

type Mode = NonNullable<DnssecPolicy["mode"]>;
const MODES: readonly Mode[] = ["off", "online", "imported"];

/** The title of a health finding of the zone. */
function findingTitle(code: string): string {
  switch (code) {
    case "dns.dnssec.clock_skew":
      return t("dns.dnssec.finding.clock_skew");
    case "dns.dnssec.expiring":
      return t("dns.dnssec.finding.expiring");
    case "dns.dnssec.resign_overdue":
      return t("dns.dnssec.finding.resign_overdue");
    case "dns.dnssec.expired":
      return t("dns.dnssec.finding.expired");
    default:
      return t("dns.dnssec.finding.other");
  }
}

function when(value: string | null | undefined): string {
  return value ? formatDateTime(value) : "–";
}

/** The form of the zone's policy: the mode, the algorithm of new keys, NSEC or NSEC3, one key. */
function PolicyForm(props: { zone: Zone; onSaved: (zone: Zone) => void }) {
  const zone = untrack(() => props.zone);
  const [mode, setMode] = createSignal<Mode>(zone.dnssec?.mode ?? "off");
  const [algorithm, setAlgorithm] = createSignal<DnssecAlgorithm>(zone.dnssec?.algorithm ?? "ecdsa_p256_sha256");
  const [nsec3, setNsec3] = createSignal(isNsec3(zone.dnssec));
  const [csk, setCsk] = createSignal(usesCsk(zone));
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  const readOnly = () => !mayWriteDns();
  const primary = () => props.zone.kind === "primary";

  const save = async (event: Event) => {
    event.preventDefault();
    if (busy() || readOnly()) return;
    setBusy(true);
    setError(undefined);
    try {
      const next = await savePolicy(props.zone, {
        mode: mode(),
        algorithm: algorithm(),
        denial: nsec3() ? { kind: "nsec3", iterations: 0, salt: "" } : { kind: "nsec" },
        csk: csk(),
      });
      toast({ kind: "ok", title: t("dns.dnssec.saved") });
      props.onSaved(next);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form class="page-section" data-testid="dnssec-policy" onSubmit={(e) => void save(e)}>
      <h2>{t("dns.dnssec.policy")}</h2>
      <fieldset class="form-row dnssec-modes" disabled={readOnly()}>
        <legend>{t("dns.dnssec.mode_label")}</legend>
        <For each={MODES}>
          {(m) => (
            <label>
              <input
                type="radio"
                name="dnssec-mode"
                value={m}
                checked={mode() === m}
                disabled={m === "online" && !primary()}
                data-testid={`dnssec-mode-${m}`}
                onChange={() => setMode(m)}
              />
              {t(`dns.dnssec.mode.${m}`)}
            </label>
          )}
        </For>
      </fieldset>
      <p>{t(`dns.dnssec.mode_help.${mode()}`)}</p>
      <Show when={mode() === "online"}>
        <div class="form-row">
          <label for="dnssec-algorithm">{t("dns.dnssec.algorithm_label")}</label>
          <select
            id="dnssec-algorithm"
            class="select"
            data-testid="dnssec-algorithm"
            disabled={readOnly()}
            value={algorithm()}
            onChange={(e) => setAlgorithm(e.currentTarget.value as DnssecAlgorithm)}
          >
            <For each={ALGORITHMS}>{(a) => <option value={a}>{t(`dns.dnssec.algorithm.${a}`)}</option>}</For>
          </select>
        </div>
        <label class="form-row">
          <input type="checkbox" data-testid="dnssec-nsec3" disabled={readOnly()} checked={nsec3()} onChange={(e) => setNsec3(e.currentTarget.checked)} />
          {t("dns.dnssec.nsec3")}
        </label>
        <label class="form-row">
          <input type="checkbox" data-testid="dnssec-csk" disabled={readOnly()} checked={csk()} onChange={(e) => setCsk(e.currentTarget.checked)} />
          {t("dns.dnssec.csk")}
        </label>
      </Show>
      <Show when={error()}>{(err) => <ErrorNotice error={err()} />}</Show>
      <Show when={!readOnly()}>
        <div class="form-row">
          <button type="submit" class="btn primary" data-testid="dnssec-save" disabled={busy()}>
            {t("dns.dnssec.save")}
          </button>
        </div>
      </Show>
    </form>
  );
}

/** The DS records for the parent, with a copy button. */
function DsCard(props: { apex: string; status: DnssecStatus }) {
  const lines = () => dsLines(props.apex, props.status);
  const copy = async () => {
    const outcome = await copyValue(lines().join("\n"));
    toast(outcome === "copied" ? { kind: "ok", title: t("dns.dnssec.ds_copied") } : { kind: "bad", title: t("dns.dnssec.ds_copy_blocked") });
  };
  return (
    <section class="page-section" data-testid="dnssec-ds">
      <h2>{t("dns.dnssec.ds")}</h2>
      <p>{t("dns.dnssec.ds_help")}</p>
      <Show when={lines().length > 0} fallback={<p class="muted">{t("dns.dnssec.ds_none")}</p>}>
        <pre class="mono dns-ds-lines" data-testid="dnssec-ds-lines">{lines().join("\n")}</pre>
        <div class="form-row">
          <button type="button" class="btn" data-testid="dnssec-ds-copy" onClick={() => void copy()}>
            {t("dns.dnssec.ds_copy")}
          </button>
        </div>
      </Show>
    </section>
  );
}

/** The keys with their states and dates. */
function KeysCard(props: { keys: readonly DnssecKey[] }) {
  const shown = () => props.keys.filter((key) => key.state !== "removed");
  return (
    <section class="page-section" data-testid="dnssec-keys">
      <h2>{t("dns.dnssec.keys")}</h2>
      <Show when={shown().length > 0} fallback={<p class="muted">{t("dns.dnssec.keys_none")}</p>}>
        <div class="table-wrap">
        <table class="plain">
          <thead>
            <tr>
              <th>{t("dns.dnssec.key.role")}</th>
              <th>{t("dns.dnssec.key.tag")}</th>
              <th>{t("dns.dnssec.algorithm_label")}</th>
              <th>{t("dns.dnssec.key.state")}</th>
              <th>{t("dns.dnssec.key.published")}</th>
              <th>{t("dns.dnssec.key.activated")}</th>
              <th>{t("dns.dnssec.key.retired")}</th>
            </tr>
          </thead>
          <tbody>
            <For each={shown()}>
              {(key) => (
                <tr data-testid="dnssec-key" data-key={`${key.role}-${key.key_tag}`} data-state={key.state}>
                  <td>{t(`dns.dnssec.role.${key.role}`)}</td>
                  <td class="mono">{key.key_tag}</td>
                  <td>{t(`dns.dnssec.algorithm.${key.algorithm}`)}</td>
                  <td>
                    <span class={key.state === "active" ? undefined : "muted"}>{t(`dns.dnssec.state.${key.state}`)}</span>
                  </td>
                  <td>{when(key.published)}</td>
                  <td>{when(key.activated)}</td>
                  <td>{when(key.retired)}</td>
                </tr>
              )}
            </For>
          </tbody>
        </table>
        </div>
      </Show>
    </section>
  );
}

/** The rollover buttons, or the rollover that runs with its job. */
function RolloverCard(props: { zone: Zone; status: DnssecStatus; onStarted: () => void }) {
  const [busy, setBusy] = createSignal(false);
  const roles = (): KeyRole[] => (usesCsk(props.zone) ? ["csk"] : ["zsk", "ksk"]);
  const start = async (role: KeyRole) => {
    if (busy()) return;
    setBusy(true);
    try {
      const job = await startRollover(props.zone.id, role);
      toast({ kind: "ok", title: t("dns.dnssec.rollover_started"), body: job.job_id });
      props.onStarted();
    } catch (err) {
      toast({ kind: "bad", title: t("dns.dnssec.rollover_failed"), body: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };
  return (
    <section class="page-section" data-testid="dnssec-rollover">
      <h2>{t("dns.dnssec.rollover")}</h2>
      <Show
        when={props.status.rollover_job}
        fallback={
          <>
            <p>{t("dns.dnssec.rollover_help")}</p>
            <Show when={mayKeys() && props.status.mode === "online"}>
              <div class="form-row">
                <For each={roles()}>
                  {(role) => (
                    <button type="button" class="btn" data-testid={`dnssec-roll-${role}`} disabled={busy()} onClick={() => void start(role)}>
                      {t(`dns.dnssec.roll.${role}`)}
                    </button>
                  )}
                </For>
              </div>
            </Show>
          </>
        }
      >
        {(job) => (
          <p data-testid="dnssec-rollover-running">
            {t("dns.dnssec.rollover_running")}{" "}
            <A href={paths.job(job())} data-testid="dnssec-rollover-job">
              {t("dns.dnssec.rollover_open_job")}
            </A>
          </p>
        )}
      </Show>
    </section>
  );
}

export function DnssecTab(props: { zone: Zone; onSaved: (zone: Zone) => void }) {
  const query = createLiveQuery({
    topics: ["dns", "jobs"],
    relevant: (e) => [...e.objects, ...e.deleted].some((o) => (o.kind === "zone" && o.id === props.zone.id) || o.kind === "job"),
    fetch: async (signal) => {
      const status = await getDnssec(props.zone.id, signal);
      return { value: status, revision: Date.now() };
    },
  });
  const status = () => latest(query);
  return (
    <div class="page-body dns-form" data-testid="dnssec-tab">
      <Show when={query.value.error && !status()}>
        {(_) => (
          <Show when={unavailable(query.value.error)} fallback={<ErrorNotice error={query.value.error} />}>
            <DnsProblem error={query.value.error} />
          </Show>
        )}
      </Show>
      <Show when={status()}>
        {(s) => (
          <>
            <For each={s().findings}>
              {(finding) => (
                <Notice kind="warn" role="status" title={findingTitle(finding.code)} testid="dnssec-finding">
                  {finding.detail}
                </Notice>
              )}
            </For>
            <section class="page-section" data-testid="dnssec-state" data-mode={s().mode}>
              <h2>{t("dns.dnssec.status")}</h2>
              <dl class="kv">
                <dt>{t("dns.dnssec.mode_label")}</dt>
                <dd data-testid="dnssec-mode">{t(`dns.dnssec.mode.${s().mode}`)}</dd>
                <dt>{t("dns.dnssec.signed_serial")}</dt>
                <dd data-testid="dnssec-signed-serial">{s().signed_serial ?? "–"}</dd>
                <dt>{t("dns.dnssec.last_signed")}</dt>
                <dd>{when(s().last_signed)}</dd>
                <dt>{t("dns.dnssec.expires")}</dt>
                <dd>{when(s().expires)}</dd>
                <dt>{t("dns.dnssec.next_resign")}</dt>
                <dd>{when(s().next_resign)}</dd>
              </dl>
            </section>
            <Show when={s().mode === "online"}>
              <DsCard apex={props.zone.name} status={s()} />
            </Show>
            <KeysCard keys={s().keys} />
            <Show when={s().mode === "online"}>
              <RolloverCard zone={props.zone} status={s()} onStarted={() => query.refetch()} />
            </Show>
          </>
        )}
      </Show>
      <PolicyForm
        zone={props.zone}
        onSaved={(next) => {
          props.onSaved(next);
          query.refetch();
        }}
      />
    </div>
  );
}
