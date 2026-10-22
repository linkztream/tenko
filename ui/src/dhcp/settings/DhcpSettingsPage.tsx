// The DHCP server settings (/settings/dhcp, administrators): the lease times of scopes that set
// none (default, minimum and maximum), whether scopes are authoritative, conflict detection and the
// lease history retention. The last two follow the security profile until they are set; the form
// shows the value in force either way. Saved with `PUT /dhcp/settings` and the revision read.
import { createSignal, Show, untrack } from "solid-js";
import { createLiveQuery, latest } from "../../api/live";
import { ErrorNotice } from "../../components/Notice";
import { PageHead } from "../../components/PageHead";
import { toast } from "../../components/toast";
import { t } from "../../i18n";
import { SettingsNav } from "../../settings/SettingsNav";
import { getSettings, putSettings, type Settings, type SettingsUpdate } from "../api";
import { LeaseFields, leaseProblem } from "../LeaseFields";
import { draftOfLease, leaseOfDraft, type LeaseDraft, type LeaseField } from "../model";
import { Check, describedBy, DhcpProblem, errorFor, Field, fieldErrors, hasField, unavailable } from "../Parts";
import "../dhcp.css";

function SettingsForm(props: { initial: Settings }) {
  const initial = untrack(() => props.initial);
  const [current, setCurrent] = createSignal<Settings>(initial);
  const [lease, setLease] = createSignal<LeaseDraft>(draftOfLease(initial.lease ?? { default_secs: 86_400, min_secs: 3600, max_secs: 604_800 }));
  const [authoritative, setAuthoritative] = createSignal(initial.authoritative ?? true);
  const [conflictFollow, setConflictFollow] = createSignal(initial.conflict_detection === undefined || initial.conflict_detection === null);
  const [conflict, setConflict] = createSignal(initial.conflict_detection ?? initial.effective_conflict_detection);
  const [historyFollow, setHistoryFollow] = createSignal(initial.history_days === undefined || initial.history_days === null);
  const [historyDays, setHistoryDays] = createSignal(String(initial.history_days ?? initial.effective_history_days));
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [leaseErrors, setLeaseErrors] = createSignal<Partial<Record<LeaseField, string>>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);

  const save = async (event: Event) => {
    event.preventDefault();
    if (busy()) return;
    const e: Record<string, string> = {};
    const le: Partial<Record<LeaseField, string>> = {};
    const body: SettingsUpdate = { authoritative: authoritative(), ddns: current().ddns ?? {} };
    const parsed = leaseOfDraft(lease(), current().lease);
    if (parsed.ok) body.lease = parsed.lease;
    else le[parsed.field] = leaseProblem(parsed.problem);
    if (!conflictFollow()) body.conflict_detection = conflict();
    if (!historyFollow()) {
      const days = historyDays().trim();
      if (!/^\d{1,4}$/.test(days) || Number(days) < 1 || Number(days) > 3650) e.history_days = t("dhcp.check.history_days");
      else body.history_days = Number(days);
    }
    setErrors(e);
    setLeaseErrors(le);
    setError(undefined);
    if (Object.keys(e).length > 0 || Object.keys(le).length > 0) return;
    setBusy(true);
    try {
      const next = await putSettings(current(), body);
      setCurrent(next);
      toast({ kind: "ok", title: t("dhcp.settings.saved") });
    } catch (err) {
      const fields = fieldErrors(err);
      if (hasField(fields, ["history_days", "lease"])) setErrors(fields);
      else setError(err);
    } finally {
      setBusy(false);
    }
  };

  const onOff = (on: boolean) => (on ? t("dhcp.settings.on") : t("dhcp.settings.off"));
  return (
    <form class="dhcp-form dhcp-settings-form" data-testid="dhcp-settings-form" onSubmit={(ev) => void save(ev)} novalidate>
      <section class="page-section" aria-labelledby="dhcp-settings-lease-title">
        <h2 id="dhcp-settings-lease-title">{t("dhcp.settings.lease")}</h2>
        <p class="muted">{t("dhcp.settings.lease_help")}</p>
        <LeaseFields id="lease" value={lease()} onChange={setLease} errors={{ ...leaseErrors(), ...(errorFor(errors(), "lease") && !leaseErrors().default ? { default: errorFor(errors(), "lease") } : {}) }} />
      </section>
      <section class="page-section" aria-labelledby="dhcp-settings-server-title">
        <h2 id="dhcp-settings-server-title">{t("dhcp.settings.server")}</h2>
        <Check id="authoritative" label={t("dhcp.settings.authoritative")} checked={authoritative()} onChange={setAuthoritative} help={t("dhcp.settings.authoritative_help")} />
        <Check id="conflict-follow" label={t("dhcp.settings.conflict_follow")} checked={conflictFollow()} onChange={setConflictFollow} />
        <p class="muted" data-testid="settings-effective-conflict" data-value={String(current().effective_conflict_detection)}>
          {t("dhcp.settings.effective", { value: onOff(current().effective_conflict_detection) })}
        </p>
        <Show when={!conflictFollow()}>
          <Check id="conflict" label={t("dhcp.settings.conflict")} checked={conflict()} onChange={setConflict} help={t("dhcp.settings.conflict_help")} />
        </Show>
        <Check id="history-follow" label={t("dhcp.settings.history_follow")} checked={historyFollow()} onChange={setHistoryFollow} />
        <p class="muted" data-testid="settings-effective-history" data-value={String(current().effective_history_days)}>
          {t("dhcp.settings.effective_days", { days: current().effective_history_days })}
        </p>
        <Show when={!historyFollow()}>
          <Field id="history_days" label={t("dhcp.settings.history_days")} error={errorFor(errors(), "history_days")} help={t("dhcp.settings.history_days_help")}>
            <input
              id="dhcp-f-history_days"
              class="input mono"
              inputmode="numeric"
              value={historyDays()}
              aria-invalid={errors().history_days ? "true" : undefined}
              aria-describedby={describedBy("history_days", errors().history_days, "help")}
              data-testid="field-history_days"
              onInput={(ev) => setHistoryDays(ev.currentTarget.value)}
            />
          </Field>
        </Show>
      </section>
      <ErrorNotice error={error()} />
      <div class="dhcp-actions">
        <button type="submit" class="btn primary" disabled={busy()} data-testid="dhcp-settings-save">
          {t("dhcp.settings.save")}
        </button>
      </div>
    </form>
  );
}

export default function DhcpSettingsPage() {
  const query = createLiveQuery({
    topics: [],
    fetch: async (signal) => {
      const settings = await getSettings(signal);
      return { value: settings, revision: settings.revision };
    },
  });
  const settings = () => latest(query);
  return (
    <div class="page" data-testid="page-dhcp-settings">
      <PageHead title={t("dhcp.settings.title")} />
      <SettingsNav />
      <div class="page-body dhcp-set-body">
        <p class="muted">{t("dhcp.settings.lede")}</p>
        <Show when={!unavailable(query.value.error)} fallback={<DhcpProblem error={query.value.error} />}>
          <ErrorNotice error={query.value.error} />
          <Show when={settings()} fallback={<Show when={!query.value.error}><p class="muted">{t("common.loading")}</p></Show>}>
            {(s) => <SettingsForm initial={s()} />}
          </Show>
        </Show>
      </div>
    </div>
  );
}
