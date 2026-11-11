// The DHCP server settings (/settings/dhcp, administrators): the lease times of scopes that set
// none (default, minimum and maximum), whether scopes are authoritative, conflict detection and the
// lease history retention, the relay agents the server trusts, and the limits per client and per
// scope. The last four follow the security profile until they are set; the form shows the value in
// force either way. A panel below lists the senders refused as relay agents (read from this server's
// node) with a button to trust each, and another the requests the limits refused; both are hidden
// when the node cannot be read. Saved with `PUT /dhcp/settings` and the revision read.
import { createResource, createSignal, For, Show, untrack } from "solid-js";
import { createLiveQuery, latest } from "../../api/live";
import { ErrorNotice, Notice } from "../../components/Notice";
import { PageHead } from "../../components/PageHead";
import { toast } from "../../components/toast";
import { formatDateTime, formatList, t } from "../../i18n";
import { SettingsNav } from "../../settings/SettingsNav";
import { getSettings, putSettings, type Settings, type SettingsUpdate } from "../api";
import { LeaseFields, leaseProblem } from "../LeaseFields";
import { thisNodeDhcp } from "../leases/api";
import { draftOfLease, leaseOfDraft, type LeaseDraft, type LeaseField } from "../model";
import { Check, describedBy, DhcpProblem, errorFor, Field, fieldErrors, hasField, unavailable } from "../Parts";
import { LIMITS, limitDraft, limitsOfDraft, limitsStored, type EffectiveLimits, type LimitName } from "./limits";
import { hostPrefix, MAX_TRUSTED_RELAYS, relayList } from "./relays";
import "../dhcp.css";

function relayProblem(check: Exclude<ReturnType<typeof relayList>, { ok: true }>): string {
  if (check.problem === "count") return t("dhcp.check.relays_count", { max: MAX_TRUSTED_RELAYS });
  const params = { line: check.line ?? 0, text: check.text ?? "" };
  if (check.problem === "format") return t("dhcp.check.relays_format", params);
  return t("dhcp.check.relays_host_bits", { ...params, suggest: hostPrefix(params.text.split("/")[0] ?? "") });
}

/** The panel of the senders this server refused as relay agents; hidden when the node cannot be read. */
function RelaysSeen(props: { settings: Settings; onTrust: (source: string) => Promise<void> }) {
  const [node] = createResource(() => props.settings.revision, () => thisNodeDhcp());
  const [failure, setFailure] = createSignal<unknown>();
  const report = () => (node.error ? undefined : node.latest?.relays);
  const listed = () => props.settings.trusted_relays ?? [];
  const refused = () => (report()?.refused ?? []).filter((r) => !listed().includes(hostPrefix(r.source)));
  const relayed = () => (props.settings.trusted_relays === undefined || props.settings.trusted_relays === null ? (report()?.relayed ?? []) : []);
  const unlogged = () => report()?.unlogged ?? 0;
  const trust = async (source: string) => {
    setFailure(undefined);
    try {
      await props.onTrust(source);
    } catch (err) {
      setFailure(err);
    }
  };
  return (
    <Show when={report() && (refused().length > 0 || relayed().length > 0)}>
      <section class="page-section" aria-labelledby="dhcp-settings-relays-seen-title" data-testid="settings-relays-seen">
        <h2 id="dhcp-settings-relays-seen-title">{t("dhcp.settings.relays_seen")}</h2>
        <Show when={relayed().length > 0}>
          <Notice kind="info" testid="settings-relays-relayed">
            {t("dhcp.settings.relays_seen_relayed")}
            <ul>
              <For each={relayed()}>
                {(r) => <li class="mono">{t("dhcp.settings.relays_seen_relayed_item", { network: r.network, relays: formatList(r.relays) })}</li>}
              </For>
            </ul>
          </Notice>
        </Show>
        <Show when={refused().length > 0}>
          <div class="table-wrap">
            <table class="plain" aria-label={t("dhcp.settings.relays_refused_label")} data-testid="settings-relays-refused">
              <thead>
                <tr>
                  <th scope="col">{t("dhcp.settings.relays_col_source")}</th>
                  <th scope="col">{t("dhcp.settings.relays_col_relay")}</th>
                  <th scope="col">{t("dhcp.settings.relays_col_count")}</th>
                  <th scope="col">{t("dhcp.settings.relays_col_last")}</th>
                  <th scope="col" />
                </tr>
              </thead>
              <tbody>
                <For each={refused()}>
                  {(r) => (
                    <tr data-testid="relay-refused" data-source={r.source}>
                      <td class="mono">
                        {r.source}{" "}
                        <Show when={r.seen_before}>
                          <span class="tag ok" data-testid="relay-known">
                            {t("dhcp.settings.relays_known")}
                          </span>
                        </Show>
                      </td>
                      <td class="mono">{r.relay}</td>
                      <td>{r.count}</td>
                      <td>{formatDateTime(r.last)}</td>
                      <td>
                        <button type="button" class="btn" aria-label={t("dhcp.settings.relays_trust_label", { source: r.source })} data-testid="relay-trust" onClick={() => void trust(r.source)}>
                          {t("dhcp.settings.relays_trust")}
                        </button>
                      </td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </div>
        </Show>
        <Show when={unlogged() > 0}>
          <p class="muted" data-testid="settings-relays-unlogged">
            {t("dhcp.settings.relays_unlogged", { count: unlogged() })}
          </p>
        </Show>
        <ErrorNotice error={failure()} />
      </section>
    </Show>
  );
}

function limitsSummary(l: EffectiveLimits): string {
  return t("dhcp.settings.limits_effective", {
    mac: limitValue(l.leases_per_mac),
    addresses: limitValue(l.addresses_per_duid),
    prefixes: limitValue(l.prefixes_per_duid),
    offers: limitValue(l.offers_per_second),
    cache: limitValue(l.renew_cache_percent, " %"),
  });
}

/** The value of a limit in a sentence: the number, or "off" for zero. */
function limitValue(value: number, suffix = ""): string {
  return value === 0 ? t("dhcp.settings.off") : `${value}${suffix}`;
}

function limitLabel(name: LimitName): string {
  switch (name) {
    case "leases_per_mac":
      return t("dhcp.settings.limit_leases_per_mac");
    case "addresses_per_duid":
      return t("dhcp.settings.limit_addresses_per_duid");
    case "prefixes_per_duid":
      return t("dhcp.settings.limit_prefixes_per_duid");
    case "offers_per_second":
      return t("dhcp.settings.limit_offers_per_second");
    case "renew_cache_percent":
      return t("dhcp.settings.limit_renew_cache");
  }
}

function limitHelp(name: LimitName, max: number): string {
  switch (name) {
    case "leases_per_mac":
      return t("dhcp.settings.limit_leases_per_mac_help", { max });
    case "addresses_per_duid":
      return t("dhcp.settings.limit_addresses_per_duid_help", { max });
    case "prefixes_per_duid":
      return t("dhcp.settings.limit_prefixes_per_duid_help", { max });
    case "offers_per_second":
      return t("dhcp.settings.limit_offers_per_second_help", { max });
    case "renew_cache_percent":
      return t("dhcp.settings.limit_renew_cache_help", { max });
  }
}

/** The readable name of a limit that refused a request. */
function refusedName(limit: string): string {
  switch (limit) {
    case "leases_per_mac":
      return t("dhcp.settings.limit_leases_per_mac");
    case "addresses_per_duid":
      return t("dhcp.settings.limit_addresses_per_duid");
    case "prefixes_per_duid":
      return t("dhcp.settings.limit_prefixes_per_duid");
    case "offers_per_second":
      return t("dhcp.settings.limit_offers_per_second");
    case "conflicts_per_mac":
      return t("dhcp.settings.limit_conflicts_per_mac");
    case "conflict_share":
      return t("dhcp.settings.limit_conflict_share");
    default:
      return limit;
  }
}

/** The panel of the requests the limits refused; hidden when the node cannot be read or nothing was refused. */
function LimitsRefused(props: { settings: Settings }) {
  const [node] = createResource(() => props.settings.revision, () => thisNodeDhcp());
  const report = () => (node.error ? undefined : node.latest?.limits);
  const refused = () => report()?.refused ?? [];
  const unlogged = () => report()?.unlogged ?? 0;
  return (
    <Show when={refused().length > 0}>
      <section class="page-section" aria-labelledby="dhcp-settings-limits-refused-title" data-testid="settings-limits-refused">
        <h2 id="dhcp-settings-limits-refused-title">{t("dhcp.settings.limits_refused")}</h2>
        <div class="table-wrap">
          <table class="plain" aria-label={t("dhcp.settings.limits_refused_label")}>
            <thead>
              <tr>
                <th scope="col">{t("dhcp.settings.limits_col_limit")}</th>
                <th scope="col">{t("dhcp.settings.limits_col_client")}</th>
                <th scope="col">{t("dhcp.settings.limits_col_network")}</th>
                <th scope="col">{t("dhcp.settings.limits_col_held")}</th>
                <th scope="col">{t("dhcp.settings.limits_col_count")}</th>
                <th scope="col">{t("dhcp.settings.limits_col_last")}</th>
              </tr>
            </thead>
            <tbody>
              <For each={refused()}>
                {(r) => (
                  <tr data-testid="limit-refused" data-limit={r.limit}>
                    <td>{refusedName(r.limit)}</td>
                    <td class="mono">{r.client ?? "\u2014"}</td>
                    <td class="mono">{r.network ?? r.scope}</td>
                    <td>{t("dhcp.settings.limits_held", { held: r.held, cap: r.cap })}</td>
                    <td>{r.count}</td>
                    <td>{formatDateTime(r.last)}</td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </div>
        <Show when={refused().some((r) => r.limit === "offers_per_second")}>
          <p class="muted" data-testid="settings-limits-offer-note">
            {t("dhcp.settings.limits_offer_note")}
          </p>
        </Show>
        <Show when={unlogged() > 0}>
          <p class="muted" data-testid="settings-limits-unlogged">
            {t("dhcp.settings.limits_unlogged", { count: unlogged() })}
          </p>
        </Show>
      </section>
    </Show>
  );
}

function SettingsForm(props: { initial: Settings }) {
  const initial = untrack(() => props.initial);
  const [current, setCurrent] = createSignal<Settings>(initial);
  const [lease, setLease] = createSignal<LeaseDraft>(draftOfLease(initial.lease ?? { default_secs: 86_400, min_secs: 3600, max_secs: 604_800 }));
  const [authoritative, setAuthoritative] = createSignal(initial.authoritative ?? true);
  const [conflictFollow, setConflictFollow] = createSignal(initial.conflict_detection === undefined || initial.conflict_detection === null);
  const [conflict, setConflict] = createSignal(initial.conflict_detection ?? initial.effective_conflict_detection);
  const [historyFollow, setHistoryFollow] = createSignal(initial.history_days === undefined || initial.history_days === null);
  const [historyDays, setHistoryDays] = createSignal(String(initial.history_days ?? initial.effective_history_days));
  const [relaysFollow, setRelaysFollow] = createSignal(initial.trusted_relays === undefined || initial.trusted_relays === null);
  const [relays, setRelays] = createSignal((initial.trusted_relays ?? []).join("\n"));
  const [limitsFollow, setLimitsFollow] = createSignal(!limitsStored(initial.limits));
  const [limits, setLimits] = createSignal(limitDraft(initial.limits, initial.effective_limits));
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
    if (!relaysFollow()) {
      const list = relayList(relays());
      if (list.ok) body.trusted_relays = list.list;
      else e.trusted_relays = relayProblem(list);
    } else if (current().trusted_relays !== undefined && current().trusted_relays !== null) body.clear_trusted_relays = true;
    if (!limitsFollow()) {
      const parsed = limitsOfDraft(limits());
      if (parsed.ok) body.limits = parsed.limits;
      else for (const [name, max] of Object.entries(parsed.problems)) e[`limits.${name}`] = t("dhcp.check.limits_range", { max });
    } else if (limitsStored(current().limits)) body.limits = {};
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
      if (hasField(fields, ["history_days", "lease", "trusted_relays", "clear_trusted_relays", "limits"])) setErrors(fields);
      else setError(err);
    } finally {
      setBusy(false);
    }
  };

  // The Trust button: the stored list with the sender added, saved with the stored values of the rest.
  const trust = async (source: string) => {
    const base = current();
    const prefix = hostPrefix(source);
    const list = [...(base.trusted_relays ?? [])];
    if (!list.includes(prefix)) list.push(prefix);
    const body: SettingsUpdate = { authoritative: base.authoritative ?? true, ddns: base.ddns ?? {}, trusted_relays: list };
    if (base.lease) body.lease = base.lease;
    if (base.conflict_detection !== undefined && base.conflict_detection !== null) body.conflict_detection = base.conflict_detection;
    if (base.history_days !== undefined && base.history_days !== null) body.history_days = base.history_days;
    if (limitsStored(base.limits)) body.limits = base.limits;
    const next = await putSettings(base, body);
    setCurrent(next);
    setRelaysFollow(false);
    setRelays((next.trusted_relays ?? list).join("\n"));
    toast({ kind: "ok", title: t("dhcp.settings.relays_trusted", { source }) });
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
      <section class="page-section" aria-labelledby="dhcp-settings-relays-title">
        <h2 id="dhcp-settings-relays-title">{t("dhcp.settings.relays")}</h2>
        <Check id="relays-follow" label={t("dhcp.settings.relays_follow")} checked={relaysFollow()} onChange={setRelaysFollow} />
        <Show when={relaysFollow()}>
          <Show
            when={current().effective_trust_any_relay}
            fallback={
              <p class="muted" data-testid="settings-relays-none">
                {t("dhcp.settings.relays_none")}
              </p>
            }
          >
            <Notice kind="warn" testid="settings-relays-trust-any">
              {t("dhcp.settings.relays_trust_any")}
            </Notice>
          </Show>
        </Show>
        <Show when={!relaysFollow()}>
          <Field id="trusted_relays" label={t("dhcp.settings.relays_list")} error={errorFor(errors(), "trusted_relays") ?? errorFor(errors(), "clear_trusted_relays")} help={t("dhcp.settings.relays_list_help")}>
            <textarea
              id="dhcp-f-trusted_relays"
              class="input mono"
              rows="5"
              spellcheck={false}
              value={relays()}
              aria-invalid={errors().trusted_relays || errors().clear_trusted_relays ? "true" : undefined}
              aria-describedby={describedBy("trusted_relays", errors().trusted_relays ?? errors().clear_trusted_relays, "help")}
              data-testid="field-trusted_relays"
              onInput={(ev) => setRelays(ev.currentTarget.value)}
            />
          </Field>
        </Show>
      </section>
      <RelaysSeen settings={current()} onTrust={trust} />
      <section class="page-section" aria-labelledby="dhcp-settings-limits-title">
        <h2 id="dhcp-settings-limits-title">{t("dhcp.settings.limits")}</h2>
        <p class="muted">{t("dhcp.settings.limits_help")}</p>
        <Check id="limits-follow" label={t("dhcp.settings.limits_follow")} checked={limitsFollow()} onChange={setLimitsFollow} />
        <p class="muted" data-testid="settings-effective-limits">
          {limitsSummary(current().effective_limits)}
        </p>
        <Show when={!limitsFollow()}>
          <For each={LIMITS}>
            {({ name, max }) => (
              <Field id={`limits_${name}`} label={limitLabel(name)} error={errorFor(errors(), `limits.${name}`)} help={limitHelp(name, max)}>
                <input
                  id={`dhcp-f-limits_${name}`}
                  class="input mono"
                  inputmode="numeric"
                  value={limits()[name]}
                  aria-invalid={errors()[`limits.${name}`] ? "true" : undefined}
                  aria-describedby={describedBy(`limits_${name}`, errors()[`limits.${name}`], "help")}
                  data-testid={`field-limits_${name}`}
                  onInput={(ev) => setLimits({ ...limits(), [name]: ev.currentTarget.value })}
                />
              </Field>
            )}
          </For>
        </Show>
      </section>
      <LimitsRefused settings={current()} />
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
