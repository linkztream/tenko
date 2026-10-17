// The settings and history tabs of the zone page. Settings: the SOA values, the serial policy
// and the description (one PATCH with the zone's revision) and the NS RRset of the apex (one
// batch change), saved together. History: the serial served now, the last change, and the
// newest audit records of the zone for those who read the audit log (until a journal route
// exists, the lead's decision for WP4.5).
import { A } from "@solidjs/router";
import { createMemo, createResource, createSignal, For, Show, untrack } from "solid-js";
import { ApiError } from "../api/problem";
import { ErrorNotice, Notice } from "../components/Notice";
import { toast } from "../components/toast";
import { TimeAgo } from "../grid/cells";
import { formatDateTime, t } from "../i18n";
import {
  changeRecords,
  listRecords,
  SERIAL_POLICIES,
  serialPolicy,
  servedSerial,
  updateZone,
  zoneAudit,
  type SerialPolicy,
  type SoaDefaults,
  type Zone,
  type ZonePatch,
} from "./api";
import { mayWriteDns } from "./access";
import { canonical, parseTtl, splitList, targetName, validName } from "./model";
import { describedBy, Field, fieldErrors } from "./Parts";
import { paths } from "../app/paths";

const SOA_NUMBERS = ["refresh", "retry", "expire", "minimum", "ttl"] as const;
type SoaNumber = (typeof SOA_NUMBERS)[number];

export function SettingsTab(props: { zone: Zone; onSaved: (zone: Zone) => void }) {
  const zone = untrack(() => props.zone);
  const readOnly = () => !mayWriteDns();
  const [mname, setMname] = createSignal(zone.soa.mname);
  const [rname, setRname] = createSignal(zone.soa.rname);
  const [numbers, setNumbers] = createSignal<Record<SoaNumber, string>>({
    refresh: String(zone.soa.refresh ?? 3600),
    retry: String(zone.soa.retry ?? 900),
    expire: String(zone.soa.expire ?? 1_209_600),
    minimum: String(zone.soa.minimum ?? 300),
    ttl: String(zone.soa.ttl ?? 3600),
  });
  const [policy, setPolicy] = createSignal<SerialPolicy>(serialPolicy(zone));
  const [description, setDescription] = createSignal(zone.description ?? "");
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);

  // The NS RRset of the apex, edited as a list of host names.
  const [apexNs] = createResource(() => listRecords(zone.id, { name: zone.name, type: "NS" }).then((sets) => sets.find((s) => s.name === zone.name && s.type === "NS")));
  const [servers, setServers] = createSignal<string | null>(null);
  const serverText = createMemo(() => servers() ?? (apexNs.latest?.records ?? []).map((r) => (r.type === "NS" ? r.host : "")).join(", "));

  const save = async (event: Event) => {
    event.preventDefault();
    if (busy() || readOnly()) return;
    const e: Record<string, string> = {};
    if (!validName(canonical(mname()))) e["soa.mname"] = t("dns.check.name");
    if (!validName(canonical(rname()))) e["soa.rname"] = t("dns.check.name");
    for (const key of SOA_NUMBERS) if (parseTtl(numbers()[key]) === null) e[`soa.${key}`] = t("dns.check.number");
    const hosts = splitList(serverText()).map((h) => targetName(h, zone.name));
    if (hosts.length === 0 || hosts.some((h) => !validName(h))) e.name_servers = t("dns.settings.ns_required");
    setErrors(e);
    if (Object.keys(e).length > 0) return;
    setBusy(true);
    setError(undefined);
    try {
      const n = (k: SoaNumber) => parseTtl(numbers()[k]) ?? 0;
      const soa: SoaDefaults = {
        mname: canonical(mname()),
        rname: canonical(rname()),
        refresh: n("refresh"),
        retry: n("retry"),
        expire: n("expire"),
        minimum: n("minimum"),
        ttl: n("ttl"),
      };
      const patch: ZonePatch = { soa, serial: policy(), description: description().trim() || null };
      let saved = await updateZone(props.zone, patch);
      const before = (apexNs.latest?.records ?? []).map((r) => (r.type === "NS" ? r.host : "")).sort().join(",");
      if ([...hosts].sort().join(",") !== before) {
        const result = await changeRecords(
          zone.id,
          [{ op: "set", name: zone.name, type: "NS", ttl: apexNs.latest?.ttl ?? soa.ttl ?? null, records: hosts.map((host) => ({ type: "NS", host })) }],
          false,
        );
        if (typeof result.serial === "number") saved = { ...saved, soa_serial: result.serial };
        setServers(null);
      }
      toast({ kind: "ok", title: t("dns.settings.saved", { name: zone.name }) });
      props.onSaved(saved);
    } catch (err) {
      const fields = fieldErrors(err);
      if (Object.keys(fields).length > 0) setErrors(fields);
      else setError(err);
    } finally {
      setBusy(false);
    }
  };

  const input = (id: string, label: string, value: () => string, set: (v: string) => void, help?: string) => (
    <Field id={id} label={label} error={errors()[id]} help={help}>
      <input
        id={`dns-f-${id}`}
        class="input mono"
        value={value()}
        disabled={readOnly()}
        spellcheck={false}
        aria-invalid={errors()[id] ? "true" : undefined}
        aria-describedby={describedBy(id, errors()[id], help)}
        data-testid={`field-${id}`}
        onInput={(e) => set(e.currentTarget.value)}
      />
    </Field>
  );

  return (
    <form class="page-body dns-form" data-testid="zone-settings" onSubmit={(e) => void save(e)} novalidate>
      <section class="page-section" aria-labelledby="dns-soa-title">
        <h2 id="dns-soa-title">{t("dns.settings.soa")}</h2>
        <p>{t("dns.settings.soa_body")}</p>
        <div class="field-row">
          {input("soa.mname", t("dns.zone.field.mname"), mname, setMname)}
          {input("soa.rname", t("dns.zone.field.rname"), rname, setRname, t("dns.settings.rname_help"))}
        </div>
        <div class="field-row">
          <For each={SOA_NUMBERS}>
            {(key) =>
              input(
                `soa.${key}`,
                t(`dns.settings.${key}`),
                () => numbers()[key],
                (v) => setNumbers({ ...numbers(), [key]: v }),
              )
            }
          </For>
        </div>
      </section>
      <section class="page-section" aria-labelledby="dns-ns-title">
        <h2 id="dns-ns-title">{t("dns.settings.ns")}</h2>
        {input("name_servers", t("dns.zone.field.name_servers"), serverText, setServers, t("dns.zone.field.name_servers_help"))}
      </section>
      <section class="page-section" aria-labelledby="dns-serial-title">
        <h2 id="dns-serial-title">{t("dns.settings.serial")}</h2>
        <Field id="serial" label={t("dns.zone.field.serial")} help={t(`dns.serial.${policy()}_help`)}>
          <select
            id="dns-f-serial"
            class="select"
            value={policy()}
            disabled={readOnly()}
            data-testid="field-serial"
            aria-describedby="dns-f-serial-help"
            onChange={(e) => setPolicy(e.currentTarget.value as SerialPolicy)}
          >
            <For each={SERIAL_POLICIES}>{(p) => <option value={p}>{t(`dns.serial.${p}`)}</option>}</For>
          </select>
        </Field>
        {input("description", t("dns.zone.field.description"), description, setDescription)}
      </section>
      <ErrorNotice error={error()} />
      <Show when={!readOnly()}>
        <div class="form-row">
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {t("dns.settings.save")}
          </button>
        </div>
      </Show>
    </form>
  );
}

export function HistoryTab(props: { zone: Zone }) {
  const [records] = createResource(
    () => `${props.zone.id}:${props.zone.revision}`,
    () => zoneAudit(props.zone.id),
  );
  const refused = () => records.error instanceof ApiError && records.error.status === 403;
  return (
    <div class="page-body" data-testid="zone-history">
      <section class="page-section" aria-labelledby="dns-hist-serial">
        <h2 id="dns-hist-serial">{t("dns.history.serial_title")}</h2>
        <dl class="kv">
          <dt>{t("dns.history.serial")}</dt>
          <dd class="mono" data-testid="zone-serial">
            {servedSerial(props.zone) ?? "–"}
          </dd>
          <dt>{t("dns.zone.field.serial")}</dt>
          <dd>{t(`dns.serial.${serialPolicy(props.zone)}`)}</dd>
          <dt>{t("dns.history.updated")}</dt>
          <dd>
            <TimeAgo at={props.zone.updated.at} />
          </dd>
          <dt>{t("dns.history.revision")}</dt>
          <dd class="mono">{props.zone.revision}</dd>
        </dl>
      </section>
      <section class="page-section" aria-labelledby="dns-hist-changes">
        <h2 id="dns-hist-changes">{t("dns.history.changes")}</h2>
        <Show when={!refused()} fallback={<Notice kind="info" testid="zone-history-refused">{t("dns.history.no_audit")}</Notice>}>
          <Show when={!records.error} fallback={<ErrorNotice error={records.error} />}>
            <Show when={(records.latest ?? []).length > 0} fallback={<p class="muted">{records.loading ? t("common.loading") : t("dns.history.empty")}</p>}>
              <div class="table-wrap">
                <table class="plain">
                  <thead>
                    <tr>
                      <th>{t("dns.history.when")}</th>
                      <th>{t("dns.history.action")}</th>
                      <th>{t("dns.history.result")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={records.latest}>
                      {(r) => (
                        <tr data-testid="history-entry" data-kind={r.draft.action} data-key={String(r.seq)}>
                          <td title={formatDateTime(r.at)}>
                            <A href={paths.auditRecord(r.seq)}>
                              <TimeAgo at={r.at} />
                            </A>
                          </td>
                          <td>
                            <code>{r.draft.action}</code>
                          </td>
                          <td>{t(`dns.history.outcome.${r.draft.outcome.kind}`)}</td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
              </div>
            </Show>
          </Show>
        </Show>
      </section>
    </div>
  );
}
