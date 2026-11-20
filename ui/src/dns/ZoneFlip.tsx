// The flip of a secondary zone to primary in place (the SOA names and the name servers it then
// has) and the release of the frozen names of a primary zone (listed by a dry run first, then
// kept as manual records or deleted). docs/dns.md sections 10.6 and 10.7.
import { createResource, createSignal, For, Show, untrack } from "solid-js";
import { api } from "../api/client";
import type { components } from "../api/generated/schema";
import { ConfirmDialog, Dialog } from "../components/Dialog";
import { ErrorNotice } from "../components/Notice";
import { toast } from "../components/toast";
import { formatNumber, t } from "../i18n";
import type { Zone } from "./api";
import { canonical, splitList, validName } from "./model";
import { describedBy, Field, fieldErrors } from "./Parts";

type S = components["schemas"];

/** Whether the zone page offers the flip: a secondary zone that is not a catalog zone. */
export function mayFlip(zone: Zone): boolean {
  return zone.kind === "secondary" && !zone.catalog;
}

/** Whether the zone page offers the release: a primary zone, not a catalog zone, with frozen RRsets. */
export function mayRelease(zone: Zone): boolean {
  return zone.kind === "primary" && !zone.catalog && (zone.origins ?? []).some((o) => o.origin === "transfer" && o.rrsets > 0);
}

function releaseZone(id: string, body: S["ZoneRelease"]): Promise<S["ZoneReleaseReport"]> {
  return api.post("/api/v1/dns/zones/{id}/release", { path: { id }, body });
}

export function FlipZoneDialog(props: { zone: Zone; onClose: () => void; onDone: () => void }) {
  const soa = untrack(() => props.zone.soa);
  const [mname, setMname] = createSignal(soa.mname);
  const [rname, setRname] = createSignal(soa.rname);
  const [servers, setServers] = createSignal("");
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);

  const validate = (): boolean => {
    const e: Record<string, string> = {};
    if (!validName(canonical(mname()))) e["soa.mname"] = t("dns.check.name");
    if (!validName(canonical(rname()))) e["soa.rname"] = t("dns.check.name");
    const ns = splitList(servers());
    if (ns.length === 0 || ns.some((s) => !validName(canonical(s)))) e.ns = t("dns.check.name");
    setErrors(e);
    return Object.keys(e).length === 0;
  };

  const submit = async (event: Event) => {
    event.preventDefault();
    if (busy() || !validate()) return;
    setBusy(true);
    setError(undefined);
    try {
      const report = await api.post("/api/v1/dns/zones/{id}/flip", {
        path: { id: props.zone.id },
        body: { to: "primary", soa: { ...soa, mname: canonical(mname()), rname: canonical(rname()) }, ns: splitList(servers()).map(canonical) },
      });
      toast({ kind: "ok", title: t("dns.zone.flip.done", { name: props.zone.name, serial: String(report.serial) }) });
      props.onDone();
    } catch (err) {
      const fields = fieldErrors(err);
      if (Object.keys(fields).length > 0) setErrors(fields);
      else setError(err);
    } finally {
      setBusy(false);
    }
  };

  const input = (id: string, value: () => string, set: (v: string) => void, help?: string) => (
    <input
      id={`dns-f-${id}`}
      class="input mono"
      value={value()}
      spellcheck={false}
      aria-invalid={errors()[id] ? "true" : undefined}
      aria-describedby={describedBy(id, errors()[id], help)}
      data-testid={`field-${id}`}
      onInput={(e) => set(e.currentTarget.value)}
    />
  );

  return (
    <Dialog label={t("dns.zone.flip.title", { name: props.zone.name })} onClose={props.onClose} class="dialog wide dns-dialog" testid="dialog-zone-flip">
      <h2 class="dialog-title">{t("dns.zone.flip.title", { name: props.zone.name })}</h2>
      <form class="dialog-body dns-form" onSubmit={(e) => void submit(e)} novalidate>
        <p>{t("dns.zone.flip.body")}</p>
        <div class="field-row">
          <Field id="soa.mname" label={t("dns.zone.field.mname")} error={errors()["soa.mname"]}>
            {input("soa.mname", mname, setMname)}
          </Field>
          <Field id="soa.rname" label={t("dns.zone.field.rname")} error={errors()["soa.rname"]}>
            {input("soa.rname", rname, setRname)}
          </Field>
        </div>
        <Field id="ns" label={t("dns.zone.field.name_servers")} error={errors().ns} help={t("dns.zone.field.name_servers_help")}>
          {input("ns", servers, setServers, t("dns.zone.field.name_servers_help"))}
        </Field>
        <ErrorNotice error={error()} />
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {t("dns.zone.flip.submit")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

export function ReleaseZoneDialog(props: { zone: Zone; onClose: () => void; onDone: () => void }) {
  const [listed] = createResource(() => releaseZone(props.zone.id, { dry_run: true }));
  const [remove, setRemove] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  const confirm = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await releaseZone(props.zone.id, { delete: remove() });
      toast({ kind: "ok", title: t("dns.zone.release.done", { name: props.zone.name }) });
      props.onDone();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <ConfirmDialog
      title={t("dns.zone.release.title", { name: props.zone.name })}
      testid="dialog-zone-release"
      danger={remove()}
      busy={busy() || !listed()}
      confirmLabel={t("dns.zone.release.confirm")}
      cancelLabel={t("common.action.cancel")}
      onConfirm={() => void confirm()}
      onClose={props.onClose}
      body={
        <>
          <Show when={listed()?.names} fallback={<ErrorNotice error={listed.error} />}>
            {(names) => (
              <>
                <p data-testid="release-count">{t("dns.zone.release.body", { count: names().length, names: formatNumber(names().length) })}</p>
                <ul class="mono" data-testid="release-names">
                  <For each={names()}>{(name) => <li>{name}</li>}</For>
                </ul>
              </>
            )}
          </Show>
          <label class="ackrow">
            <input type="checkbox" class="cb" checked={remove()} data-testid="release-delete" onChange={(e) => setRemove(e.currentTarget.checked)} />
            {t("dns.zone.release.delete")}
          </label>
          <ErrorNotice error={error()} />
        </>
      }
    />
  );
}
