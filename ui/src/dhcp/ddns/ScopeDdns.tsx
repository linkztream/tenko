// The DDNS tab of a scope (/dhcp/scopes/:prefix/ddns, docs/dhcp.md section 13.1): every field of
// the scope's DDNS settings, the settings of the server the scope starts from, and what the
// security profile does. The scope's settings are saved with its revision and only when something
// changed. The API cannot take a scope's own DDNS settings back (a patch without `ddns` keeps
// them, and a patch has no way to clear them), so "use the server's settings" is offered as a copy
// of the server's current settings into the form.
import { createEffect, createResource, createSignal, Show, untrack } from "solid-js";
import { ErrorNotice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { t } from "../../i18n";
import { mayWriteDhcp } from "../access";
import { getSettings, updateScope, type Scope } from "../api";
import { fieldErrors } from "../Parts";
import { ddnsWords } from "../words";
import { createZoneChoices, DdnsFields, zoneNameIn } from "./DdnsFields";
import { ddnsFieldErrors, ddnsOfDraft, draftOfDdns, sameDdns, type DdnsDraft, type DdnsField } from "./model";
import "./ddns.css";

export function DdnsTab(props: { scope: Scope; onSaved: (scope: Scope) => void }) {
  const initial = untrack(() => props.scope);
  const writable = () => mayWriteDhcp();
  const [settings] = createResource(() => getSettings());
  const zones = createZoneChoices();
  const server = () => (settings.error ? undefined : settings.latest?.ddns);

  const [draft, setDraftSignal] = createSignal<DdnsDraft>(draftOfDdns(initial.ddns));
  const [touched, setTouched] = createSignal(false);
  const [errors, setErrors] = createSignal<Partial<Record<DdnsField, string>>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);
  const edit = (next: DdnsDraft) => {
    setTouched(true);
    setDraftSignal(next);
  };

  // A scope without settings of its own follows the server: the form starts from the server's.
  createEffect(() => {
    const s = server();
    if (s && !initial.ddns && !touched()) setDraftSignal(draftOfDdns(s));
  });

  /** What the scope has now: its own settings, or the server's it follows. */
  const baseline = () => props.scope.ddns ?? server();

  const save = async (event: Event) => {
    event.preventDefault();
    if (busy() || !writable()) return;
    setError(undefined);
    const parsed = ddnsOfDraft(draft());
    if (!parsed.ok) {
      setErrors({ ttl: t("dhcp.ddns.check.ttl") });
      return;
    }
    setErrors({});
    if (sameDdns(parsed.ddns, baseline())) {
      toast({ kind: "info", title: t("dhcp.scope.unchanged") });
      return;
    }
    setBusy(true);
    try {
      const next = await updateScope(props.scope, { ddns: parsed.ddns });
      toast({ kind: "ok", title: t("dhcp.ddns.saved", { network: next.cidr }) });
      props.onSaved(next);
    } catch (err) {
      const named = ddnsFieldErrors(fieldErrors(err), "ddns");
      if (Object.keys(named).length > 0) setErrors(named);
      else setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div class="page-body dhcp-tab ddns-tab" data-testid="scope-ddns">
      <form class="dhcp-form" data-testid="ddns-form" onSubmit={(ev) => void save(ev)} novalidate>
        <section class="page-section" aria-labelledby="dhcp-ddns-title">
          <h2 id="dhcp-ddns-title">{t("dhcp.ddns.title", { network: props.scope.cidr })}</h2>
          <p class="muted">{t("dhcp.ddns.help")}</p>
          <p class="muted" data-testid="ddns-needs-dns">
            {t("dhcp.ddns.needs_dns")}
          </p>
          <Show when={server()}>
            {(s) => (
              <div class="ddns-server">
                <p data-testid="ddns-server">{t("dhcp.ddns.server_now", { words: ddnsWords(s(), zoneNameIn(zones())) })}</p>
                <Show when={!props.scope.ddns}>
                  <p class="muted" data-testid="ddns-follows">
                    {t("dhcp.ddns.follows")}
                  </p>
                </Show>
                <Show when={writable()}>
                  <div class="dhcp-actions">
                    <button type="button" class="btn" data-testid="ddns-inherit" onClick={() => edit(draftOfDdns(s()))}>
                      {t("dhcp.ddns.inherit")}
                    </button>
                    <Show when={props.scope.ddns}>
                      <span class="help">{t("dhcp.ddns.inherit_help")}</span>
                    </Show>
                  </div>
                </Show>
              </div>
            )}
          </Show>
          <DdnsFields value={draft()} onChange={edit} zones={zones} disabled={!writable()} errors={errors()} />
          <ErrorNotice error={error()} />
          <Show when={writable()}>
            <div class="dhcp-actions">
              <button type="submit" class="btn primary" disabled={busy()} data-testid="ddns-save">
                {t("dhcp.scope.save")}
              </button>
            </div>
          </Show>
        </section>
      </form>
    </div>
  );
}
