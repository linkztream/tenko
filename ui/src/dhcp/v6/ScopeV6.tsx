// The DHCPv6 tab of a scope on an IPv6 prefix (WP9.4, docs/dhcp.md 19.2): the preferred lifetime,
// Rapid Commit and the relay Interface-Id. A save sends the whole `v6` object (the server replaces
// it whole), "Use the defaults" sends `clear_v6`. The valid lifetime is the scope's default lease
// time, else the server's; the preferred lifetime may not be above it.
import { createResource, createSignal, Show, untrack } from "solid-js";
import { ErrorNotice } from "../../components/Notice";
import { toast } from "../../components/toast";
import { formatDuration, formatNumber, t } from "../../i18n";
import { mayWriteDhcp } from "../access";
import { getSettings, updateScope, type Scope, type Scope6Settings } from "../api";
import { defaultPreferred, MAX_INTERFACE_ID, preferredOfText } from "../model";
import { Check, describedBy, errorFor, Field, fieldErrors, hasField } from "../Parts";

const SERVER_VALID_SECS = 86_400;

/** The three settings as the form shows them. */
interface Draft {
  preferred: string;
  rapid: boolean;
  interfaceId: string;
}

function draftOf(v6: Scope6Settings | null | undefined): Draft {
  return { preferred: v6?.preferred_secs ? String(v6.preferred_secs) : "", rapid: v6?.rapid_commit ?? true, interfaceId: v6?.interface_id ?? "" };
}

export function ScopeV6Tab(props: { scope: Scope; onSaved: (scope: Scope) => void }) {
  const initial = draftOf(untrack(() => props.scope.v6));
  const writable = () => mayWriteDhcp();
  const [settings] = createResource(() => getSettings());
  // The valid lifetime of an address is the lease time of the scope (a pool or a range may set its own).
  const validSecs = () => props.scope.lease?.default_secs ?? (settings.error ? SERVER_VALID_SECS : (settings.latest?.lease?.default_secs ?? SERVER_VALID_SECS));

  const [preferred, setPreferred] = createSignal(initial.preferred);
  const [rapid, setRapid] = createSignal(initial.rapid);
  const [interfaceId, setInterfaceId] = createSignal(initial.interfaceId);
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);

  const show = (draft: Draft) => {
    setPreferred(draft.preferred);
    setRapid(draft.rapid);
    setInterfaceId(draft.interfaceId);
  };

  const save = async (event: Event) => {
    event.preventDefault();
    if (busy() || !writable()) return;
    const scope = props.scope;
    const e: Record<string, string> = {};
    const parsed = preferredOfText(preferred(), validSecs());
    if (!parsed.ok) e.preferred = t(`dhcp.v6.check.preferred_${parsed.problem}`, { valid: formatNumber(validSecs()) });
    const id = interfaceId().trim();
    if (id.length > MAX_INTERFACE_ID) e.interface_id = t("dhcp.v6.check.interface_id", { max: MAX_INTERFACE_ID });
    setErrors(e);
    setError(undefined);
    if (!parsed.ok || Object.keys(e).length > 0) return;
    const now = draftOf(scope.v6);
    if ((parsed.secs === null ? "" : String(parsed.secs)) === now.preferred && rapid() === now.rapid && id === now.interfaceId) {
      toast({ kind: "info", title: t("dhcp.scope.unchanged") });
      return;
    }
    // The server replaces the whole object: send every setting that is set.
    const v6: Scope6Settings = { rapid_commit: rapid() };
    if (parsed.secs !== null) v6.preferred_secs = parsed.secs;
    if (id !== "") v6.interface_id = id;
    await send({ v6 });
  };

  const send = async (patch: { v6: Scope6Settings } | { clear_v6: true }) => {
    setBusy(true);
    try {
      const next = await updateScope(props.scope, patch);
      toast({ kind: "ok", title: t("dhcp.v6.saved", { network: next.cidr }) });
      show(draftOf(next.v6));
      setErrors({});
      props.onSaved(next);
    } catch (err) {
      const fields = fieldErrors(err);
      if (hasField(fields, ["v6"])) {
        const map: Record<string, string> = {};
        if (errorFor(fields, "v6.preferred_secs")) map.preferred = errorFor(fields, "v6.preferred_secs") ?? "";
        if (errorFor(fields, "v6.interface_id")) map.interface_id = errorFor(fields, "v6.interface_id") ?? "";
        if (Object.keys(map).length > 0) setErrors(map);
        else setError(err);
      } else setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form class="page-body dhcp-form" data-testid="scope-v6" onSubmit={(ev) => void save(ev)} novalidate>
      <section class="page-section" aria-labelledby="dhcp-v6-title">
        <h2 id="dhcp-v6-title">{t("dhcp.v6.title", { network: props.scope.cidr })}</h2>
        <p class="muted">{t("dhcp.v6.help")}</p>
        <Field id="preferred" label={t("dhcp.v6.field.preferred")} error={errors().preferred} help={t("dhcp.v6.field.preferred_help")}>
          <input
            id="dhcp-f-preferred"
            class="input"
            inputmode="numeric"
            value={preferred()}
            disabled={!writable()}
            placeholder={String(defaultPreferred(validSecs()))}
            aria-invalid={errors().preferred ? "true" : undefined}
            aria-describedby={describedBy("preferred", errors().preferred, "help")}
            data-testid="field-preferred"
            onInput={(ev) => setPreferred(ev.currentTarget.value)}
          />
        </Field>
        <p class="muted" data-testid="v6-preferred-default" data-value={String(defaultPreferred(validSecs()))}>
          {t("dhcp.v6.preferred_default", { seconds: formatNumber(defaultPreferred(validSecs())), valid: formatDuration(validSecs()) })}
        </p>
        <Check id="rapid_commit" label={t("dhcp.v6.field.rapid_commit")} checked={rapid()} onChange={setRapid} disabled={!writable()} help={t("dhcp.v6.field.rapid_commit_help")} />
        <Field id="interface_id" label={t("dhcp.v6.field.interface_id")} error={errors().interface_id} help={t("dhcp.v6.field.interface_id_help")}>
          <input
            id="dhcp-f-interface_id"
            class="input mono"
            value={interfaceId()}
            disabled={!writable()}
            spellcheck={false}
            autocomplete="off"
            aria-invalid={errors().interface_id ? "true" : undefined}
            aria-describedby={describedBy("interface_id", errors().interface_id, "help")}
            data-testid="field-interface_id"
            onInput={(ev) => setInterfaceId(ev.currentTarget.value)}
          />
        </Field>
        <ErrorNotice error={error()} />
        <Show when={writable()}>
          <div class="dhcp-actions">
            <button type="submit" class="btn primary" disabled={busy()} data-testid="v6-save">
              {t("dhcp.v6.save")}
            </button>
            <Show when={props.scope.v6}>
              <button type="button" class="btn ghost" disabled={busy()} data-testid="v6-defaults" onClick={() => void send({ clear_v6: true })}>
                {t("dhcp.v6.defaults")}
              </button>
            </Show>
          </div>
        </Show>
      </section>
    </form>
  );
}
