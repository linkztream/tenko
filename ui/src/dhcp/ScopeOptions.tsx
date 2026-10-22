// The options tab of a scope: the scope's own option set, and the options a client gets in the
// scope: a MAC address (and optionally a client identifier in hexadecimal), then each option with
// its name, its value and the level it came from (server, shared network, scope, policy, host),
// and the reservation the client has, if any.
import { createSignal, For, Show } from "solid-js";
import { ErrorNotice } from "../components/Notice";
import { t } from "../i18n";
import { mayWriteDhcp } from "./access";
import { getEffectiveOptions, type EffectiveOptions, type Scope } from "./api";
import { checkMac, dataText, parseHex } from "./model";
import { describedBy, Field } from "./Parts";
import { OptionSetEditor } from "./options/OptionSetEditor";

export function OptionsTab(props: { scope: Scope }) {
  const [mac, setMac] = createSignal("");
  const [clientId, setClientId] = createSignal("");
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [result, setResult] = createSignal<EffectiveOptions>();
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);
  /** Bumped by a save of the set, so the effective options read again. */
  const [version, setVersion] = createSignal(0);

  const show = async (event?: Event) => {
    event?.preventDefault();
    if (busy()) return;
    const e: Record<string, string> = {};
    const address = checkMac(mac());
    if (address === null) e.mac = t("dhcp.check.mac");
    const id = clientId().trim() === "" ? undefined : parseHex(clientId());
    if (id === null) e.client_id = t("dhcp.check.hex");
    setErrors(e);
    if (Object.keys(e).length > 0 || address === null) return;
    setBusy(true);
    setError(undefined);
    try {
      setResult(await getEffectiveOptions(props.scope.prefix, { mac: address, clientId: id ?? undefined }));
    } catch (err) {
      setResult(undefined);
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div class="page-body dhcp-tab" data-testid="scope-options" data-version={version()}>
      <section class="page-section" aria-labelledby="dhcp-scope-options-title">
        <h2 id="dhcp-scope-options-title">{t("dhcp.scope.options_title", { network: props.scope.cidr })}</h2>
        <p class="muted">{t("dhcp.scope.options_help")}</p>
        <OptionSetEditor
          owner={`scope:${props.scope.prefix}`}
          label={t("dhcp.scope.options_title", { network: props.scope.cidr })}
          canWrite={mayWriteDhcp()}
          testid="scope-optset"
          onSaved={() => {
            setVersion((n) => n + 1);
            if (result()) void show();
          }}
        />
      </section>
      <section class="page-section" aria-labelledby="dhcp-effective-title">
        <h2 id="dhcp-effective-title">{t("dhcp.effective.title")}</h2>
        <p class="muted">{t("dhcp.effective.help")}</p>
        <form class="dhcp-form dhcp-effective-form" onSubmit={(e) => void show(e)} novalidate>
          <div class="field-row">
            <Field id="mac" label={t("dhcp.effective.mac")} error={errors().mac}>
              <input
                id="dhcp-f-mac"
                class="input mono"
                value={mac()}
                placeholder={t("dhcp.example.mac")}
                spellcheck={false}
                aria-invalid={errors().mac ? "true" : undefined}
                aria-describedby={describedBy("mac", errors().mac)}
                data-testid="field-mac"
                onInput={(e) => setMac(e.currentTarget.value)}
              />
            </Field>
            <Field id="client_id" label={t("dhcp.effective.client_id")} error={errors().client_id}>
              <input
                id="dhcp-f-client_id"
                class="input mono"
                value={clientId()}
                spellcheck={false}
                aria-invalid={errors().client_id ? "true" : undefined}
                aria-describedby={describedBy("client_id", errors().client_id)}
                data-testid="field-client_id"
                onInput={(e) => setClientId(e.currentTarget.value)}
              />
            </Field>
          </div>
          <div class="dhcp-actions">
            <button type="submit" class="btn" disabled={busy()} data-testid="effective-show">
              {t("dhcp.effective.show")}
            </button>
          </div>
        </form>
        <ErrorNotice error={error()} />
        <Show when={result()}>
          {(r) => (
            <div data-testid="effective-options">
              <Show when={r().reservation}>
                <p data-testid="effective-reservation" data-key={r().reservation}>
                  {t("dhcp.effective.reservation")}
                </p>
              </Show>
              <p class="muted">{t("dhcp.effective.note")}</p>
              <Show when={r().options.length > 0} fallback={<p class="muted" data-testid="effective-empty">{t("dhcp.effective.empty")}</p>}>
                <div class="table-wrap">
                  <table class="plain">
                    <caption class="sr-only">{t("dhcp.effective.title")}</caption>
                    <thead>
                      <tr>
                        <th scope="col">{t("dhcp.optset.col.code")}</th>
                        <th scope="col">{t("dhcp.optset.col.name")}</th>
                        <th scope="col">{t("dhcp.optset.col.value")}</th>
                        <th scope="col">{t("dhcp.effective.col.level")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      <For each={r().options}>
                        {(o) => (
                          <tr data-testid="effective-option" data-key={`${o.value.space}:${o.value.code}`} data-code={o.value.code} data-level={o.level}>
                            <td class="mono">{o.value.code}</td>
                            <td class="mono">{o.name ?? ""}</td>
                            <td class="mono dhcp-value">{o.typed !== undefined && o.typed !== null ? dataText(o.typed) : o.value.data}</td>
                            <td>
                              <span class="tag" data-testid="effective-level" data-key={o.level}>
                                {t(`dhcp.level.${o.level}`)}
                              </span>
                            </td>
                          </tr>
                        )}
                      </For>
                    </tbody>
                  </table>
                </div>
              </Show>
            </div>
          )}
        </Show>
      </section>
    </div>
  );
}
