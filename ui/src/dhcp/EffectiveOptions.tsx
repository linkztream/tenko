// "Why did this client get this value" (the options tab of a scope, docs/dhcp.md sections 4 and
// 16.1): a client described by its MAC address, client identifier, vendor class (option 60), user
// class (option 77), architecture (option 93) and host name (option 12). The answer is the
// matcher's, the one the engine uses: the reservation the client has, the classes it is in, the
// policies that match it in order, and each option with its value, the level it came from and a
// line saying why (for the policy level, which policy, the first matching one that sets it).
import { A } from "@solidjs/router";
import { createEffect, createResource, createSignal, For, on, Show } from "solid-js";
import { ErrorNotice } from "../components/Notice";
import { t } from "../i18n";
import { getEffectiveOptions, listClasses, listPolicies, type EffectiveOption, type EffectiveOptions, type Scope } from "./api";
import { ArchitecturePicker } from "./classes/MatchEditor";
import { architectureOfText, checkMac, dataText, parseHex } from "./model";
import { describedBy, Field } from "./Parts";
import { dhcpPaths } from "./paths";
import "./policies/policies.css";

/** The policy an option came from, if it came from one. */
function policyOf(option: EffectiveOption): string | undefined {
  const owner = option.owner;
  return typeof owner === "object" && "policy" in owner ? owner.policy : undefined;
}

export function EffectiveView(props: { scope: Scope; /** Changes when the options of the scope were saved: the answer is read again. */ version: number }) {
  const [mac, setMac] = createSignal("");
  const [clientId, setClientId] = createSignal("");
  const [vendorClass, setVendorClass] = createSignal("");
  const [userClass, setUserClass] = createSignal("");
  const [architecture, setArchitecture] = createSignal("");
  const [hostName, setHostName] = createSignal("");
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [result, setResult] = createSignal<EffectiveOptions>();
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);
  const [classes] = createResource(async () => (await listClasses()).items);
  const [policies] = createResource(async () => (await listPolicies()).items);
  const className = (id: string) => (classes.error ? undefined : classes.latest?.find((c) => c.id === id)?.name) ?? id;
  const policyName = (id: string) => (policies.error ? undefined : policies.latest?.find((p) => p.id === id)?.name) ?? id;

  const show = async (event?: Event) => {
    event?.preventDefault();
    if (busy()) return;
    const e: Record<string, string> = {};
    const address = checkMac(mac());
    if (address === null) e.mac = t("dhcp.check.mac");
    const id = clientId().trim() === "" ? undefined : parseHex(clientId());
    if (id === null) e.client_id = t("dhcp.check.hex");
    const code = architecture().trim() === "" ? undefined : architectureOfText(architecture());
    if (code === null) e.architecture = t("dhcp.check.match_number");
    setErrors(e);
    if (Object.keys(e).length > 0 || address === null) return;
    setBusy(true);
    setError(undefined);
    try {
      setResult(
        await getEffectiveOptions(props.scope.prefix, {
          mac: address,
          clientId: id ?? undefined,
          vendorClass: vendorClass().trim() || undefined,
          userClass: userClass().trim() || undefined,
          architecture: code ?? undefined,
          hostName: hostName().trim() || undefined,
        }),
      );
    } catch (err) {
      setResult(undefined);
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  // A save of the scope's options changes the answer: ask again for the client shown.
  createEffect(
    on(
      () => props.version,
      () => {
        if (result()) void show();
      },
      { defer: true },
    ),
  );

  const text = (id: string, label: string, get: () => string, set: (v: string) => void, placeholder?: string) => (
    <Field id={id} label={label} error={errors()[id]}>
      <input
        id={`dhcp-f-${id}`}
        class="input mono"
        value={get()}
        placeholder={placeholder}
        spellcheck={false}
        aria-invalid={errors()[id] ? "true" : undefined}
        aria-describedby={describedBy(id, errors()[id])}
        data-testid={`field-${id}`}
        onInput={(e) => set(e.currentTarget.value)}
      />
    </Field>
  );

  return (
    <section class="page-section" aria-labelledby="dhcp-effective-title">
      <h2 id="dhcp-effective-title">{t("dhcp.effective.title")}</h2>
      <p class="muted">{t("dhcp.effective.help_facts")}</p>
      <form class="dhcp-form dhcp-effective-form" onSubmit={(e) => void show(e)} novalidate>
        <div class="field-row">
          {text("mac", t("dhcp.effective.mac"), mac, setMac, t("dhcp.example.mac"))}
          {text("client_id", t("dhcp.effective.client_id"), clientId, setClientId)}
        </div>
        <div class="field-row">
          {text("vendor_class", t("dhcp.effective.vendor_class"), vendorClass, setVendorClass, "PXEClient:Arch:00007")}
          {text("user_class", t("dhcp.effective.user_class"), userClass, setUserClass)}
        </div>
        <div class="field-row">
          <Field id="architecture-menu" label={t("dhcp.effective.architecture")} error={errors().architecture}>
            <ArchitecturePicker
              id="architecture"
              value={architecture()}
              onChange={setArchitecture}
              testid="field-architecture"
              valueTestid="field-architecture-value"
              emptyLabel={t("dhcp.arch.none")}
              label={t("dhcp.effective.architecture")}
              invalid={errors().architecture !== undefined}
              describedby={errors().architecture ? "dhcp-f-architecture-menu-error" : undefined}
            />
          </Field>
          {text("host_name", t("dhcp.effective.host_name"), hostName, setHostName)}
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
            <div class="dhcp-effective-lists">
              <div>
                <h3 id="dhcp-effective-classes-title">{t("dhcp.effective.classes")}</h3>
                <Show when={(r().classes ?? []).length > 0} fallback={<p class="muted" data-testid="effective-classes-none">{t("dhcp.effective.no_classes")}</p>}>
                  <ul data-testid="effective-classes" aria-labelledby="dhcp-effective-classes-title">
                    <For each={r().classes ?? []}>
                      {(id) => (
                        <li data-testid="effective-class" data-key={className(id)}>
                          <span class="tag mono">{className(id)}</span>
                        </li>
                      )}
                    </For>
                  </ul>
                </Show>
              </div>
              <div>
                <h3 id="dhcp-effective-policies-title">{t("dhcp.effective.policies")}</h3>
                <Show when={(r().policies ?? []).length > 0} fallback={<p class="muted" data-testid="effective-policies-none">{t("dhcp.effective.no_policies")}</p>}>
                  <ul data-testid="effective-policies" aria-labelledby="dhcp-effective-policies-title">
                    <For each={r().policies ?? []}>
                      {(id) => (
                        <li data-testid="effective-policy" data-key={policyName(id)}>
                          <A class="tag accent mono" href={dhcpPaths.policies()}>
                            {policyName(id)}
                          </A>
                        </li>
                      )}
                    </For>
                  </ul>
                </Show>
              </div>
            </div>
            <p class="muted">{t("dhcp.effective.note_live")}</p>
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
                      <th scope="col">{t("dhcp.effective.col.why")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={r().options}>
                      {(o) => {
                        const policy = () => policyOf(o);
                        /** The policy's name for a policy, else the level. */
                        const owner = () => {
                          const id = policy();
                          return id !== undefined ? policyName(id) : o.level;
                        };
                        return (
                          <tr
                            data-testid="effective-option"
                            data-key={`${o.value.space}:${o.value.code}`}
                            data-code={o.value.code}
                            data-level={o.level}
                            data-owner={owner()}
                          >
                            <td class="mono">{o.value.code}</td>
                            <td class="mono">{o.name ?? ""}</td>
                            <td class="mono dhcp-value">{o.typed !== undefined && o.typed !== null ? dataText(o.typed) : o.value.data}</td>
                            <td>
                              <span class="tag" data-testid="effective-level" data-key={o.level}>
                                {t(`dhcp.level.${o.level}`)}
                              </span>
                            </td>
                            <td data-testid="effective-why">
                              <Show when={policy()} fallback={t(`dhcp.effective.why.${o.level}`)}>
                                {(id) => <>{t("dhcp.effective.why.policy", { name: policyName(id()) })}</>}
                              </Show>
                            </td>
                          </tr>
                        );
                      }}
                    </For>
                  </tbody>
                </table>
              </div>
            </Show>
          </div>
        )}
      </Show>
    </section>
  );
}
