// The tenant and VRF switcher: a native select with one group per tenant, so it works with
// the keyboard and screen readers without anything custom.
import { For, Show } from "solid-js";
import { t } from "../i18n";
import type { Scope } from "./scope";

export function ScopeSwitcher(props: { scope: Scope; onChange?: (vrfId: string) => void }) {
  return (
    <Show when={props.scope.data()}>
      {(data) => (
        <select
          class="select scope-switch"
          aria-label={t("ipam.scope.label")}
          title={t("ipam.scope.label")}
          data-testid="ipam-scope"
          value={props.scope.vrf()?.id ?? ""}
          onChange={(e) => {
            props.scope.choose(e.currentTarget.value);
            props.onChange?.(e.currentTarget.value);
          }}
        >
          <For each={data().tenants}>
            {(tenant) => (
              <optgroup label={tenant.name}>
                <For each={data().vrfs.filter((v) => v.tenant === tenant.id)}>
                  {(vrf) => (
                    <option value={vrf.id}>
                      {t("ipam.scope.option", { tenant: tenant.name, vrf: vrf.name })}
                    </option>
                  )}
                </For>
              </optgroup>
            )}
          </For>
        </select>
      )}
    </Show>
  );
}
