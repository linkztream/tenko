// The options tab of a scope: the scope's own option set, and "why did this client get this
// value": the options a client gets in the scope, the classes it is in and the policies that
// match it (EffectiveOptions.tsx), and the reservation the client has, if any. A DHCPv6 scope
// (WP9.4) edits its `dhcp6` options with the DHCPv6 catalog; the effective view asks for DHCPv4
// facts (client identifier, option 60, option 93) and is left out for it, with a line.
import { createSignal, Show } from "solid-js";
import { t } from "../i18n";
import { mayWriteDhcp } from "./access";
import type { Scope } from "./api";
import { EffectiveView } from "./EffectiveOptions";
import { isV6 } from "./model";
import { OptionSetEditor } from "./options/OptionSetEditor";
import { V4Only } from "./v6/V4Only";

export function OptionsTab(props: { scope: Scope }) {
  /** Bumped by a save of the set, so the effective options read again. */
  const [version, setVersion] = createSignal(0);

  return (
    <div class="page-body dhcp-tab" data-testid="scope-options" data-version={version()}>
      <section class="page-section" aria-labelledby="dhcp-scope-options-title">
        <h2 id="dhcp-scope-options-title">{t("dhcp.scope.options_title", { network: props.scope.cidr })}</h2>
        <p class="muted">{isV6(props.scope) ? t("dhcp.v6.options_help") : t("dhcp.scope.options_help")}</p>
        <OptionSetEditor
          owner={`scope:${props.scope.prefix}`}
          label={t("dhcp.scope.options_title", { network: props.scope.cidr })}
          space={isV6(props.scope) ? "dhcp6" : "dhcp4"}
          canWrite={mayWriteDhcp()}
          testid="scope-optset"
          onSaved={() => setVersion((n) => n + 1)}
        />
      </section>
      <Show when={!isV6(props.scope)} fallback={<V4Only part="effective" text={t("dhcp.v6.no_effective")} />}>
        <EffectiveView scope={props.scope} version={version()} />
      </Show>
    </div>
  );
}
