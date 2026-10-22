// The options tab of a scope: the scope's own option set, and "why did this client get this
// value": the options a client gets in the scope, the classes it is in and the policies that
// match it (EffectiveOptions.tsx), and the reservation the client has, if any.
import { createSignal } from "solid-js";
import { t } from "../i18n";
import { mayWriteDhcp } from "./access";
import type { Scope } from "./api";
import { EffectiveView } from "./EffectiveOptions";
import { OptionSetEditor } from "./options/OptionSetEditor";

export function OptionsTab(props: { scope: Scope }) {
  /** Bumped by a save of the set, so the effective options read again. */
  const [version, setVersion] = createSignal(0);

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
          onSaved={() => setVersion((n) => n + 1)}
        />
      </section>
      <EffectiveView scope={props.scope} version={version()} />
    </div>
  );
}
