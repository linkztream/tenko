// "What is this installation for?" (OPS-25): the product modules this installation runs. It
// sits in the roles step, below the roles; all four are selected until the operator clears
// one, and at least one stays selected. A module that has no code yet carries a note that it
// arrives in a later version. The choice is sent after setup, with the session it creates.
import { For } from "solid-js";
import { t } from "../../i18n";
import { MODULE_NAMES, type ModuleName } from "../../updates/modules";
import { MODULES_FOCUS } from "../../updates/wizardModules";
import { useWizard } from "../controller";

const NAME = {
  ipam: "setup.modules.ipam.name",
  dns: "setup.modules.dns.name",
  dhcp: "setup.modules.dhcp.name",
  discovery: "setup.modules.discovery.name",
} as const satisfies Record<ModuleName, string>;

const DESCRIPTION = {
  ipam: "setup.modules.ipam.description",
  dns: "setup.modules.dns.description",
  dhcp: "setup.modules.dhcp.description",
  discovery: "setup.modules.discovery.description",
} as const satisfies Record<ModuleName, string>;

/** The modules whose code arrives in a later version of the product. */
const LATER: Readonly<Record<ModuleName, boolean>> = { ipam: false, dns: true, dhcp: true, discovery: true };

export function Modules() {
  const w = useWizard();
  return (
    <div class="wz-blk">
      <h2>
        <span id="wz-modules-title">{t("setup.modules.title")}</span>
        <span class="aside">{t("setup.modules.aside")}</span>
      </h2>
      <div role="group" aria-labelledby="wz-modules-title">
        <For each={MODULE_NAMES}>
          {(module) => (
            <label class="wz-choice multi">
              <input
                id={module === "ipam" ? MODULES_FOCUS : undefined}
                data-testid="setup-module"
                data-key={module}
                class="cb"
                type="checkbox"
                checked={w.state.modules[module]}
                onChange={(e) => w.setModule(module, e.currentTarget.checked)}
              />
              <span>
                <span class="t">{t(NAME[module])}</span>
                <span class="d">{t(DESCRIPTION[module])}</span>
              </span>
              <span class="r">{LATER[module] ? t("setup.modules.later") : ""}</span>
            </label>
          )}
        </For>
      </div>
    </div>
  );
}
