import { For, Show } from "solid-js";
import { NODE_ROLES, type NodeRole, type Profile } from "../../api/types";
import { t } from "../../i18n";
import { formatMegabytes, formatMemory } from "../format";
import { FOCUS } from "../gates";
import { ProblemNotice } from "../parts";
import { useWizard } from "../controller";
import { Modules } from "./Modules";

/** What each role needs from the node, in megabytes (the mockup's estimates). */
const ROLE_MEMORY: Readonly<Record<NodeRole, number>> = { controller: 1100, dns: 250, dhcp: 100, probe: 150 };

const ROLE_NAME = {
  controller: "node.role.controller",
  dns: "node.role.dns",
  dhcp: "node.role.dhcp",
  probe: "node.role.probe",
} as const satisfies Record<NodeRole, string>;

const ROLE_DESCRIPTION = {
  controller: "setup.roles.controller.description",
  dns: "setup.roles.dns.description",
  dhcp: "setup.roles.dhcp.description",
  probe: "setup.roles.probe.description",
} as const satisfies Record<NodeRole, string>;

const ROLE_HINT = {
  home: "setup.roles.hint.home",
  standard: "setup.roles.hint.standard",
  hardened: "setup.roles.hint.hardened",
  lab: "setup.roles.hint.lab",
} as const satisfies Record<Profile, string>;

/** The networks with a VLAN color of their own in the design; the rest get the neutral swatch. */
const VLAN_CLASS = ["lan", "lab", "iot", "dmz"];

/** Step 6: roles, probe networks and the cluster. */
export function Roles() {
  const w = useWizard();
  const selectedMb = () => NODE_ROLES.filter((r) => w.state.roles[r]).reduce((sum, r) => sum + ROLE_MEMORY[r], 0);
  const totalMb = () => ((w.node()?.memory_bytes ?? 0) > 0 ? (w.node()?.memory_bytes ?? 0) / 1024 ** 2 : null);
  const percent = () => {
    const total = totalMb();
    return total === null ? 0 : Math.min(100, Math.round((selectedMb() / total) * 100));
  };
  const dmzTicked = () => w.networks().some((n) => n.id === "dmz" && w.state.networks[n.id]);

  return (
    <div>
      <p class="wz-lede">
        {t("setup.roles.lede")} {t(ROLE_HINT[w.state.profile])}
      </p>
      <ProblemNotice step={5} />

      <div class="wz-blk tight">
        <div role="group" aria-label={t("setup.roles.group")}>
          <For each={NODE_ROLES}>
            {(role) => (
              <label class="wz-choice multi">
                <input
                  id={role === "controller" ? FOCUS.roleController : role === "probe" ? FOCUS.roleProbe : undefined}
                  data-testid="setup-role"
                  data-key={role}
                  class="cb"
                  type="checkbox"
                  checked={w.state.roles[role]}
                  onChange={(e) => w.setRole(role, e.currentTarget.checked)}
                />
                <span>
                  <span class="t">{t(ROLE_NAME[role])}</span>
                  <span class="d">{t(ROLE_DESCRIPTION[role])}</span>
                </span>
                <span class="r">
                  {role === "probe"
                    ? t("setup.roles.hint_probe", { amount: formatMegabytes(ROLE_MEMORY[role]) })
                    : t("setup.roles.hint", { amount: formatMegabytes(ROLE_MEMORY[role]) })}
                </span>
              </label>
            )}
          </For>
        </div>
        <div class="wz-mem">
          <Show when={selectedMb() > 0} fallback={<span>{t("setup.roles.memory_none")}</span>}>
            <Show when={totalMb() !== null}>
              <span
                class="meter"
                classList={{ warn: percent() > 70 && percent() <= 90, crit: percent() > 90 }}
                style={{ "--v": `${percent()}%` }}
                aria-hidden="true"
              >
                <span class="bar">
                  <i />
                </span>
              </span>
            </Show>
            <span>
              {totalMb() === null
                ? t("setup.roles.memory_unknown_total", { amount: formatMegabytes(selectedMb()) })
                : t("setup.roles.memory", {
                    amount: formatMegabytes(selectedMb()),
                    total: formatMemory(w.node()?.memory_bytes ?? 0),
                  })}
            </span>
          </Show>
        </div>
      </div>

      <Modules />

      <div class="wz-blk">
        <h2 id="wz-probe-title">
          {t("setup.roles.probe.title")}
          <span class="aside">{t("setup.roles.probe.aside")}</span>
        </h2>
        <fieldset class="wz-segs" disabled={!w.state.roles.probe} aria-labelledby="wz-probe-title">
          <Show when={w.networks().length > 0} fallback={<p class="wz-help wz-segs-empty">{t("setup.roles.probe.none")}</p>}>
            <For each={w.networks()}>
              {(n, i) => (
                <>
                  <label class="wz-segrow">
                    <input
                      id={i() === 0 ? FOCUS.firstNetwork : undefined}
                      class="cb"
                      type="checkbox"
                      checked={w.state.networks[n.id] === true}
                      onChange={(e) => w.setState("networks", n.id, e.currentTarget.checked)}
                    />
                    <span class="vlan" classList={{ [n.id]: VLAN_CLASS.includes(n.id) }}>
                      <Show when={n.vlan != null}>
                        <span class="id">{n.vlan}</span>
                      </Show>
                      {n.name}
                    </span>
                    <span class="mono">{n.prefix}</span>
                    <span class="wz-help">
                      {n.interface}, {n.address}
                    </span>
                  </label>
                  <Show when={n.id === "dmz"}>
                    <div class="wz-segnote" classList={{ warn: dmzTicked() }}>
                      {t("setup.roles.dmz.note")}
                      <Show when={dmzTicked()}>{` ${t("setup.roles.dmz.ticked")}`}</Show>
                    </div>
                  </Show>
                </>
              )}
            </For>
          </Show>
        </fieldset>
      </div>

      <div class="wz-blk">
        <h2 id="wz-cluster-title">{t("setup.cluster.title")}</h2>
        <div role="radiogroup" aria-labelledby="wz-cluster-title">
          <label class="wz-choice">
            <input class="wz-rd" type="radio" name="wz-cluster" value="new" checked />
            <span>
              <span class="t">{t("setup.cluster.new")}</span>
              <span class="d">{t("setup.cluster.new_description")}</span>
            </span>
            <span />
          </label>
          <label class="wz-choice">
            <input class="wz-rd" type="radio" name="wz-cluster" value="join" disabled />
            <span>
              <span class="t">
                {t("setup.cluster.join")}
                <span class="tag">{t("setup.cluster.later")}</span>
              </span>
              <span class="d">{t("setup.cluster.join_description")}</span>
            </span>
            <span />
          </label>
        </div>
      </div>
    </div>
  );
}
