import { For, Show } from "solid-js";
import { PROFILES, type Profile } from "../../api/types";
import { Icon } from "../../components/Icon";
import { t } from "../../i18n";
import { formatToggle, settingValue, TOGGLE_TOTAL, TOGGLES, weakerThan } from "../../settings/toggles";
import { FOCUS } from "../gates";
import { ProblemNotice } from "../parts";
import { useWizard } from "../controller";

const HINT = {
  home: "setup.profile.hint.home",
  standard: "setup.profile.hint.standard",
  hardened: "setup.profile.hint.hardened",
  lab: "setup.profile.hint.lab",
} as const satisfies Record<Profile, string>;

const LAB_RELAXES = [
  "setup.lab.relax.http",
  "setup.lab.relax.lockout",
  "setup.lab.relax.recursion",
  "setup.lab.relax.ddns",
  "setup.lab.relax.tokens",
  "setup.lab.relax.breach",
  "setup.lab.relax.scan",
] as const;

const LAB_ENFORCED = ["setup.lab.enforced.secrets", "setup.lab.enforced.audit", "setup.lab.enforced.attribution"] as const;

/** Step 2: the security profile, the Lab warning and the key settings of the chosen profile. */
export function ProfileStep() {
  const w = useWizard();
  const settings = () => w.info(w.state.profile)?.settings;
  const home = () => w.info("home")?.settings;

  return (
    <div>
      <p class="wz-lede">{t("setup.profile.lede", { total: TOGGLE_TOTAL })}</p>
      <ProblemNotice step={1} />

      <div class="wz-blk tight">
        <div role="radiogroup" aria-label={t("setup.profile.group")}>
          <For each={PROFILES}>
            {(p) => (
              <label class="wz-choice" data-p={p}>
                <input
                  class="wz-rd"
                  type="radio"
                  name="wz-profile"
                  value={p}
                  checked={w.state.profile === p}
                  onChange={() => w.setProfile(p)}
                />
                <span>
                  <span class="t">{t(`profile.${p}.name`)}</span>
                  <span class="d">{t(`profile.${p}.description`)}</span>
                </span>
                <span class="r">{t(HINT[p])}</span>
              </label>
            )}
          </For>
        </div>

        <Show when={w.state.profile === "lab"}>
          <div class="wz-labwarn" role="group" aria-labelledby="wz-lab-title">
            <h2 id="wz-lab-title">
              <Icon name="alert" />
              {t("setup.lab.title")}
            </h2>
            <div class="cols">
              <div>
                <h3>{t("setup.lab.relaxes")}</h3>
                <ul>
                  <For each={LAB_RELAXES}>{(key) => <li>{t(key)}</li>}</For>
                </ul>
              </div>
              <div>
                <h3>{t("setup.lab.enforced")}</h3>
                <ul>
                  <For each={LAB_ENFORCED}>{(key) => <li>{t(key)}</li>}</For>
                </ul>
              </div>
            </div>
            <p class="never">
              <strong>{t("setup.lab.never_title")}</strong> {t("setup.lab.never_body")}
            </p>
            <label class="ack">
              <input
                id={FOCUS.labAck}
                class="cb"
                type="checkbox"
                checked={w.state.labAck}
                onChange={(e) => w.setState("labAck", e.currentTarget.checked)}
              />
              {t("setup.lab.ack")}
            </label>
          </div>
        </Show>
      </div>

      <div class="wz-blk">
        <h2>
          {t("setup.profile.table.title", { profile: t(`profile.${w.state.profile}.name`) })}
          <span class="aside">{t("setup.profile.table.aside", { shown: TOGGLES.length, total: TOGGLE_TOTAL })}</span>
        </h2>
        <Show when={settings()}>
          {(s) => (
            <table class="wz-tg" aria-label={t("setup.profile.table.label")}>
              <thead>
                <tr>
                  <th scope="col">{t("setup.profile.table.setting")}</th>
                  <th scope="col">{t("setup.profile.table.id")}</th>
                  <th scope="col">{t("setup.profile.table.value")}</th>
                </tr>
              </thead>
              <tbody>
                <For each={TOGGLES}>
                  {(def) => {
                    const value = () => settingValue(s(), def.setting);
                    const weak = () => {
                      const base = home();
                      return !!base && weakerThan(def.setting, value(), settingValue(base, def.setting));
                    };
                    return (
                      <tr>
                        <td class="k">{t(def.name)}</td>
                        <td class="id mono">{def.id}</td>
                        <td class="v" classList={{ weak: weak() }}>
                          {formatToggle(def.setting, value())}
                          <Show when={weak()}>
                            <span class="tag conflict">
                              <Icon name="alert" size="xs" />
                              {t("setup.profile.weaker")}
                            </span>
                          </Show>
                        </td>
                      </tr>
                    );
                  }}
                </For>
              </tbody>
            </table>
          )}
        </Show>
        <p class="wz-help gap">{t("setup.profile.table.note")}</p>
      </div>
    </div>
  );
}
