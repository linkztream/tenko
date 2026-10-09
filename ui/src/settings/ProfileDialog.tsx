// Changing the security profile: choose, read what changes, acknowledge Lab, confirm.
// A profile switch resets every toggle to the profile's values, so the dialog lists the
// toggles whose value will change before anything is sent.
import { createMemo, createSignal, For, Show, untrack } from "solid-js";
import type { PasswordPolicy, Profile, SecuritySettingsView, SettingsPatch } from "../api/types";
import { PROFILES } from "../api/types";
import { Icon } from "../components/Icon";
import { Dialog } from "../components/Dialog";
import { ErrorNotice, Notice } from "../components/Notice";
import { toast } from "../components/toast";
import { formatList, t } from "../i18n";
import { ReloadedNote } from "./fields";
import { pinBlocked, planProfileChange, PROFILE_DEFAULTS, weakerSettings } from "./profileMatrix";
import { formatToggle } from "./toggles";

export function ProfileDialog(props: {
  view: SecuritySettingsView;
  save: (patch: SettingsPatch) => Promise<SecuritySettingsView>;
  onClose: () => void;
}) {
  const current = () => props.view.settings.profile;
  const [target, setTarget] = createSignal<Profile>(untrack(() => props.view.settings.profile));
  const [acknowledged, setAcknowledged] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);

  const same = () => target() === current();
  const changes = createMemo(() => planProfileChange(props.view, target()));
  const weakNames = () => weakerSettings(target()).map((d) => t(d.name));
  const lab = () => target() === "lab";
  const needsAck = () => lab() && !same();
  const pinRefused = () => pinBlocked(props.view, PROFILE_DEFAULTS[target()].password_policy as PasswordPolicy);
  const nothing = () => same() && changes().length === 0;
  const name = () => t(`profile.${target()}.name`);

  const confirmLabel = () =>
    same() ? t("settings.security.profile.reset_to", { profile: name() }) : t("settings.security.profile.switch_to", { profile: name() });

  const select = (p: Profile) => {
    setTarget(p);
    setAcknowledged(false);
    setError(null);
  };

  const submit = async (e: Event) => {
    e.preventDefault();
    if (busy() || nothing() || pinRefused() || (needsAck() && !acknowledged())) return;
    setBusy(true);
    setError(null);
    const wasSame = same();
    const profile = target();
    try {
      await props.save({ profile });
      toast({
        kind: "ok",
        title: wasSame
          ? t("settings.security.profile.reset_done", { profile: t(`profile.${profile}.name`) })
          : t("settings.security.profile.switch_done", { profile: t(`profile.${profile}.name`) }),
      });
      props.onClose();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog label={t("settings.security.profile.dialog_title")} onClose={props.onClose} class="dialog wide">
      <form class="dialog-form" onSubmit={(e) => void submit(e)} novalidate>
        <h2 class="dialog-title">{t("settings.security.profile.dialog_title")}</h2>
        <div class="dialog-body">
          <ErrorNotice error={error()} />
          <ReloadedNote error={error()} />

          <div class="field">
            <span class="label" id="pd-label">
              {t("settings.security.profile.heading")}
            </span>
            <div class="choices" role="radiogroup" aria-labelledby="pd-label">
              <For each={PROFILES}>
                {(p) => (
                  <label class="choice">
                    <input type="radio" name="profile" value={p} checked={target() === p} onChange={() => select(p)} />
                    <span>
                      <strong>{t(`profile.${p}.name`)}</strong>
                      <Show when={p === current()}>
                        {" "}
                        <span class="tag accent">{t("settings.security.profile.current")}</span>
                      </Show>
                      <small class="muted">{t(`profile.${p}.description`)}</small>
                    </span>
                  </label>
                )}
              </For>
            </div>
          </div>

          <div class="consequences" aria-live="polite">
            <p>
              {same()
                ? t("settings.security.profile.resets_same", { profile: name() })
                : t("settings.security.profile.resets", { profile: name() })}
            </p>
            <Show
              when={changes().length > 0}
              fallback={<p class="muted">{t("settings.security.profile.no_changes")}</p>}
            >
              <p class="muted">{t("settings.security.profile.changes", { count: changes().length })}</p>
              <div class="table-wrap">
                <table class="plain" aria-label={t("settings.security.profile.changes_table")}>
                  <thead>
                    <tr>
                      <th scope="col">{t("settings.security.col.setting")}</th>
                      <th scope="col">{t("settings.security.profile.col_now")}</th>
                      <th scope="col">{t("settings.security.profile.col_after")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={changes()}>
                      {(c) => (
                        <tr>
                          <td>
                            {t(c.def.name)} <span class="mono muted">{c.def.id}</span>
                          </td>
                          <td>{formatToggle(c.def.setting, c.from)}</td>
                          <td>
                            {formatToggle(c.def.setting, c.to)}
                            <Show when={c.weaker}>
                              {" "}
                              <span class="deviation weak">
                                <Icon name="alert" size="xs" />
                                {t("settings.security.marker.weak")}
                              </span>
                            </Show>
                          </td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
              </div>
            </Show>

            <Show when={pinRefused()}>
              <Notice kind="bad">{t("errors.settings.pin_coupling")}</Notice>
            </Show>
            <Show when={lab() && !same()}>
              <Notice kind="bad" title={t("settings.security.profile.lab_title")}>
                {t("settings.security.profile.lab_warning")}
              </Notice>
            </Show>
            <Show when={!lab() && weakNames().length > 0 && !same()}>
              <Notice kind="bad" title={t("settings.security.marker.weak")}>
                {t("settings.security.profile.weak_warning", { names: formatList(weakNames()) })}
              </Notice>
            </Show>
          </div>

          <Show when={needsAck()}>
            <label class="ackrow">
              <input
                type="checkbox"
                class="cb"
                checked={acknowledged()}
                onChange={(e) => setAcknowledged(e.currentTarget.checked)}
              />
              <span>{t("settings.security.profile.lab_ack")}</span>
            </label>
          </Show>
        </div>
        <div class="dialog-actions">
          <button type="button" class="btn ghost" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button
            type="submit"
            class={lab() && !same() ? "btn danger" : "btn primary"}
            disabled={busy() || nothing() || pinRefused() || (needsAck() && !acknowledged())}
          >
            {confirmLabel()}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
