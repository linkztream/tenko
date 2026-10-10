// Editing one toggle: the editor that fits the value, and above the buttons what saving
// would do (the warning banner, the deviation marker) before anything is sent.
import { createSignal, Match, Show, Switch, untrack } from "solid-js";
import type {
  BreachMode,
  LockoutMode,
  MfaRequirement,
  PasswordPolicy,
  SecuritySettingsView,
  SessionLifetime,
  SettingsPatch,
} from "../api/types";
import { Dialog } from "../components/Dialog";
import { ErrorNotice, Notice } from "../components/Notice";
import { toast } from "../components/toast";
import { t } from "../i18n";
import { ReloadedNote } from "./fields";
import { homeValue, pinCoupled, sameValue } from "./profileMatrix";
import { patchFor } from "./toggleEdit";
import {
  AuditExportEditor,
  BreachEditor,
  LockoutEditor,
  MfaEditor,
  PasskeyEditor,
  PolicyEditor,
  RevealEditor,
  SessionEditor,
  TokenEditor,
  UpdatesEditor,
} from "./ToggleEditors";
import { formatToggle, weakerThan, type AuditExport, type RevealPolicy, type ToggleDef, type UpdatesPolicy } from "./toggles";

export function ToggleDialog(props: {
  view: SecuritySettingsView;
  def: ToggleDef;
  save: (patch: SettingsPatch) => Promise<SecuritySettingsView>;
  onClose: () => void;
}) {
  const setting = untrack(() => props.def.setting);
  const state = () => props.view.toggles.find((s) => s.id === props.def.id);
  const initial = untrack(() => state()?.value);
  const home = homeValue(setting);
  const name = () => t(props.def.name);

  // The value the form would save; undefined while the form has a mistake in it.
  const [draft, setDraft] = createSignal<{ value: unknown } | undefined>({ value: initial });
  const onDraft = (value: unknown) => setDraft(value === undefined ? undefined : { value });
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);

  const profile = () => props.view.settings.profile;
  const changed = () => {
    const d = draft();
    return d !== undefined && !sameValue(d.value, state()?.value);
  };
  const draftWeak = () => {
    const d = draft();
    return d !== undefined && weakerThan(setting, d.value, home);
  };
  const draftDiffers = () => {
    const d = draft();
    return d !== undefined && !sameValue(d.value, state()?.profile_default);
  };
  const currentWeak = () => state()?.weaker_than_home ?? false;
  const currentDiffers = () => state()?.deviates ?? false;
  const bannerOn = () => props.view.banner.lab || props.view.banner.weaker_than_home;
  const othersWeak = () => props.view.toggles.some((x) => x.id !== props.def.id && x.weaker_than_home);
  const labActive = () => profile() === "lab";
  // The PIN coupling rule (IAM-07) looks at the policy and at MFA together; no other toggle can break it.
  const pinRefused = () => {
    const d = draft();
    if (d === undefined) return false;
    const { password_policy, mfa } = props.view.settings;
    if (setting === "password_policy") return pinCoupled(props.view, { password_policy: d.value as PasswordPolicy, mfa });
    if (setting === "mfa") return pinCoupled(props.view, { password_policy, mfa: d.value as MfaRequirement });
    return false;
  };

  const submit = async (e: Event) => {
    e.preventDefault();
    const d = draft();
    if (!d || !changed() || pinRefused() || busy()) return;
    setBusy(true);
    setError(null);
    try {
      await props.save(patchFor(setting, d.value));
      toast({ kind: "ok", title: t("settings.security.saved", { name: name() }), body: formatToggle(setting, d.value) });
      props.onClose();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      label={t("settings.security.edit_title", { name: name() })}
      onClose={props.onClose}
      class="dialog wide"
      testid="dialog-toggle"
    >
      <form class="dialog-form" onSubmit={(e) => void submit(e)} novalidate>
        <h2 class="dialog-title">
          {t("settings.security.edit_title", { name: name() })} <span class="mono muted">{props.def.id}</span>
        </h2>
        <div class="dialog-body">
          <ErrorNotice error={error()} />
          <ReloadedNote error={error()} />
          <dl class="kv">
            <dt>{t("settings.security.col.value")}</dt>
            <dd>{formatToggle(setting, state()?.value)}</dd>
            <dt>{t("settings.security.col.profile")}</dt>
            <dd>{formatToggle(setting, state()?.profile_default)}</dd>
          </dl>

          <Switch>
            <Match when={setting === "password_policy"}>
              <PolicyEditor initial={initial as PasswordPolicy} onDraft={onDraft} />
            </Match>
            <Match when={setting === "mfa"}>
              <MfaEditor initial={initial as MfaRequirement} onDraft={onDraft} />
            </Match>
            <Match when={setting === "passkey_for_admins"}>
              <PasskeyEditor initial={Boolean(initial)} onDraft={onDraft} />
            </Match>
            <Match when={setting === "session"}>
              <SessionEditor initial={initial as SessionLifetime} onDraft={onDraft} />
            </Match>
            <Match when={setting === "token_max_days"}>
              <TokenEditor initial={(initial ?? null) as number | null} onDraft={onDraft} />
            </Match>
            <Match when={setting === "breach_check"}>
              <BreachEditor initial={initial as BreachMode} onDraft={onDraft} />
            </Match>
            <Match when={setting === "lockout"}>
              <LockoutEditor initial={initial as LockoutMode} onDraft={onDraft} />
            </Match>
            <Match when={setting === "audit_export"}>
              <AuditExportEditor initial={initial as AuditExport} onDraft={onDraft} />
            </Match>
            <Match when={setting === "updates"}>
              <UpdatesEditor initial={initial as UpdatesPolicy} onDraft={onDraft} />
            </Match>
            <Match when={setting === "secret_reveal"}>
              <RevealEditor initial={initial as RevealPolicy} onDraft={onDraft} />
            </Match>
          </Switch>

          <div class="consequences" aria-live="polite">
            <Show when={!changed()}>
              <p class="muted">{t("settings.security.consequence.none")}</p>
            </Show>
            <Show when={pinRefused()}>
              <Notice kind="bad" testid="toggle-pin-coupling">{t("errors.settings.pin_coupling")}</Notice>
            </Show>
            <Show when={changed() && draftWeak()}>
              <Notice kind="bad" title={t("settings.security.marker.weak")}>
                {bannerOn() ? t("settings.security.consequence.weak_stays") : t("settings.security.consequence.weak_new")}
              </Notice>
            </Show>
            <Show when={changed() && !draftWeak() && currentWeak()}>
              <Notice kind="ok">
                {labActive()
                  ? t("settings.security.consequence.raised_lab")
                  : othersWeak()
                    ? t("settings.security.consequence.raised_others")
                    : t("settings.security.consequence.raised_clears")}
              </Notice>
            </Show>
            <Show when={changed() && draftDiffers() && !currentDiffers()}>
              <Notice kind="info">
                {t("settings.security.consequence.differs", { profile: t(`profile.${profile()}.name`) })}
              </Notice>
            </Show>
            <Show when={changed() && !draftDiffers() && currentDiffers()}>
              <Notice kind="info">
                {t("settings.security.consequence.matches", { profile: t(`profile.${profile()}.name`) })}
              </Notice>
            </Show>
          </div>
        </div>
        <div class="dialog-actions">
          <button type="button" class="btn ghost" onClick={() => props.onClose()} data-testid="form-cancel">
            {t("common.action.cancel")}
          </button>
          <button
            type="submit"
            class="btn primary"
            disabled={busy() || !changed() || pinRefused()}
            data-testid="form-submit"
          >
            {t("settings.security.save")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
