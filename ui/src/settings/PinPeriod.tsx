// The period an unconfirmed PIN keeps working, next to the password policy (TGL-01): a PIN
// stored before the PIN minimum rose to six digits stops working that many days after the
// upgrade unless a sign-in confirms it is long enough.
import { createEffect, createSignal, on, Show, untrack } from "solid-js";
import type { SecuritySettingsView, SettingsPatch } from "../api/types";
import { ErrorNotice } from "../components/Notice";
import { toast } from "../components/toast";
import { t } from "../i18n";
import { FieldHelp, ReloadedNote } from "./fields";
import { toPinDays, UNCONFIRMED_PIN_DAYS_DEFAULT } from "./toggleEdit";

/** The days of the settings; settings stored before the rule follow the default. */
export function pinDaysOf(view: SecuritySettingsView): number {
  return view.settings.unconfirmed_pin_days ?? UNCONFIRMED_PIN_DAYS_DEFAULT;
}

export function PinPeriod(props: {
  view: SecuritySettingsView;
  save: (patch: SettingsPatch) => Promise<SecuritySettingsView>;
}) {
  const [text, setText] = createSignal(String(untrack(() => pinDaysOf(props.view))));
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>(null);

  // A reload or a profile switch brings a new value.
  createEffect(on(() => pinDaysOf(props.view), (days) => setText(String(days)), { defer: true }));

  const parsed = () => toPinDays(text());
  const changed = () => parsed() !== undefined && parsed() !== pinDaysOf(props.view);

  const submit = async (e: Event) => {
    e.preventDefault();
    const days = parsed();
    if (days === undefined || !changed() || busy()) return;
    setBusy(true);
    setError(null);
    try {
      const next = await props.save({ unconfirmed_pin_days: days });
      setText(String(pinDaysOf(next)));
      toast({ kind: "ok", title: t("settings.security.pin_days.saved"), body: t("settings.security.pin_days.value", { days }) });
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section class="page-section" aria-labelledby="sec-pin-days" data-testid="pin-period">
      <h2 id="sec-pin-days">{t("settings.security.pin_days.heading")}</h2>
      <p class="muted">{t("settings.security.pin_days.intro")}</p>
      <form class="dialog-form" onSubmit={(e) => void submit(e)} novalidate>
        <ErrorNotice error={error()} />
        <ReloadedNote error={error()} />
        <div class="field">
          <label for="tg-pin-days">{t("settings.security.pin_days.label")}</label>
          <div class="form-row">
            <input
              id="tg-pin-days"
              data-testid="field-unconfirmed_pin_days"
              class="input num duration"
              inputmode="numeric"
              autocomplete="off"
              value={text()}
              aria-invalid={parsed() === undefined ? "true" : undefined}
              aria-describedby="tg-pin-days-help"
              onInput={(e) => setText(e.currentTarget.value)}
            />
            <button type="submit" class="btn" disabled={busy() || !changed()} data-testid="pin-days-save">
              {t("settings.security.save")}
            </button>
            <Show when={text().trim() !== String(UNCONFIRMED_PIN_DAYS_DEFAULT)}>
              <button
                type="button"
                class="btn ghost"
                data-testid="pin-days-default"
                onClick={() => setText(String(UNCONFIRMED_PIN_DAYS_DEFAULT))}
              >
                {t("settings.security.pin_days.use_default", { days: UNCONFIRMED_PIN_DAYS_DEFAULT })}
              </button>
            </Show>
          </div>
          <FieldHelp
            id="tg-pin-days-help"
            help={t("settings.security.pin_days.help", { days: UNCONFIRMED_PIN_DAYS_DEFAULT })}
            error={parsed() === undefined ? t("settings.security.pin_days.error") : undefined}
          />
        </div>
      </form>
    </section>
  );
}
