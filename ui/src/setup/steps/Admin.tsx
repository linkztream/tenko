import { For, Show } from "solid-js";
import { Icon, type IconName } from "../../components/Icon";
import { ErrorNotice } from "../../components/Notice";
import { t } from "../../i18n";
import { formatPolicy } from "../../settings/toggles";
import { buildChecklist, violationMessage, type ChecklistItem, type ItemState } from "../checklist";
import { FOCUS } from "../gates";
import { ProblemNotice } from "../parts";
import { isValidUserName } from "../validate";
import { useWizard } from "../controller";

const GLYPH: Partial<Record<ItemState, IconName>> = { ok: "check", bad: "x", off: "alert" };

/** Step 3: the first administrator, with the live password policy feedback. */
export function Admin() {
  const w = useWizard();
  const userBad = () => w.state.userName !== "" && !isValidUserName(w.state.userName);
  const kind = () => w.generatorKind();

  const items = (): ChecklistItem[] =>
    buildChecklist({
      hasPassword: w.state.password !== "",
      pending: w.checkStatus() === "pending",
      result: w.checkResult(),
      breachOff: w.breachOff(),
    });

  const ruleText = (): string => formatPolicy(w.checkResult()?.policy ?? w.policy());
  const text = (item: ChecklistItem): string => {
    const profile = t(`profile.${w.state.profile}.name`);
    switch (item.id) {
      case "rule":
        return ruleText();
      case "trivial":
        return t("setup.admin.check.trivial");
      case "context":
        return t("setup.admin.check.context");
      case "breach":
        if (item.state === "bad") return t("setup.admin.check.breach_found");
        if (item.state === "pending") return t("setup.admin.check.breach_pending");
        if (w.breachOff()) return t("setup.admin.check.breach_off", { profile });
        if (item.state === "off") return t("setup.admin.check.breach_unavailable");
        return t("setup.admin.check.breach");
    }
  };
  const word = (state: ItemState): string => {
    switch (state) {
      case "ok":
        return t("setup.admin.check.state.ok");
      case "bad":
        return t("setup.admin.check.state.bad");
      case "off":
        return t("setup.admin.check.state.off");
      case "pending":
        return t("setup.admin.check.state.pending");
      case "idle":
        return t("setup.admin.check.state.idle");
    }
  };
  const why = (item: ChecklistItem): string[] =>
    // The explanation under a row: the rule row says what exactly is missing.
    item.state === "bad" && item.id === "rule" ? item.violations.map(violationMessage) : [];

  const hint = () => {
    if (w.state.generated) return t("setup.admin.password.help_generated");
    return t(`setup.admin.password.help.${kind()}`, { profile: t(`profile.${w.state.profile}.name`) });
  };

  const passkeyTag = () =>
    w.state.profile === "hardened" ? t("common.required") : w.state.profile === "standard" ? t("common.recommended") : t("common.optional");

  return (
    <div>
      <p class="wz-lede">{t("setup.admin.lede")}</p>
      <ProblemNotice step={2} />

      <div class="wz-form">
        <div class="field">
          <label for={FOCUS.userName}>{t("setup.admin.user.label")}</label>
          <input
            id={FOCUS.userName}
            data-testid="field-user-name"
            class="input"
            classList={{ bad: userBad() }}
            value={w.state.userName}
            onInput={(e) => w.setState("userName", e.currentTarget.value)}
            autocomplete="username"
            autocapitalize="off"
            spellcheck={false}
            aria-invalid={userBad() ? "true" : undefined}
            aria-describedby="wz-user-help"
          />
          <span class="help" classList={{ bad: userBad() }} id="wz-user-help">
            {userBad() ? t("setup.admin.user.invalid") : t("setup.admin.user.help")}
          </span>
        </div>
        <div class="field">
          <label for={FOCUS.displayName}>{t("setup.admin.name.label")}</label>
          <input
            id={FOCUS.displayName}
            data-testid="field-display-name"
            class="input"
            value={w.state.displayName}
            onInput={(e) => w.setState("displayName", e.currentTarget.value)}
            autocomplete="name"
            aria-describedby="wz-name-help"
          />
          <span class="help" id="wz-name-help">
            {t("setup.admin.name.help")}
          </span>
        </div>

        <div class="field wide">
          <label for={FOCUS.password}>{t(`setup.admin.password.label.${kind()}`)}</label>
          <div class="wz-pwrow">
            <input
              id={FOCUS.password}
              data-testid="field-password"
              class="input mono"
              type={w.state.showPassword ? "text" : "password"}
              value={w.state.password}
              placeholder={t(`setup.admin.password.placeholder.${kind()}`)}
              onInput={(e) => {
                w.setState("password", e.currentTarget.value);
                w.setState("generated", false);
              }}
              autocomplete="new-password"
              autocapitalize="off"
              spellcheck={false}
              aria-describedby="wz-pw-help wz-checks"
            />
            <button
              type="button"
              class="icon-btn"
              aria-pressed={w.state.showPassword}
              aria-label={w.state.showPassword ? t("setup.admin.password.hide") : t("setup.admin.password.show")}
              title={w.state.showPassword ? t("setup.admin.password.hide") : t("setup.admin.password.show")}
              onClick={() => {
                w.setState("showPassword", (v) => !v);
                document.getElementById(FOCUS.password)?.focus();
              }}
            >
              <Icon name="eye" />
            </button>
            <button type="button" class="btn" onClick={() => w.generate()}>
              {t("setup.admin.password.generate")}
            </button>
          </div>
          <span class="help" id="wz-pw-help">
            {hint()}
          </span>
          <ul class="wz-checks" id="wz-checks" aria-live="polite">
            <For each={items()}>
              {(item) => (
                <li classList={{ [item.state]: true }}>
                  <span class="ck">
                    <Show when={GLYPH[item.state]}>{(name) => <Icon name={name()} />}</Show>
                  </span>
                  <span>
                    <span class="sr-only">{word(item.state)}: </span>
                    {text(item)}
                    <For each={why(item)}>{(m) => <span class="why">{m}</span>}</For>
                  </span>
                </li>
              )}
            </For>
          </ul>
          <Show when={w.checkStatus() === "error"}>
            <div class="wz-checkerr">
              <ErrorNotice error={w.checkError()} />
              <button type="button" class="btn sm" onClick={() => w.retryCheck()}>
                {t("common.action.retry")}
              </button>
            </div>
          </Show>
        </div>
      </div>

      <div class="wz-blk tight">
        <div class="wz-pk">
          <div class="info">
            <h2 class="wz-pk-title">
              {t("setup.admin.passkey.title")} <span class="tag" classList={{ accent: w.state.profile === "hardened" }}>{passkeyTag()}</span>
            </h2>
            <p class="wz-help ink">{t(`setup.admin.passkey.help.${w.state.profile}`)}</p>
          </div>
        </div>
      </div>

      <div class="wz-blk after">
        <div class="note">
          <Icon name="lock" size="sm" />
          <div class="grow">
            <strong>{t("setup.admin.vault.title")}</strong> {t("setup.admin.vault.body")}
          </div>
        </div>
        <p class="wz-help gap">{t("setup.admin.codes_note")}</p>
      </div>
    </div>
  );
}
