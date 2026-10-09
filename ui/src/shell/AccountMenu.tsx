import { A } from "@solidjs/router";
import { For, onCleanup, onMount } from "solid-js";
import { Portal } from "solid-js/web";
import { api } from "../api/client";
import { DENSITIES, density, emphasizeHost, setDensity, setEmphasizeHost, setTheme, theme, THEMES } from "../app/prefs";
import { paths } from "../app/paths";
import { applyLanguage, session, updateUserLanguage } from "../auth/session";
import { Addr, Mac } from "../components/Addr";
import { Icon } from "../components/Icon";
import { Kbd } from "../components/Kbd";
import { Segmented } from "../components/Segmented";
import { Switch } from "../components/Switch";
import { toast } from "../components/toast";
import { availableLocales, storeLocale, t } from "../i18n";

/**
 * The account menu (avatar, top right): theme, row density, "Emphasize host part",
 * language, security and sign-in, keyboard shortcuts and sign out.
 */
export function AccountMenu(props: {
  anchor: HTMLElement;
  onClose: () => void;
  onShortcuts: () => void;
  onSignOut: () => void;
}) {
  let menu!: HTMLDivElement;
  const s = () => session();

  const onDown = (e: MouseEvent) => {
    const target = e.target as Node;
    if (!menu.contains(target) && !props.anchor.contains(target)) props.onClose();
  };
  const onKey = (e: KeyboardEvent) => {
    if (e.key === "Escape") {
      e.stopPropagation();
      props.onClose();
      props.anchor.focus();
    }
  };
  onMount(() => {
    const r = props.anchor.getBoundingClientRect();
    menu.style.setProperty("top", `${r.bottom + 6}px`);
    menu.style.setProperty("right", `${Math.max(8, window.innerWidth - r.right)}px`);
    document.addEventListener("mousedown", onDown);
    menu.querySelector<HTMLElement>("button, input, select, a")?.focus();
  });
  onCleanup(() => document.removeEventListener("mousedown", onDown));

  const strength = () => {
    const st = s()?.strength;
    return st ? t(`auth.strength.${st}`) : "";
  };
  const role = () => {
    const roles = s()?.roles ?? [];
    const top = roles.includes("admin") ? "admin" : roles.includes("operator") ? "operator" : "viewer";
    return t(`role.${top}.name`);
  };

  const changeLanguage = async (code: string) => {
    const user = s()?.user;
    if (!user) return;
    try {
      await api.patch("/api/v1/users/{id}", { path: { id: user.id }, body: { language: code } });
      storeLocale(null);
      updateUserLanguage(code || null);
    } catch {
      storeLocale(code || null);
      updateUserLanguage(code || null);
      toast({ title: t("shell.account.language_local") });
    }
    await applyLanguage();
  };

  return (
    <Portal>
      <div
        ref={menu}
        class="acct"
        role="dialog"
        aria-label={t("shell.account.title")}
        onKeyDown={onKey}
        data-testid="dialog-account"
      >
        <div class="who">
          <strong>{s()?.user.display_name}</strong>
          <span>{t("shell.account.who", { role: role(), method: strength() })}</span>
        </div>
        <div class="row">
          <span class="lbl">{t("shell.account.theme")}</span>
          <Segmented
            label={t("shell.account.theme")}
            value={theme()}
            onChange={setTheme}
            options={THEMES.map((v) => ({ value: v, label: t(`prefs.theme.${v}`) }))}
          />
        </div>
        <div class="row">
          <span class="lbl">{t("shell.account.density")}</span>
          <Segmented
            label={t("shell.account.density")}
            value={density()}
            onChange={setDensity}
            options={DENSITIES.map((v) => ({ value: v, label: t(`prefs.density.${v}`) }))}
          />
        </div>
        <div class="row">
          <Switch
            checked={emphasizeHost()}
            onChange={setEmphasizeHost}
            label={t("shell.account.emphasis")}
            hint={t("shell.account.emphasis_hint")}
          />
          <span class="sample">
            <Addr value="192.0.2.41" />, <Mac value="00-00-5E-00-53-29" />
          </span>
        </div>
        <div class="row">
          <label class="lbl" for="acct-language">
            {t("shell.account.language")}
          </label>
          <select
            id="acct-language"
            data-testid="field-language"
            class="select"
            value={s()?.user.language ?? ""}
            onChange={(e) => void changeLanguage(e.currentTarget.value)}
          >
            <option value="">{t("shell.account.language_auto")}</option>
            <For each={availableLocales()}>{(l) => <option value={l.code}>{l.name}</option>}</For>
          </select>
        </div>
        <div class="row items">
          <A class="item" href={paths.account()} onClick={() => props.onClose()} data-testid="account-security">
            <Icon name="key" />
            {t("shell.account.security")}
          </A>
          <button type="button" class="item" onClick={() => props.onShortcuts()}>
            <Icon name="info" />
            {t("shell.keys.title")}
            <Kbd keys={["?"]} />
          </button>
          <button type="button" class="item" onClick={() => props.onSignOut()} data-testid="account-sign-out">
            <Icon name="user" />
            {t("shell.account.sign_out")}
          </button>
        </div>
      </div>
    </Portal>
  );
}
