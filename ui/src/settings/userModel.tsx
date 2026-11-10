// How a user reads in the lists and on the detail page: status with glyph and word,
// roles, sign-in methods and language.
import { Show } from "solid-js";
import type { FactorSummary, RoleName, UserInfo } from "../api/types";
import { Icon } from "../components/Icon";
import { availableLocales, formatDateTime, formatList, t } from "../i18n";

const DAY_MS = 86_400_000;

/** Whole days until a PIN that no sign-in has confirmed stops working; 0 or less once it has. */
export function pinDaysLeft(expiresAt: string, now: number = Date.now()): number {
  return Math.ceil((new Date(expiresAt).getTime() - now) / DAY_MS);
}

/** The status of an account: active, disabled, locked, break-glass, password change required. */
export function UserStatus(props: { user: UserInfo }) {
  const quiet = () => !props.user.disabled && !props.user.lock;
  return (
    <span class="user-status">
      <Show when={props.user.disabled}>
        <span class="flag status-disabled">
          <Icon name="pause" size="xs" />
          {t("settings.users.status.disabled")}
        </span>
      </Show>
      <Show when={props.user.lock}>
        {(lock) => (
          <span class="flag locked">
            <Icon name="lock" size="xs" />
            {lock().until_unlock
              ? t("settings.users.status.locked_manual")
              : t("settings.users.status.locked", { time: formatDateTime(lock().until) })}
          </span>
        )}
      </Show>
      <Show when={quiet()}>
        <span class="flag status-active">
          <Icon name="check" size="xs" />
          {t("settings.users.status.active")}
        </span>
      </Show>
      <Show when={props.user.break_glass}>
        <span class="flag status-break-glass">
          <Icon name="key" size="xs" />
          {t("settings.users.status.break_glass")}
        </span>
      </Show>
      <Show when={props.user.password_change_required}>
        <span class="flag discrepancy">
          <Icon name="refresh" size="xs" />
          {t("settings.users.status.password_change")}
        </span>
      </Show>
      <Show when={props.user.pin_expires_at}>
        {(at) => (
          <span class="flag discrepancy" title={t("settings.users.status.pin_until", { time: formatDateTime(at()) })}>
            <Icon name="clock" size="xs" />
            {pinDaysLeft(at()) > 0
              ? t("settings.users.status.pin_days", { days: pinDaysLeft(at()) })
              : t("settings.users.status.pin_expired")}
          </span>
        )}
      </Show>
    </span>
  );
}

/** The sign-in methods of an account, one phrase each. A security key is also a registered key. */
export function methodParts(f: FactorSummary): string[] {
  const parts: string[] = [];
  if (f.password) parts.push(t("settings.users.methods.password"));
  const passkeys = Math.max(0, f.webauthn - f.hardware_keys);
  if (passkeys > 0) parts.push(t("settings.users.methods.passkeys", { count: passkeys }));
  if (f.hardware_keys > 0) parts.push(t("settings.users.methods.security_keys", { count: f.hardware_keys }));
  if (f.totp) parts.push(t("settings.users.methods.authenticator"));
  if (f.recovery_codes > 0) parts.push(t("settings.users.methods.recovery_codes", { count: f.recovery_codes }));
  return parts;
}

export function methodsText(f: FactorSummary): string {
  const parts = methodParts(f);
  return parts.length > 0 ? formatList(parts, "unit") : t("common.none");
}

export function rolesText(roles: readonly RoleName[]): string {
  return formatList(
    roles.map((r) => t(`role.${r}.name`)),
    "unit",
  );
}

/** The name of a language, or "Follow the browser" when the account has none. */
export function languageName(code: string | null | undefined): string {
  if (!code) return t("shell.account.language_auto");
  return availableLocales().find((l) => l.code === code)?.name ?? code;
}
