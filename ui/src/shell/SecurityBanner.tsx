import { A } from "@solidjs/router";
import { Show } from "solid-js";
import { paths } from "../app/paths";
import { isAdmin, session } from "../auth/session";
import { Icon } from "../components/Icon";
import { t } from "../i18n";

/**
 * The persistent warning while the Lab profile or any setting weaker than the Home
 * profile is active (API-10, SECURITY-PROFILES.md). It cannot be dismissed. The
 * break-glass account gets the same treatment.
 */
export function SecurityBanner() {
  return (
    <div class="banners">
      <RiskBanner />
      <ActionBanner />
    </div>
  );
}

/** What this account must do before anything else: a second factor or a new password. */
function ActionBanner() {
  const flags = () => session()?.flags;
  return (
    <Show when={flags()?.mfa_enrolment_required || flags()?.password_change_required}>
      <div class="banner warn" role="status">
        <Icon name="key" />
        <span class="grow">
          {flags()?.password_change_required ? t("shell.banner.password_change") : t("shell.banner.mfa_required")}
        </span>
        <A class="btn sm" href={paths.account()}>
          {t("shell.banner.fix")}
        </A>
      </div>
    </Show>
  );
}

function RiskBanner() {
  const banner = () => session()?.banner;
  const breakGlass = () => session()?.flags.break_glass ?? false;
  const visible = () => !!banner()?.lab || !!banner()?.weaker_than_home || breakGlass();
  return (
    <Show when={visible()}>
      <div class="banner danger" role="alert">
        <Icon name="alert" />
        <Show
          when={breakGlass()}
          fallback={
            <>
              <strong>{banner()?.lab ? t("shell.banner.lab_title") : t("shell.banner.weak_title")}</strong>
              <span class="grow">{banner()?.lab ? t("shell.banner.lab_body") : t("shell.banner.weak_body")}</span>
            </>
          }
        >
          <strong>{t("shell.banner.break_glass_title")}</strong>
          <span class="grow">{t("shell.banner.break_glass_body")}</span>
        </Show>
        <Show when={isAdmin()}>
          <A class="btn sm danger" href={paths.settings("security")}>
            {t("shell.banner.review")}
          </A>
        </Show>
      </div>
    </Show>
  );
}
