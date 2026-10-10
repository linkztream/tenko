// Settings: the security profile and toggles, and user administration; links lead to the
// updates page and the operator secrets. The route is /settings/:section?/:id? and needs
// the administrator role (enforced by the router).
import { A, Navigate, useParams } from "@solidjs/router";
import { Match, Show, Switch } from "solid-js";
import { decodeSegment, paths } from "../app/paths";
import { PageHead } from "../components/PageHead";
import { t } from "../i18n";
import { SECRETS_PATH } from "../secrets/paths";
import { UPDATES_PATH } from "../updates/paths";
import SecurityPage from "./SecurityPage";
import UserDetail from "./UserDetail";
import UsersPage from "./UsersPage";
import "./settings.css";

export default function Settings() {
  const params = useParams<{ section?: string; id?: string }>();
  return (
    <div class="page">
      <PageHead title={t("settings.title")} />
      <nav class="subnav" aria-label={t("settings.nav.label")}>
        <A href={paths.settings("security")}>{t("settings.nav.security")}</A>
        <A href={paths.settings("users")}>{t("settings.nav.users")}</A>
        <A href={UPDATES_PATH}>{t("settings.nav.updates")}</A>
        <A href={SECRETS_PATH}>{t("settings.nav.secrets")}</A>
      </nav>
      <Switch fallback={<Navigate href={paths.settings("security")} />}>
        <Match when={params.section === "security"}>
          <SecurityPage />
        </Match>
        <Match when={params.section === "users"}>
          <Show when={params.id} keyed fallback={<UsersPage />}>
            {(id) => <UserDetail id={decodeSegment(id)} />}
          </Show>
        </Match>
      </Switch>
    </div>
  );
}
