// Settings: the security profile and toggles, and user administration. The route is
// /settings/:section?/:id? and needs the administrator role (enforced by the router).
import { A, Navigate, useParams } from "@solidjs/router";
import { Match, Show, Switch } from "solid-js";
import { decodeSegment, paths } from "../app/paths";
import { PageHead } from "../components/PageHead";
import { t } from "../i18n";
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
