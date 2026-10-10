// Settings: the security profile and toggles, and user administration; the navigation also
// leads to the updates page and to the operator secrets (/settings/secrets, a route of its own
// in the secrets area). The route is /settings/:section?/:id? and needs the administrator role
// (enforced by the router).
import { Navigate, useParams } from "@solidjs/router";
import { Match, Show, Switch } from "solid-js";
import { decodeSegment, paths } from "../app/paths";
import { PageHead } from "../components/PageHead";
import { t } from "../i18n";
import SecurityPage from "./SecurityPage";
import { SettingsNav } from "./SettingsNav";
import UserDetail from "./UserDetail";
import UsersPage from "./UsersPage";
import "./settings.css";

export default function Settings() {
  const params = useParams<{ section?: string; id?: string }>();
  return (
    <div class="page">
      <PageHead title={t("settings.title")} />
      <SettingsNav />
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
