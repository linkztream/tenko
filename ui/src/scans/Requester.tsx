// Who started a scan: the display name of the user, looked up once per tab. An account that may
// not read users, or an id that is no user (a token), sees a short id instead.
import { createResource } from "solid-js";
import { api } from "../api/client";
import { session } from "../auth/session";
import { shortId } from "../components/Principal";
import { t } from "../i18n";

const names = new Map<string, Promise<string | null>>();

function userName(id: string): Promise<string | null> {
  let found = names.get(id);
  if (!found) {
    found = api
      .get("/api/v1/users/{id}", { path: { id } })
      .then((u) => u.display_name || u.name)
      .catch(() => null);
    names.set(id, found);
  }
  return found;
}

export function Requester(props: { id: string }) {
  const me = () => (session()?.user.id === props.id ? session()?.user : undefined);
  const [name] = createResource(() => (me() ? false : props.id), userName);
  return (
    <span class="principal" title={props.id}>
      {me()?.display_name || me()?.name || name() || t("principal.user", { id: shortId(props.id) })}
    </span>
  );
}
