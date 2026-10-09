// Who did something (jobs, audit, history): a user by name, an API token, a component of
// Tenko itself, or a node. A user other than the signed-in one is looked up once per tab;
// accounts without the right to read users see a short id instead.
import { createResource, Match, Switch } from "solid-js";
import { api } from "../api/client";
import type { Principal } from "../api/types";
import { session } from "../auth/session";
import { t } from "../i18n";

const names = new Map<string, Promise<string | null>>();

function userName(id: string): Promise<string | null> {
  let p = names.get(id);
  if (!p) {
    p = api
      .get("/api/v1/users/{id}", { path: { id } })
      .then((u) => u.display_name || u.name)
      .catch(() => null);
    names.set(id, p);
  }
  return p;
}

/** A short form of an id for display ("0190d1c2"). */
export function shortId(id: string | number): string {
  return String(id).slice(0, 8);
}

/** The principal in words, without a lookup (the user's own name, else a short id). */
export function principalText(p: Principal): string {
  switch (p.kind) {
    case "user": {
      const me = session()?.user;
      if (me && me.id === p.id) return t("principal.you", { name: me.display_name || me.name });
      return t("principal.user", { id: shortId(p.id) });
    }
    case "token":
      return t("principal.token", { id: shortId(p.id) });
    case "system":
      return t("principal.system", { component: p.component });
    case "node":
      return t("principal.node", { id: String(p.id) });
  }
}

export function PrincipalLabel(props: { principal: Principal }) {
  const otherUser = () => {
    const p = props.principal;
    return p.kind === "user" && p.id !== session()?.user.id ? p.id : false;
  };
  const [name] = createResource(otherUser, userName);
  return (
    <span class="principal" title={props.principal.kind === "user" ? props.principal.id : undefined}>
      <Switch fallback={principalText(props.principal)}>
        <Match when={otherUser() && name()}>{(n) => n()}</Match>
      </Switch>
    </span>
  );
}
