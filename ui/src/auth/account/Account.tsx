import { A, useParams } from "@solidjs/router";
import { For, Match, Show, Switch } from "solid-js";
import { decodeSegment, paths, type AccountSection } from "../../app/paths";
import { CaRootLink } from "../../components/CaRootLink";
import { PageHead } from "../../components/PageHead";
import { t, type MessageKey } from "../../i18n";
import { session } from "../session";
import "../auth.css";
import "./account.css";
import Methods from "./Methods";
import Sessions from "./Sessions";
import Tokens from "./Tokens";

const LINKS: readonly { section: AccountSection; label: MessageKey }[] = [
  { section: "security", label: "account.nav.methods" },
  { section: "sessions", label: "account.nav.sessions" },
  { section: "tokens", label: "account.nav.tokens" },
];

/** The account pages: sign-in methods, sessions and personal tokens (IAM-03 to IAM-10). */
export default function Account() {
  const params = useParams<{ section?: string }>();
  // No section is the sign-in methods; an unknown one shows them too.
  const section = (): AccountSection => {
    const s = decodeSegment(params.section);
    return s === "sessions" || s === "tokens" ? s : "security";
  };

  return (
    <div class="page">
      <PageHead title={t("account.title")} sub={session()?.user.display_name} />
      <nav class="subnav" aria-label={t("account.nav.label")}>
        <For each={LINKS}>
          {(link) => (
            <A href={paths.account(link.section)} classList={{ active: section() === link.section }}>
              {t(link.label)}
            </A>
          )}
        </For>
      </nav>
      <Show when={session()}>
        <Switch>
          <Match when={section() === "sessions"}>
            <Sessions />
          </Match>
          <Match when={section() === "tokens"}>
            <Tokens />
          </Match>
          <Match when={true}>
            <Methods />
            <div class="page-body">
              <CaRootLink withHelp />
            </div>
          </Match>
        </Switch>
      </Show>
    </div>
  );
}
