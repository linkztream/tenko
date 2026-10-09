import { A } from "@solidjs/router";
import { Show } from "solid-js";
import type { SystemStatus } from "../api/types";
import { paths } from "../app/paths";
import { cycleTheme, effectiveTheme, theme } from "../app/prefs";
import { session } from "../auth/session";
import { Icon } from "../components/Icon";
import { Kbd } from "../components/Kbd";
import { Mark, Wordmark } from "../components/Mark";
import { formatNumber, t, type MessageKey } from "../i18n";

const STORE_ROLE: Record<string, MessageKey> = {
  leader: "shell.top.role.leader",
  follower: "shell.top.role.follower",
  learner: "shell.top.role.learner",
  candidate: "shell.top.role.candidate",
  memory: "shell.top.role.memory",
  shutdown: "shell.top.role.shutdown",
};

export function storeRoleLabel(role: string | undefined): string {
  const key = role ? STORE_ROLE[role] : undefined;
  return key ? t(key) : t("shell.top.role.unknown");
}

export function themeLabel(): string {
  const mode = effectiveTheme() === "dark" ? t("shell.theme.mode.dark") : t("shell.theme.mode.light");
  if (theme() === "system") return t("shell.theme.system", { mode });
  return theme() === "dark" ? t("shell.theme.dark") : t("shell.theme.light");
}

export function initials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  const letters = parts.length > 1 ? `${parts[0]?.[0] ?? ""}${parts[parts.length - 1]?.[0] ?? ""}` : (parts[0] ?? "?").slice(0, 2);
  return letters.toUpperCase();
}

export function TopBar(props: {
  system: SystemStatus | null;
  systemError: boolean;
  onPalette: () => void;
  onShortcuts: () => void;
  onAccount: (anchor: HTMLElement) => void;
  accountOpen: boolean;
}) {
  const nodeDot = () => {
    if (props.systemError || !props.system) return "dot bad";
    const lag = props.system.store.lag ?? 0;
    return lag > 0 || props.system.store.role === "candidate" ? "dot warn" : "dot live";
  };
  const nodeTitle = () =>
    props.system
      ? t("shell.top.node_title", {
          revision: formatNumber(props.system.store.revision),
          lag: props.system.store.lag ?? 0,
        })
      : t("shell.top.node_unreachable");
  const profile = () => session()?.profile;
  const icon = () => (theme() === "system" ? "system" : theme() === "light" ? "sun" : "moon");

  return (
    <header class="topbar">
      <A class="brand" href={paths.dashboard()} aria-label={t("shell.brand.home")}>
        <span class="mark-cell">
          <Mark />
        </span>
        <Wordmark />
      </A>
      <button type="button" class="cmd" onClick={() => props.onPalette()} aria-label={t("shell.top.command_open")}>
        <Icon name="search" />
        <span class="hint">{t("shell.top.command_hint")}</span>
        <Kbd keys={["Ctrl", "K"]} />
      </button>
      <span class="spacer" />
      <div class="top-group">
        <A class="pill" href={paths.dashboard()} title={nodeTitle()}>
          <span class={nodeDot()} />
          <span>
            {t("shell.top.node")} <strong>{props.system ? storeRoleLabel(props.system.store.role) : "–"}</strong>
          </span>
        </A>
        <Show when={profile()}>
          {(p) => (
            <A
              class={p() === "lab" ? "pill danger" : "pill"}
              href={paths.settings("security")}
              title={t("shell.top.profile_title", { profile: t(`profile.${p()}.name`) })}
            >
              <Icon name="shield" size="sm" />
              <span>{t("shell.top.profile", { profile: t(`profile.${p()}.name`) })}</span>
            </A>
          )}
        </Show>
        <button
          type="button"
          class="icon-btn"
          onClick={() => props.onShortcuts()}
          title={t("shell.top.shortcuts_title")}
          aria-label={t("shell.keys.title")}
        >
          <Icon name="info" />
        </button>
        <button
          type="button"
          class="icon-btn"
          onClick={() => cycleTheme()}
          title={t("shell.theme.change", { current: themeLabel() })}
          aria-label={themeLabel()}
        >
          <Icon name={icon()} />
        </button>
        <button
          type="button"
          class="avatar"
          aria-haspopup="dialog"
          aria-expanded={props.accountOpen}
          aria-label={t("shell.account.open", { name: session()?.user.display_name ?? "" })}
          title={t("shell.account.open", { name: session()?.user.display_name ?? "" })}
          onClick={(e) => props.onAccount(e.currentTarget)}
        >
          {initials(session()?.user.display_name || session()?.user.name || "?")}
        </button>
      </div>
    </header>
  );
}
