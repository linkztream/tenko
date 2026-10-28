import { A } from "@solidjs/router";
import { createEffect, createSignal, createUniqueId, getOwner, lazy, runWithOwner, Show, type Accessor } from "solid-js";
import type { SystemStatus } from "../api/types";
import { paths } from "../app/paths";
import { cycleTheme, effectiveTheme, theme } from "../app/prefs";
import { session } from "../auth/session";
import { Icon } from "../components/Icon";
import { Kbd } from "../components/Kbd";
import { Mark, Wordmark } from "../components/Mark";
import { formatNumber, t, withPacks, type MessageKey } from "../i18n";
import type { ClusterSummary } from "./cluster";

// The cards behind the node and profile chips load with their area's texts when first opened.
const TopCards = lazy(withPacks(["cluster", "settings"], () => import("./TopCards")));

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
  // A single controller is one node and needs nothing else; the summary of a cluster (a read of
  // its members) loads only when the status says there is one.
  const owner = getOwner();
  let loading = false;
  const [summary, setSummary] = createSignal<Accessor<ClusterSummary> | null>(null);
  const multi = () => {
    const state = props.system?.store.quorum?.state;
    return state !== undefined && state !== "single";
  };
  createEffect(() => {
    if (!multi() || loading) return;
    loading = true;
    void import("./cluster").then((module) => runWithOwner(owner, () => setSummary(() => module.createClusterSummary(() => props.system))));
  });
  const cluster = (): ClusterSummary => {
    if (!props.system) return { nodes: null, behind: 0, view: null };
    if (!multi()) return { nodes: 1, behind: 0, view: null };
    return summary()?.() ?? { nodes: null, behind: 0, view: null };
  };

  // The cluster card of the node chip and the profile card of the profile chip: one at a time.
  const cardId = createUniqueId();
  const [card, setCard] = createSignal<{ kind: "cluster" | "profile"; anchor: HTMLElement } | null>(null);
  const open = () => card()?.kind;
  const toggle = (kind: "cluster" | "profile", anchor: HTMLElement) => setCard((cur) => (cur?.kind === kind ? null : { kind, anchor }));
  const close = () => setCard(null);

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
        <button
          type="button"
          class="pill"
          title={nodeTitle()}
          aria-haspopup="dialog"
          aria-expanded={open() === "cluster"}
          aria-controls={open() === "cluster" ? cardId : undefined}
          data-testid="node-chip"
          onClick={(e) => toggle("cluster", e.currentTarget)}
        >
          <span class={nodeDot()} />
          <span>
            <strong>{props.system ? storeRoleLabel(props.system.store.role) : "–"}</strong>
            <Show when={cluster().nodes}>
              {(nodes) => <> · {t("shell.top.cluster", { nodes: nodes(), behind: cluster().behind })}</>}
            </Show>
          </span>
        </button>
        <Show when={profile()}>
          {(p) => (
            <button
              type="button"
              class={p() === "lab" ? "pill danger" : "pill"}
              title={t("shell.top.profile_title", { profile: t(`profile.${p()}.name`) })}
              aria-haspopup="dialog"
              aria-expanded={open() === "profile"}
              aria-controls={open() === "profile" ? cardId : undefined}
              data-testid="profile-chip"
              onClick={(e) => toggle("profile", e.currentTarget)}
            >
              <Icon name="shield" size="sm" />
              <span>{t("shell.top.profile", { profile: t(`profile.${p()}.name`) })}</span>
            </button>
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
          data-testid="account-menu"
          aria-haspopup="dialog"
          aria-expanded={props.accountOpen}
          aria-label={t("shell.account.open", { name: session()?.user.display_name ?? "" })}
          title={t("shell.account.open", { name: session()?.user.display_name ?? "" })}
          onClick={(e) => props.onAccount(e.currentTarget)}
        >
          {initials(session()?.user.display_name || session()?.user.name || "?")}
        </button>
      </div>
      <Show when={card()}>
        {(c) => (
          <TopCards
            kind={c().kind}
            id={cardId}
            anchor={c().anchor}
            system={props.system}
            summary={cluster()}
            profile={profile() ?? "standard"}
            onClose={close}
          />
        )}
      </Show>
    </header>
  );
}
