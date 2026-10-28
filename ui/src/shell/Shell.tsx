import { useLocation, useNavigate } from "@solidjs/router";
import { createEffect, createSignal, getOwner, lazy, on, onCleanup, onMount, runWithOwner, Show, type Accessor, type JSX } from "solid-js";
import { DENSITIES, setDensity, setEmphasizeHost, setTheme, cycleTheme, emphasizeHost, THEMES } from "../app/prefs";
import { paths } from "../app/paths";
import { hasRole, isAdmin, signOut } from "../auth/session";
import { t, withPacks } from "../i18n";
import { SECRETS_PATH } from "../secrets/paths";
import { ModuleGate } from "../updates/ModuleGate";
import { areaEnabled, loadModules, moduleRunning, resetModules, RESTART_WARNING } from "../updates/modules";
import { UPDATES_PATH } from "../updates/paths";
import { AccountMenu } from "./AccountMenu";
import { BugReportDialog } from "./BugReport";
import { AREAS } from "./areas";
import { ClusterBanner } from "./ClusterBanner";
import { CommandPalette } from "./CommandPalette";
import { useCommands } from "./commands";
import { useGlobalKeys } from "./keyboard";
import { KeySheet } from "./KeySheet";
import { trackLazyPart } from "./lazyParts";
import { Rail } from "./Rail";
import { SecurityBanner } from "./SecurityBanner";
import type { FindingCounts } from "./findings";
import type * as FindingsUi from "./findingsShell";
import { createShellStatus, setSelectionStatus } from "./status";
import { StatusBar } from "./StatusBar";
import { TopBar } from "./TopBar";

// The release notes after an upgrade, and on request, come from the updates area.
const WhatsNew = lazy(withPacks(["updates"], () => import("../updates/WhatsNew")));

const HINTS: Partial<Record<string, () => string>> = {
  dashboard: () => t("shell.command.dashboard_hint"),
};

/** The application frame: top bar, banner, rail, main area and status bar. */
export function Shell(props: { children?: JSX.Element }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [palette, setPalette] = createSignal<string | null>(null);
  const [sheet, setSheet] = createSignal(false);
  const [report, setReport] = createSignal(false);
  const [account, setAccount] = createSignal<HTMLElement | null>(null);
  const [notes, setNotes] = createSignal(false);
  const status = createShellStatus();
  // The one store of the findings counts: the rail badges and the status bar read the same numbers.
  // It loads after the shell is up, so the first page load stays small; its counts come from a
  // read anyway.
  const owner = getOwner();
  let gone = false;
  onCleanup(() => (gone = true));
  const [store, setStore] = createSignal<{ counts: Accessor<FindingCounts | null>; ui: typeof FindingsUi } | null>(null);
  onMount(() => {
    void trackLazyPart(withPacks(["findings"], () => import("./findingsShell"))()).then((ui) => {
      if (!gone) runWithOwner(owner, () => setStore({ counts: ui.useFindingCounts(), ui }));
    });
  });
  const findings = () => store()?.counts() ?? null;

  // Which modules this installation runs decides which areas show (OPS-25).
  onMount(() => void loadModules());
  onCleanup(resetModules);
  // A module change that waits for a restart shows up in the status; read the modules again.
  createEffect(
    on(
      () => status.system()?.warnings.some((w) => w.code === RESTART_WARNING) ?? false,
      () => void loadModules(),
      { defer: true },
    ),
  );

  const doSignOut = async () => {
    setAccount(null);
    await signOut();
    navigate(paths.signIn(), { replace: true });
  };

  // A view owns the selection count; a new page starts without one.
  createEffect(on(() => location.pathname, () => setSelectionStatus(null), { defer: true }));

  useGlobalKeys({
    openPalette: () => setPalette(""),
    openShortcuts: () => setSheet(true),
    cycleTheme,
    navigate: (p) => navigate(p),
    modalOpen: () => palette() !== null || sheet(),
  });

  useCommands(() => [
    ...AREAS.map((a) => ({
      id: `shell.goto.${a.id}`,
      group: "goto" as const,
      icon: a.icon,
      label: () => t(a.label),
      hint: HINTS[a.id],
      keys: ["G", a.chord],
      when: () => areaEnabled(a.id),
      run: () => navigate(a.path),
    })),
    {
      id: "shell.goto.account",
      group: "goto",
      icon: "key",
      label: () => t("shell.account.security"),
      run: () => navigate(paths.account()),
    },
    {
      id: "shell.goto.hosts",
      group: "goto",
      icon: "server",
      label: () => t("shell.command.hosts"),
      when: () => moduleRunning("ipam"),
      run: () => navigate(paths.hosts()),
    },
    {
      id: "shell.goto.addresses",
      group: "goto",
      icon: "ipam",
      label: () => t("shell.command.addresses"),
      when: () => moduleRunning("ipam"),
      run: () => navigate(paths.addresses()),
    },
    {
      id: "shell.goto.vlans",
      group: "goto",
      icon: "link",
      label: () => t("shell.command.vlans"),
      when: () => moduleRunning("ipam"),
      run: () => navigate(paths.vlans()),
    },
    {
      id: "shell.import",
      group: "actions",
      icon: "export",
      label: () => t("shell.command.import"),
      when: () => moduleRunning("ipam"),
      run: () => navigate(paths.imports()),
    },
    {
      id: "shell.goto.updates",
      group: "goto",
      icon: "download",
      label: () => t("shell.command.updates"),
      when: isAdmin,
      run: () => navigate(UPDATES_PATH),
    },
    {
      id: "shell.goto.secrets",
      group: "goto",
      icon: "key",
      label: () => t("shell.command.secrets"),
      when: () => isAdmin() || hasRole("operator"),
      run: () => navigate(SECRETS_PATH),
    },
    {
      id: "shell.whats_new",
      group: "actions",
      icon: "info",
      label: () => t("shell.command.whats_new"),
      run: () => setNotes(true),
    },
    {
      id: "shell.audit_verify",
      group: "actions",
      icon: "audit",
      label: () => t("shell.command.audit_verify"),
      run: () => navigate(paths.audit()),
    },
    ...THEMES.map((theme) => ({
      id: `shell.theme.${theme}`,
      group: "preferences" as const,
      icon: theme === "system" ? ("system" as const) : theme === "light" ? ("sun" as const) : ("moon" as const),
      label: () => t(`shell.command.theme_${theme}`),
      keys: theme === "system" ? ["Shift", "T"] : undefined,
      run: () => setTheme(theme),
    })),
    ...DENSITIES.map((d) => ({
      id: `shell.density.${d}`,
      group: "preferences" as const,
      icon: "density" as const,
      label: () => t(`shell.command.density_${d}`),
      run: () => setDensity(d),
    })),
    {
      id: "shell.emphasis",
      group: "preferences",
      icon: "eye",
      label: () => (emphasizeHost() ? t("shell.command.emphasis_off") : t("shell.command.emphasis_on")),
      run: () => setEmphasizeHost(!emphasizeHost()),
    },
    {
      id: "shell.shortcuts",
      group: "preferences",
      icon: "info",
      label: () => t("shell.command.shortcuts"),
      keys: ["?"],
      run: () => setSheet(true),
    },
    {
      id: "shell.sign_out",
      group: "preferences",
      icon: "user",
      label: () => t("shell.account.sign_out"),
      run: () => void doSignOut(),
    },
  ]);

  return (
    <div class="app">
      <a class="skip-link" href="#main">
        {t("shell.skip_to_content")}
      </a>
      <TopBar
        system={status.system()}
        systemError={status.systemError()}
        onPalette={() => setPalette("")}
        onShortcuts={() => setSheet(true)}
        onAccount={(el) => setAccount((cur) => (cur ? null : el))}
        accountOpen={account() !== null}
      />
      {/* One grid cell for the banners: the security warnings first, then the partition state. */}
      <div class="banners">
        <SecurityBanner />
        <ClusterBanner system={status.system()} />
      </div>
      <Rail counts={findings()} badges={store()?.ui} />
      <main class="main" id="main" tabIndex={-1}>
        <ModuleGate>{props.children}</ModuleGate>
      </main>
      <StatusBar
        jobs={status.jobs()}
        version={status.system()?.version}
        findingsItem={
          <Show when={store()}>
            {(s) => {
              const Item = s().ui.FindingsStatus;
              return <Item counts={findings()} />;
            }}
          </Show>
        }
      />
      <Show when={palette() !== null}>
        <CommandPalette initial={palette() ?? ""} onClose={() => setPalette(null)} />
      </Show>
      <Show when={sheet()}>
        <KeySheet onClose={() => setSheet(false)} />
      </Show>
      <Show when={report()}>
        <BugReportDialog onClose={() => setReport(false)} />
      </Show>
      <WhatsNew open={notes()} onClose={() => setNotes(false)} />
      <Show when={account()}>
        {(anchor) => (
          <AccountMenu
            anchor={anchor()}
            onClose={() => setAccount(null)}
            onShortcuts={() => {
              setAccount(null);
              setSheet(true);
            }}
            onBugReport={() => {
              setAccount(null);
              setReport(true);
            }}
            onSignOut={() => void doSignOut()}
          />
        )}
      </Show>
    </div>
  );
}
