import { useLocation, useNavigate } from "@solidjs/router";
import { createEffect, createSignal, on, Show, type JSX } from "solid-js";
import { DENSITIES, setDensity, setEmphasizeHost, setTheme, cycleTheme, emphasizeHost, THEMES } from "../app/prefs";
import { paths } from "../app/paths";
import { signOut } from "../auth/session";
import { t } from "../i18n";
import { AccountMenu } from "./AccountMenu";
import { AREAS } from "./areas";
import { CommandPalette } from "./CommandPalette";
import { useCommands } from "./commands";
import { useGlobalKeys } from "./keyboard";
import { KeySheet } from "./KeySheet";
import { Rail } from "./Rail";
import { SecurityBanner } from "./SecurityBanner";
import { createShellStatus, setSelectionStatus } from "./status";
import { StatusBar } from "./StatusBar";
import { TopBar } from "./TopBar";

const HINTS: Partial<Record<string, () => string>> = {
  dashboard: () => t("shell.command.dashboard_hint"),
};

/** The application frame: top bar, banner, rail, main area and status bar. */
export function Shell(props: { children?: JSX.Element }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [palette, setPalette] = createSignal<string | null>(null);
  const [sheet, setSheet] = createSignal(false);
  const [account, setAccount] = createSignal<HTMLElement | null>(null);
  const status = createShellStatus();

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
      run: () => navigate(a.path),
    })),
    {
      id: "shell.goto.account",
      group: "goto",
      icon: "key",
      label: () => t("shell.account.security"),
      run: () => navigate(paths.account()),
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

  const activeJobs = () => {
    const j = status.jobs();
    return j ? j.running + j.waiting : 0;
  };

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
      <SecurityBanner />
      <Rail activeJobs={activeJobs()} />
      <main class="main" id="main" tabIndex={-1}>
        {props.children}
      </main>
      <StatusBar jobs={status.jobs()} version={status.system()?.version} />
      <Show when={palette() !== null}>
        <CommandPalette initial={palette() ?? ""} onClose={() => setPalette(null)} />
      </Show>
      <Show when={sheet()}>
        <KeySheet onClose={() => setSheet(false)} />
      </Show>
      <Show when={account()}>
        {(anchor) => (
          <AccountMenu
            anchor={anchor()}
            onClose={() => setAccount(null)}
            onShortcuts={() => {
              setAccount(null);
              setSheet(true);
            }}
            onSignOut={() => void doSignOut()}
          />
        )}
      </Show>
    </div>
  );
}
