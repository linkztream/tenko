// Commands of the command palette (Ctrl+K). The shell registers navigation and
// preferences; a view registers its own actions while it is mounted:
//
//   useCommands(() => [{ id: "ipam.move", group: "actions", icon: "move", keys: ["M"],
//     label: () => t("ipam.command.move"), run: () => openMovePreview() }]);
//
// Every command shows its shortcut, so the palette is where shortcuts are learned.
import { createSignal, onCleanup } from "solid-js";
import type { IconName } from "../components/Icon";

export type CommandGroup = "actions" | "goto" | "preferences";

export interface Command {
  /** Stable id, `<area>.<name>`. */
  id: string;
  group: CommandGroup;
  icon: IconName;
  /** Translated label; a function so it follows a language switch. */
  label: () => string;
  hint?: () => string;
  /** Key caps of the shortcut that runs the same command, for display. */
  keys?: readonly string[];
  /** Extra words that should find this command. */
  keywords?: () => string;
  /** Hidden when this returns false. */
  when?: () => boolean;
  run: () => void;
}

const [registered, setRegistered] = createSignal<readonly Command[]>([]);

/** The commands that apply right now. */
export function activeCommands(): readonly Command[] {
  return registered().filter((c) => c.when?.() ?? true);
}

/** Adds commands; returns the function that removes them again. */
export function registerCommands(list: readonly Command[]): () => void {
  setRegistered((all) => [...all.filter((c) => !list.some((n) => n.id === c.id)), ...list]);
  return () => setRegistered((all) => all.filter((c) => !list.includes(c)));
}

/** Registers commands for the lifetime of the calling component. */
export function useCommands(make: () => readonly Command[]): void {
  onCleanup(registerCommands(make()));
}

/** Case-insensitive match of every word of the query against label, hint and keywords. */
export function matchCommand(command: Command, query: string): boolean {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) return true;
  const hay = `${command.label()} ${command.hint?.() ?? ""} ${command.keywords?.() ?? ""}`.toLowerCase();
  return words.every((w) => hay.includes(w));
}
