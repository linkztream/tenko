// The global keyboard map (design/README.md, "Keyboard map"): Ctrl+K, ?, G chords and
// Shift+T. Single-key shortcuts never fire while focus is in a text field. Views handle
// their own keys and use isTyping() for the same rule.
import { onCleanup } from "solid-js";
import { AREAS } from "./areas";

/** Whether a key event comes from a place where typing a letter means text. */
export function isTyping(e: KeyboardEvent): boolean {
  const el = e.target as HTMLElement | null;
  if (!el) return false;
  const tag = el.tagName;
  if (tag === "TEXTAREA" || tag === "SELECT" || el.isContentEditable) return true;
  if (tag !== "INPUT") return false;
  const type = (el as HTMLInputElement).type;
  return !["checkbox", "radio", "button", "submit", "reset", "range", "color"].includes(type);
}

export interface GlobalKeyActions {
  openPalette: () => void;
  openShortcuts: () => void;
  cycleTheme: () => void;
  navigate: (path: string) => void;
  /** True while a dialog is open: only Ctrl+K stays live. */
  modalOpen: () => boolean;
}

const CHORD_MS = 900;

/** Installs the global keys for the lifetime of the calling component. */
export function useGlobalKeys(actions: GlobalKeyActions): void {
  let chord = false;
  let chordTimer: ReturnType<typeof setTimeout> | undefined;

  const onKeyDown = (e: KeyboardEvent) => {
    if ((e.ctrlKey || e.metaKey) && !e.altKey && e.key.toLowerCase() === "k") {
      e.preventDefault();
      actions.openPalette();
      return;
    }
    if (e.defaultPrevented || actions.modalOpen() || isTyping(e) || e.ctrlKey || e.metaKey || e.altKey) return;
    if (chord) {
      chord = false;
      clearTimeout(chordTimer);
      const area = AREAS.find((a) => a.chord.toLowerCase() === e.key.toLowerCase());
      if (area) {
        e.preventDefault();
        actions.navigate(area.path);
      }
      return;
    }
    if (e.key === "?") {
      e.preventDefault();
      actions.openShortcuts();
    } else if (e.key === "T" && e.shiftKey) {
      e.preventDefault();
      actions.cycleTheme();
    } else if (e.key === "g" && !e.shiftKey) {
      chord = true;
      chordTimer = setTimeout(() => (chord = false), CHORD_MS);
    }
  };

  document.addEventListener("keydown", onKeyDown);
  onCleanup(() => {
    clearTimeout(chordTimer);
    document.removeEventListener("keydown", onKeyDown);
  });
}
