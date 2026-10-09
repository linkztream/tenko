import { For } from "solid-js";
import { Dialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { Kbd } from "../components/Kbd";
import { t, type MessageKey } from "../i18n";
import { AREAS } from "./areas";

interface Row {
  label: () => string;
  keys: readonly string[];
}

const row = (key: MessageKey, keys: readonly string[]): Row => ({ label: () => t(key), keys });

/** The keyboard map of design/README.md. */
function sections(): { title: MessageKey; rows: Row[] }[] {
  return [
    {
      title: "shell.keys.section.anywhere",
      rows: [
        row("shell.keys.palette", ["Ctrl", "K"]),
        row("shell.keys.title", ["?"]),
        ...AREAS.map((a) => ({ label: () => t("shell.keys.goto", { area: t(a.label) }), keys: ["G", a.chord] })),
        row("shell.keys.theme", ["Shift", "T"]),
      ],
    },
    {
      title: "shell.keys.section.grids",
      rows: [
        row("shell.keys.move_focus", ["↑", "↓", "←", "→"]),
        row("shell.keys.move_focus_alt", ["J", "K"]),
        row("shell.keys.select_row", ["Space"]),
        row("shell.keys.extend", ["Shift", "↑↓"]),
        row("shell.keys.select_all", ["Ctrl", "A"]),
        row("shell.keys.edit", ["Enter"]),
        row("shell.keys.cancel", ["Esc"]),
        row("shell.keys.filter", ["/"]),
        row("shell.keys.details", ["."]),
        row("shell.keys.full_page", ["Shift", "Enter"]),
      ],
    },
    {
      title: "shell.keys.section.changes",
      rows: [
        row("shell.keys.move", ["M"]),
        row("shell.keys.mode", ["Shift", "M"]),
        row("shell.keys.lock", ["L"]),
        row("shell.keys.claim", ["N"]),
        row("shell.keys.undo", ["Ctrl", "Z"]),
        row("shell.keys.job_panel", ["Shift", "J"]),
        row("shell.keys.export", ["Ctrl", "Shift", "E"]),
      ],
    },
    {
      title: "shell.keys.section.tree",
      rows: [
        row("shell.keys.focus_tree", ["["]),
        row("shell.keys.focus_grid", ["]"]),
        row("shell.keys.expand", ["→", "←"]),
        row("shell.keys.close_panel", ["Esc"]),
      ],
    },
  ];
}

/** The keyboard shortcuts sheet, opened with `?`. */
export function KeySheet(props: { onClose: () => void }) {
  return (
    <Dialog label={t("shell.keys.title")} onClose={props.onClose} class="sheet">
      <h2>
        {t("shell.keys.title")}
        <button type="button" class="icon-btn" aria-label={t("common.action.close")} onClick={() => props.onClose()}>
          <Icon name="x" />
        </button>
      </h2>
      <div class="cols">
        <For each={sections()}>
          {(section) => (
            <section>
              <h3>{t(section.title)}</h3>
              <dl>
                <For each={section.rows}>
                  {(r) => (
                    <>
                      <dt>{r.label()}</dt>
                      <dd>
                        <Kbd keys={r.keys} />
                      </dd>
                    </>
                  )}
                </For>
              </dl>
            </section>
          )}
        </For>
      </div>
      <p class="muted sheet-note">{t("shell.keys.note")}</p>
    </Dialog>
  );
}
