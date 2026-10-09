// The selection action bar (design.css `.actionbar`): it appears while rows are selected
// and offers the bulk actions of the view, each with its key.
import { Show, type JSX } from "solid-js";
import { Icon } from "../components/Icon";
import { Kbd } from "../components/Kbd";
import { t } from "../i18n";

export function ActionBar(props: { count: number; onClear: () => void; children: JSX.Element; testid?: string }) {
  return (
    <Show when={props.count > 0}>
      <div class="actionbar" role="toolbar" aria-label={t("grid.actionbar.label")} data-testid={props.testid ?? "actionbar"}>
        <span class="count">
          <span class="n">{props.count}</span>
          {t("grid.actionbar.selected", { count: props.count })}
        </span>
        {props.children}
        <span class="sep" />
        <button
          type="button"
          class="icon-btn"
          aria-label={t("grid.selection.clear")}
          title={t("grid.selection.clear")}
          onClick={() => props.onClear()}
        >
          <Icon name="x" />
        </button>
      </div>
    </Show>
  );
}

/** A button of the action bar with its icon and key caps. */
export function ActionButton(props: {
  label: string;
  icon?: Parameters<typeof Icon>[0]["name"];
  keys?: readonly string[];
  primary?: boolean;
  disabled?: boolean;
  onClick: () => void;
  testid?: string;
}) {
  return (
    <button
      type="button"
      class={props.primary ? "btn sm primary" : "btn sm ghost"}
      disabled={props.disabled}
      data-testid={props.testid}
      onClick={() => props.onClick()}
    >
      <Show when={props.icon}>
        <Icon name={props.icon!} size="sm" />
      </Show>
      {props.label}
      <Show when={props.keys}>
        <Kbd keys={props.keys ?? []} />
      </Show>
    </button>
  );
}
