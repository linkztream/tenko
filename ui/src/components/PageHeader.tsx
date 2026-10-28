// The page header, one pattern for every view (design/README.md, "Navigation shell"): the title
// (18 px, 600) with an info button that opens the view's explanation in a popover (principle 9:
// explain once, on demand), one subtitle line of facts (counts, scope, freshness), the primary
// actions on the right and the sub-navigation tabs under it.
import { createSignal, createUniqueId, Show, type JSX } from "solid-js";
import { t } from "../i18n";
import { Icon } from "./Icon";
import { Popover } from "./Popover";
import "./page-header.css";

export function PageHeader(props: {
  title: string;
  /** The view's explanation, behind the info button; no button without it. */
  info?: JSX.Element;
  /** One line of facts under the title. */
  sub?: JSX.Element;
  actions?: JSX.Element;
  /** The sub-navigation, under the header. */
  tabs?: JSX.Element;
  crumbs?: JSX.Element;
}) {
  const id = createUniqueId();
  const [anchor, setAnchor] = createSignal<HTMLElement | null>(null);
  return (
    <>
      <div class="page-head page-header" data-testid="page-header">
        <div class="titles">
          <Show when={props.crumbs}>
            <div class="crumbs">{props.crumbs}</div>
          </Show>
          <div class="title-row">
            <h1 tabIndex={-1}>{props.title}</h1>
            <Show when={props.info}>
              <button
                type="button"
                class="icon-btn info-btn"
                aria-label={t("shell.page.info", { title: props.title })}
                title={t("shell.page.info", { title: props.title })}
                aria-haspopup="dialog"
                aria-expanded={anchor() !== null}
                aria-controls={anchor() ? id : undefined}
                data-testid="page-info"
                onClick={(e) => {
                  const el = e.currentTarget;
                  setAnchor((cur) => (cur ? null : el));
                }}
              >
                <Icon name="info" size="sm" />
              </button>
            </Show>
          </div>
          <Show when={props.sub}>
            <p class="page-sub" data-testid="page-sub">
              {props.sub}
            </p>
          </Show>
        </div>
        <Show when={props.actions}>
          <div class="actions">{props.actions}</div>
        </Show>
      </div>
      {props.tabs}
      <Show when={anchor()}>
        {(el) => (
          <Popover anchor={el()} id={id} label={props.title} onClose={() => setAnchor(null)} testid="page-info-popover" class="page-info">
            <h2 class="popover-title">{props.title}</h2>
            <div class="popover-body">{props.info}</div>
          </Popover>
        )}
      </Show>
    </>
  );
}
