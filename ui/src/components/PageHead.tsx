import { Show, type JSX } from "solid-js";

/** The head of a page in the shell: title, an optional subtitle and actions on the right. */
export function PageHead(props: { title: JSX.Element; sub?: JSX.Element; actions?: JSX.Element; crumbs?: JSX.Element }) {
  return (
    <div class="page-head">
      <div>
        <Show when={props.crumbs}>
          <div class="crumbs">{props.crumbs}</div>
        </Show>
        <h1 tabIndex={-1}>
          {props.title}
          <Show when={props.sub}>
            <span class="sub">{props.sub}</span>
          </Show>
        </h1>
      </div>
      <Show when={props.actions}>
        <div class="actions">{props.actions}</div>
      </Show>
    </div>
  );
}
