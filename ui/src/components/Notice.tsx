import { Show, type JSX } from "solid-js";
import { errorMessage } from "../api/problem";
import { Icon, type IconName } from "./Icon";

/** A note inside a page or card: neutral, warning or error, never color alone. */
export function Notice(props: {
  kind?: "info" | "warn" | "bad" | "ok";
  title?: JSX.Element;
  children?: JSX.Element;
  role?: "alert" | "status";
}) {
  const icon = (): IconName => (props.kind === "ok" ? "check" : props.kind === "info" || !props.kind ? "info" : "alert");
  return (
    <div class={`note ${props.kind ?? "info"}`} role={props.role}>
      <Icon name={icon()} size="sm" />
      <div class="grow">
        <Show when={props.title}>
          <strong>{props.title}</strong>{" "}
        </Show>
        {props.children}
      </div>
    </div>
  );
}

/** The translated message of an API or client error, as an alert. */
export function ErrorNotice(props: { error: unknown }) {
  return (
    <Show when={props.error}>
      <Notice kind="bad" role="alert">
        {errorMessage(props.error)}
      </Notice>
    </Show>
  );
}
