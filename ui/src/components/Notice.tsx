import { Show, type JSX } from "solid-js";
import { ApiError, errorMessage } from "../api/problem";
import { Icon, type IconName } from "./Icon";

/** A note inside a page or card: neutral, warning or error, never color alone. */
export function Notice(props: {
  kind?: "info" | "warn" | "bad" | "ok";
  title?: JSX.Element;
  children?: JSX.Element;
  role?: "alert" | "status";
  /** The `data-testid` of the note (ui/README.md). */
  testid?: string;
  /** The problem code of an API error, as `data-code`. */
  code?: string | undefined;
}) {
  const icon = (): IconName => (props.kind === "ok" ? "check" : props.kind === "info" || !props.kind ? "info" : "alert");
  return (
    <div class={`note ${props.kind ?? "info"}`} role={props.role} data-testid={props.testid} data-code={props.code}>
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

/**
 * The translated message of an API or client error, as an alert. It is the test id
 * `error-notice`; an `ApiError` also puts its problem code in `data-code`.
 */
export function ErrorNotice(props: { error: unknown }) {
  return (
    <Show when={props.error}>
      <Notice kind="bad" role="alert" testid="error-notice" code={props.error instanceof ApiError ? props.error.code : undefined}>
        {errorMessage(props.error)}
      </Notice>
    </Show>
  );
}
