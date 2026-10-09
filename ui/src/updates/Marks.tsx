// The marks of a release: it fixes security issues, it needs an action. Each is an icon and
// a word together, never color alone.
import { Show } from "solid-js";
import { Icon } from "../components/Icon";
import "./marks.css";

export function Marks(props: { security?: boolean | undefined; action?: boolean | undefined; securityLabel: string; actionLabel: string }) {
  return (
    <Show when={props.security || props.action}>
      <span class="upd-marks">
        <Show when={props.security}>
          <span class="upd-mark security" data-testid="update-mark" data-key="security">
            <Icon name="shield" size="xs" />
            {props.securityLabel}
          </span>
        </Show>
        <Show when={props.action}>
          <span class="upd-mark action" data-testid="update-mark" data-key="action">
            <Icon name="alert" size="xs" />
            {props.actionLabel}
          </span>
        </Show>
      </span>
    </Show>
  );
}
