// The empty state (design/README.md, component inventory, decision 20): a feature that is not
// set up shows one sentence of what is missing and one action that fixes it, on a quiet
// --surface-2 fill and never dashed (dashed means "not yet intent"). It stands where the
// feature's figures would be, instead of a row of zeros.
import { A } from "@solidjs/router";
import { Show } from "solid-js";
import "./empty-state.css";

export function EmptyState(props: {
  /** What is missing, as one sentence. */
  text: string;
  /** The action that fixes it, as a link. */
  action?: { label: string; href: string; testid?: string };
  testid?: string;
}) {
  return (
    <div class="empty-state" data-testid={props.testid}>
      <p>{props.text}</p>
      <Show when={props.action}>
        {(action) => (
          <A class="btn sm" href={action().href} data-testid={action().testid}>
            {action().label}
          </A>
        )}
      </Show>
    </div>
  );
}
