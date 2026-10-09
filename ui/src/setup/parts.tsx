// Small pieces the steps share.
import { For, Show } from "solid-js";
import { errorMessage, fieldErrorMessage, isApiError } from "../api/problem";
import { Notice } from "../components/Notice";
import { useWizard } from "./controller";

/** The reason the server refused the request, on the step it belongs to (an alert). */
export function ProblemNotice(props: { step: number }) {
  const w = useWizard();
  const problem = () => (w.state.problem?.step === props.step ? w.state.problem : null);
  const details = (err: unknown): string[] => {
    if (!isApiError(err)) return [];
    const main = errorMessage(err);
    return Array.from(new Set(err.fieldErrors.map(fieldErrorMessage))).filter((m) => m !== main);
  };
  return (
    <Show when={problem()}>
      {(p) => (
        <div class="wz-problem">
          <Notice kind="bad" role="alert">
            {errorMessage(p().error)}
            <Show when={details(p().error).length > 0}>
              <ul>
                <For each={details(p().error)}>{(m) => <li>{m}</li>}</For>
              </ul>
            </Show>
          </Notice>
        </div>
      )}
    </Show>
  );
}
