// The reviewable part of a plan (API-09): what changes per kind, every change with its
// field diffs, and the warnings; a warning that blocks the apply has its own acknowledge
// check box (design/README.md, "Preview before apply").
import { For, Show } from "solid-js";
import type { PlanView, PlanWarning } from "../../api/types";
import { Notice } from "../../components/Notice";
import { locale, t } from "../../i18n";
import { actionWord, kindTitle, kindWord } from "../words";
import { changeLabel, warningText } from "./describe";

function capitalize(text: string): string {
  return text.charAt(0).toLocaleUpperCase(locale()) + text.slice(1);
}

export function PlanPreview(props: {
  plan: PlanView | null | undefined;
  warnings: readonly PlanWarning[];
  acknowledged: ReadonlySet<string>;
  onAcknowledge: (code: string, on: boolean) => void;
}) {
  const changes = () => props.plan?.changes ?? [];
  const blocking = () => props.warnings.filter((w) => w.requires_ack && !w.acknowledged);
  const plain = () => props.warnings.filter((w) => !(w.requires_ack && !w.acknowledged));

  return (
    <section class="plan" data-testid="plan-preview" aria-label={t("ipam.plan.heading")}>
      <Show when={props.plan?.summary.counts.length} fallback={<p class="muted">{t("ipam.plan.nothing")}</p>}>
        <ul class="plan-summary" data-testid="plan-summary">
          <For each={props.plan?.summary.counts ?? []}>
            {(c) => (
              <li>
                {t("ipam.plan.summary_line", {
                  kind: capitalize(kindWord(c.kind, c.count)),
                  action: actionWord(c.action, c.count),
                })}
              </li>
            )}
          </For>
        </ul>
      </Show>
      <Show when={blocking().length > 0}>
        <div class="plan-warnings" data-testid="plan-blocking">
          <For each={blocking()}>
            {(w) => (
              <Notice kind="warn">
                <p>{warningText(w)}</p>
                <label class="ackrow">
                  <input
                    type="checkbox"
                    class="cb"
                    checked={props.acknowledged.has(w.code)}
                    data-testid="plan-ack"
                    data-code={w.code}
                    onChange={(e) => props.onAcknowledge(w.code, e.currentTarget.checked)}
                  />
                  {t("ipam.plan.ack")}
                </label>
              </Notice>
            )}
          </For>
        </div>
      </Show>
      <Show when={plain().length > 0}>
        <div class="plan-warnings" data-testid="plan-warnings">
          <For each={plain()}>{(w) => <Notice kind="info">{warningText(w)}</Notice>}</For>
        </div>
      </Show>
      <Show when={changes().length > 0}>
        <div class="table-wrap plan-changes">
          <table class="plain" aria-label={t("ipam.plan.changes")}>
            <thead>
              <tr>
                <th scope="col">{t("ipam.plan.col.action")}</th>
                <th scope="col">{t("ipam.plan.col.object")}</th>
                <th scope="col">{t("ipam.plan.col.fields")}</th>
              </tr>
            </thead>
            <tbody>
              <For each={changes()}>
                {(c) => (
                  <tr data-testid="plan-change" data-kind={c.object.kind} data-action={c.action}>
                    <td>
                      <span class={`plan-action ${c.action}`}>{t(`ipam.plan.change.${c.action}`)}</span>
                      <Show when={c.derived}>
                        {" "}
                        <span class="tag">{t("ipam.plan.derived")}</span>
                      </Show>
                    </td>
                    <td>
                      <span class="muted">{kindTitle(c.object.kind)}</span> <span class="mono">{changeLabel(c)}</span>
                    </td>
                    <td class="plan-fields">
                      <For each={c.fields ?? []}>
                        {(f) => (
                          <div>
                            <span class="muted">{f.field}</span> <del class="mono">{f.old ?? "–"}</del>
                            {" → "}
                            <ins class="mono">{f.new ?? "–"}</ins>
                          </div>
                        )}
                      </For>
                    </td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </div>
      </Show>
    </section>
  );
}
