// The facts behind a subject, one row per source and subject (docs/reconciliation.md, section
// 2.2): what the source reported, its first and last sighting, the counted sightings, and
// whether the fact is still current. Used by the subject page and the host page.
import { A } from "@solidjs/router";
import { For, Show } from "solid-js";
import { paths } from "../app/paths";
import { TimeAgo } from "../grid/cells";
import { formatNumber, t } from "../i18n";
import type { ObservedFact } from "./api";
import { factTypeWord, isCurrent, lookupSubject, observedText, sourceText, type SourceNames } from "./model";

export function FactState(props: { fact: ObservedFact }) {
  const current = () => isCurrent(props.fact);
  return (
    <span class={`tag fact-state ${current() ? "current" : "expired"}`} data-state={current() ? "current" : "expired"}>
      {current() ? t("discovery.fact.current") : t("discovery.fact.expired")}
    </span>
  );
}

export function FactTable(props: {
  facts: readonly ObservedFact[];
  names: SourceNames;
  /** Link each fact to the picture of its subject (off on the subject page itself). */
  links?: boolean;
  label: string;
}) {
  return (
    <div class="table-wrap">
      <table class="plain fact-table" aria-label={props.label}>
        <thead>
          <tr>
            <th scope="col">{t("discovery.col.source")}</th>
            <th scope="col">{t("discovery.col.type")}</th>
            <th scope="col">{t("discovery.col.observed")}</th>
            <th scope="col">{t("discovery.col.first_seen")}</th>
            <th scope="col">{t("discovery.col.last_seen")}</th>
            <th scope="col" class="r">
              {t("discovery.col.sightings")}
            </th>
            <th scope="col">{t("discovery.col.state")}</th>
          </tr>
        </thead>
        <tbody>
          <For each={props.facts}>
            {(fact) => (
              <tr data-testid="fact" data-key={`${fact.source_key}|${fact.subject_key}`} data-state={isCurrent(fact) ? "current" : "expired"}>
                <td>{sourceText(fact.source, props.names)}</td>
                <td>{factTypeWord(fact.observed.type)}</td>
                <td class="fact-observed mono">
                  <Show when={props.links && lookupSubject(fact)} fallback={observedText(fact.observed)}>
                    {(subject) => <A href={paths.observation(subject())}>{observedText(fact.observed)}</A>}
                  </Show>
                </td>
                <td>
                  <TimeAgo at={fact.first_seen} />
                </td>
                <td>
                  <TimeAgo at={fact.last_seen} />
                </td>
                <td class="r num">{formatNumber(fact.sightings ?? 1)}</td>
                <td>
                  <FactState fact={fact} />
                </td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
    </div>
  );
}
