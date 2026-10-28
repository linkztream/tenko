// The needs-attention strip of the start page (U3, ui-plan section 5.1): the findings to act on,
// one row each (the glyph of the kind, the kind in a word, the subject, one line of evidence, since
// when, and the default action), the most urgent first as the index orders them; below them one
// line for the findings to review, counted per area, with its link to the list. When nothing is to
// act on the strip is one "All clear" line, never two empty cards. The counts come from the one
// findings store of the shell (U2), so the strip, the rail and the status bar never disagree; the
// rows are read from `GET /findings?severity=act` and follow the `findings` topic.
//
// Test ids: `dashboard-attention` (`data-state` attention or clear), `dashboard-finding` per row
// (`data-id`, `data-kind`), `dashboard-finding-action`, `dashboard-findings-more`, `dashboard-clear`,
// `dashboard-proposals` (the review line, `data-count`) with `dashboard-proposals-link`.
import { A } from "@solidjs/router";
import { For, Show } from "solid-js";
import { api } from "../api/client";
import { createLiveQuery } from "../api/live";
import { paths } from "../app/paths";
import { Icon } from "../components/Icon";
import { TimeAgo } from "../grid/cells";
import { formatList, t } from "../i18n";
import type { FindingArea, FindingCounts } from "../shell/findings";
import { findingAction, findingEvidence, findingGlyph, findingKindWord, findingSubject, type Finding } from "./findingWords";

/** Rows the strip shows; the rest are one link to the list. */
const ROWS = 5;

/** The areas in the order of the rail, for the words of the review line. */
const AREAS: readonly FindingArea[] = ["ipam", "dns", "dhcp", "discovery", "topology", "jobs", "connectors", "nodes", "settings"];

export function Attention(props: { counts: FindingCounts | null }) {
  const act = createLiveQuery<Finding[]>({
    topics: ["findings"],
    debounceMs: 300,
    fetch: async (signal) => {
      try {
        const page = await api.get("/api/v1/findings", { query: { severity: "act", limit: 50 }, signal });
        return { value: page.items };
      } catch {
        // An account that may not read the findings, or a server without the index: no rows.
        return { value: [] };
      }
    },
  });
  const rows = () => act.latest() ?? [];
  const actCount = () => Math.max(props.counts?.total.act ?? 0, rows().length);
  const review = () => props.counts?.total.review ?? 0;
  const reviewAreas = () =>
    formatList(
      AREAS.filter((area) => (props.counts?.areas[area].review ?? 0) > 0).map((area) =>
        t("dashboard.attention.review_in", { count: props.counts!.areas[area].review, area: t(`shell.nav.${area}`) }),
      ),
    );
  const loaded = () => act.latest() !== undefined;

  return (
    <section
      class="attention"
      aria-label={t("dashboard.attention.label")}
      data-testid="dashboard-attention"
      data-state={!loaded() ? undefined : actCount() > 0 ? "attention" : "clear"}
    >
      <Show
        when={actCount() > 0}
        fallback={
          <Show when={loaded()}>
            <div class="attention-row clear" data-testid="dashboard-clear">
              <Icon name="check" size="sm" class="ok-glyph" />
              <strong class="ok-word">{t("dashboard.attention.clear")}</strong>
              <span class="attention-text">{t("dashboard.attention.clear_text")}</span>
            </div>
          </Show>
        }
      >
        <For each={rows().slice(0, ROWS)}>
          {(finding) => {
            const subject = () => findingSubject(finding);
            const evidence = () => findingEvidence(finding);
            const action = () => findingAction(finding);
            return (
              <div class="attention-row act" data-testid="dashboard-finding" data-id={finding.id} data-kind={finding.kind}>
                <Icon name={findingGlyph(finding.kind)} size="sm" class="act-glyph" />
                <strong class="act-word">{findingKindWord(finding.kind)}</strong>
                <Show when={subject()}>{(s) => <span classList={{ "attention-subject": true, mono: s().mono }}>{s().text}</span>}</Show>
                <span classList={{ "attention-evidence": true, mono: evidence().mono }}>{evidence().text}</span>
                <span class="attention-since">
                  <TimeAgo at={finding.since} />
                </span>
                <Show when={action()}>
                  {(a) => (
                    <A class="btn sm act-action" href={a().href} data-testid="dashboard-finding-action">
                      {a().label}
                    </A>
                  )}
                </Show>
              </div>
            );
          }}
        </For>
        <Show when={actCount() > Math.min(ROWS, rows().length)}>
          <div class="attention-row more">
            <A href={paths.discovery({ severity: "act" })} data-testid="dashboard-findings-more">
              {t("dashboard.attention.more", { count: actCount() - Math.min(ROWS, rows().length) })}
            </A>
          </div>
        </Show>
      </Show>
      <Show when={review() > 0}>
        <div class="attention-row review" data-testid="dashboard-proposals" data-count={review()}>
          <Icon name="proposal" size="sm" class="review-glyph" />
          <strong class="review-word">{t("dashboard.attention.review", { count: review() })}</strong>
          <span class="attention-text">{reviewAreas()}</span>
          <A class="attention-link" href={paths.discovery({ severity: "review" })} data-testid="dashboard-proposals-link">
            {t("dashboard.attention.review_link")}
          </A>
        </div>
      </Show>
    </section>
  );
}
