// Columns of the findings list (Discovery, U4). Every cell is one line of a 28 px row: the glyph of
// the kind with its word (the glyph keeps its domain color; the severity groups the rows), the
// subject as a link in the data font where it is an identifier, one line of evidence, the source
// (hidden by default), since when, and the default action as a button. Kind and source say their
// value once in the header when every row shares it (the majority rule of the grid).
import { A } from "@solidjs/router";
import { Show } from "solid-js";
import { Icon } from "../components/Icon";
import { TimeAgo } from "../grid/cells";
import type { Column } from "../grid/types";
import { t } from "../i18n";
import { FindingAction } from "./FindingAction";
import { evidenceOf, kindGlyph, kindWord, subjectOf, type Finding } from "./findings";

/** The glyph and the word of a finding's kind. */
export function FindingKindCell(props: { finding: Finding }) {
  const glyph = () => kindGlyph(props.finding.kind, props.finding.severity);
  return (
    <span class="finding-kind" data-kind={props.finding.kind} data-level={props.finding.severity}>
      <span class={`fglyph ${glyph().tone}`}>
        <Icon name={glyph().icon} size="sm" />
      </span>
      <span class="word">{kindWord(props.finding.kind)}</span>
    </span>
  );
}

/** What a finding is about, as a link where it has a page. */
export function FindingSubjectCell(props: { finding: Finding }) {
  const subject = () => subjectOf(props.finding);
  return (
    <Show when={subject()} fallback={<span class="muted">–</span>}>
      {(s) => (
        <span class="finding-subject" classList={{ mono: s().mono }} title={s().text}>
          <Show when={s().href} fallback={s().text}>
            {(href) => (
              <A href={href()} data-testid="finding-subject">
                {s().text}
              </A>
            )}
          </Show>
        </span>
      )}
    </Show>
  );
}

export function sourceWord(source: Finding["source"]): string {
  return t(`discovery.findings.source.${source}`);
}

export function findingColumns(actions: { onPanel: (finding: Finding) => void; onDone: () => void }): Column<Finding>[] {
  return [
    {
      id: "kind",
      header: () => t("discovery.findings.col.kind"),
      width: 200,
      fixed: true,
      text: (f) => kindWord(f.kind),
      majority: (f) => kindWord(f.kind),
      render: (f) => <FindingKindCell finding={f} />,
    },
    {
      id: "subject",
      header: () => t("discovery.findings.col.subject"),
      width: 220,
      text: (f) => subjectOf(f)?.text ?? "",
      render: (f) => <FindingSubjectCell finding={f} />,
    },
    {
      id: "evidence",
      header: () => t("discovery.findings.col.evidence"),
      text: (f) => evidenceOf(f).text,
      render: (f) => {
        const e = evidenceOf(f);
        return (
          <span class="finding-evidence" classList={{ mono: e.mono }} title={e.text} data-testid="finding-evidence">
            {e.text}
          </span>
        );
      },
    },
    {
      id: "source",
      header: () => t("discovery.findings.col.source"),
      width: 120,
      hidden: true,
      text: (f) => sourceWord(f.source),
      majority: (f) => sourceWord(f.source),
      render: (f) => <span class="muted">{sourceWord(f.source)}</span>,
    },
    {
      id: "since",
      header: () => t("discovery.findings.col.since"),
      width: 140,
      render: (f) => <TimeAgo at={f.since} />,
    },
    {
      id: "action",
      header: () => t("discovery.findings.col.action"),
      width: 160,
      render: (f) => <FindingAction finding={f} onPanel={actions.onPanel} onDone={actions.onDone} />,
    },
  ];
}
