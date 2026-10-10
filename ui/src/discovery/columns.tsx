// Columns of the proposal inbox. Severity, kind and state carry a glyph and a word, so color is
// never the only cue (design/README.md, "Color is for exceptions"); the sortable columns sort
// on the server (`sort` of GET /proposals).
import { For, Show } from "solid-js";
import { Addr, Mac } from "../components/Addr";
import { Icon } from "../components/Icon";
import { TimeAgo } from "../grid/cells";
import type { Column } from "../grid/types";
import { t } from "../i18n";
import type { Proposal, ProposalEvidence } from "./api";
import { kindClass, kindIcon, kindWord, lastSeenOf, ruleText, severityIcon, severityWord, sourceText, stateWord, type SourceNames } from "./model";
import { PrefixRef } from "./refs";

export function SeverityBadge(props: { severity: Proposal["severity"] }) {
  return (
    <span class={`sev ${props.severity}`} data-severity={props.severity}>
      <Icon name={severityIcon(props.severity)} size="xs" />
      {severityWord(props.severity)}
    </span>
  );
}

export function KindBadge(props: { kind: Proposal["kind"] }) {
  return (
    <span class={`flag ${kindClass(props.kind)}`} data-kind={props.kind}>
      <Icon name={kindIcon(props.kind)} size="sm" />
      {kindWord(props.kind)}
    </span>
  );
}

export function StateBadge(props: { state: Proposal["state"] }) {
  return (
    <span class={`tag proposal-state ${props.state}`} data-state={props.state}>
      {stateWord(props.state)}
    </span>
  );
}

/** What a proposal is about: MAC, address or network, and the name a source gives it. */
export function SubjectCell(props: { proposal: Proposal }) {
  const s = () => props.proposal.subject;
  return (
    <span class="subject-cell">
      <Show when={s().mac}>{(mac) => <Mac value={mac()} />}</Show>
      <Show when={s().ip}>{(ip) => <Addr value={ip()} />}</Show>
      <Show when={!s().ip && s().cidr}>{(cidr) => <Addr value={cidr() as string} />}</Show>
      <Show when={s().name}>{(name) => <span class="muted">{name()}</span>}</Show>
    </span>
  );
}

/** One badge per source of the evidence, with the full source in the tooltip. */
export function SourceBadges(props: { evidence: readonly ProposalEvidence[]; names: SourceNames }) {
  const distinct = () => {
    const seen = new Map<string, ProposalEvidence>();
    for (const e of props.evidence) if (!seen.has(e.source_key)) seen.set(e.source_key, e);
    return [...seen.values()];
  };
  return (
    <Show when={distinct().length > 0} fallback={<span class="muted">–</span>}>
      <span class="srcs">
        <For each={distinct()}>
          {(e) => (
            <span class="src" title={sourceText(e.source, props.names)} data-source={e.source_key}>
              {t(`discovery.source_short.${e.source.type}`)}
            </span>
          )}
        </For>
      </span>
    </Show>
  );
}

export function proposalColumns(names: () => SourceNames): Column<Proposal>[] {
  return [
    {
      id: "severity",
      header: () => t("discovery.col.severity"),
      width: 100,
      sort: "severity",
      text: (p) => severityWord(p.severity),
      render: (p) => <SeverityBadge severity={p.severity} />,
    },
    {
      id: "kind",
      header: () => t("discovery.col.kind"),
      width: 180,
      sort: "kind",
      text: (p) => kindWord(p.kind),
      render: (p) => <KindBadge kind={p.kind} />,
    },
    {
      id: "summary",
      header: () => t("discovery.col.summary"),
      width: 320,
      fixed: true,
      text: (p) => ruleText(p),
      render: (p) => (
        <span class="proposal-summary" title={ruleText(p)}>
          {ruleText(p)}
        </span>
      ),
    },
    {
      id: "subject",
      header: () => t("discovery.col.subject"),
      width: 240,
      text: (p) => [p.subject.mac, p.subject.ip ?? p.subject.cidr, p.subject.name].filter(Boolean).join(" "),
      render: (p) => <SubjectCell proposal={p} />,
    },
    {
      id: "prefix",
      header: () => t("discovery.col.prefix"),
      width: 140,
      render: (p) => (
        <Show when={p.subject.prefix} fallback={<span class="muted">–</span>}>
          {(id) => <PrefixRef id={id()} />}
        </Show>
      ),
    },
    {
      id: "sources",
      header: () => t("discovery.col.sources"),
      width: 150,
      render: (p) => <SourceBadges evidence={p.evidence} names={names()} />,
    },
    {
      id: "last_seen",
      header: () => t("discovery.col.last_seen"),
      width: 100,
      sort: "last_seen",
      render: (p) => <TimeAgo at={lastSeenOf(p)} />,
    },
    {
      id: "created",
      header: () => t("discovery.col.created"),
      width: 100,
      sort: "created",
      hidden: true,
      render: (p) => <TimeAgo at={p.created} />,
    },
    {
      id: "state",
      header: () => t("discovery.col.state"),
      width: 100,
      sort: "state",
      text: (p) => stateWord(p.state),
      render: (p) => <StateBadge state={p.state} />,
    },
    {
      id: "updated",
      header: () => t("discovery.col.updated"),
      width: 110,
      sort: "updated",
      hidden: true,
      render: (p) => <TimeAgo at={p.updated} />,
    },
  ];
}
