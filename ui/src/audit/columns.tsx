// Columns of the audit log grid: sequence number, time, principal, action, objects,
// outcome and source address. Rows are immutable records, so no column sorts; the order
// of the list is a filter (newest or oldest first).
import { A } from "@solidjs/router";
import type { AuditRecord } from "../api/types";
import { paths } from "../app/paths";
import { PrincipalLabel, principalText } from "../components/Principal";
import type { Column } from "../grid/types";
import { formatDateTime, formatRelative, t } from "../i18n";
import { AuditAction } from "./actionLabel";
import { Maybe, ObjectList, OutcomeBadge } from "./cells";
import { kindWord } from "./model";
import { objectViews } from "./objects";

/** The time of a record to the second, in the language of the UI. */
export function recordTime(at: string): string {
  return formatDateTime(at, { dateStyle: "medium", timeStyle: "medium" });
}

export function auditColumns(): Column<AuditRecord>[] {
  return [
    {
      id: "seq",
      header: () => t("audit.col.seq"),
      width: 72,
      align: "right",
      fixed: true,
      class: "num",
      text: (r) => String(r.seq),
      render: (r) => (
        <A class="mono seq-link" href={paths.auditRecord(r.seq)} tabIndex={-1}>
          {r.seq}
        </A>
      ),
    },
    {
      id: "time",
      header: () => t("audit.col.time"),
      width: 184,
      text: (r) => recordTime(r.at),
      render: (r) => (
        <time datetime={r.at} title={formatRelative(r.at)}>
          {recordTime(r.at)}
        </time>
      ),
    },
    {
      id: "principal",
      header: () => t("audit.col.principal"),
      width: 170,
      text: (r) => principalText(r.principal),
      render: (r) => <PrincipalLabel principal={r.principal} />,
    },
    {
      id: "action",
      header: () => t("audit.col.action"),
      width: 380,
      text: (r) => r.draft.action,
      render: (r) => <AuditAction draft={r.draft} />,
    },
    {
      id: "objects",
      header: () => t("audit.col.objects"),
      width: 240,
      text: (r) => objectViews(r).map((o) => `${kindWord(o.ref.kind)} ${o.text}`).join(", "),
      render: (r) => <ObjectList record={r} />,
    },
    {
      id: "outcome",
      header: () => t("audit.col.outcome"),
      width: 200,
      text: (r) => r.draft.outcome.kind,
      render: (r) => <OutcomeBadge record={r} />,
    },
    {
      id: "source",
      header: () => t("audit.col.source"),
      width: 120,
      text: (r) => r.draft.source_ip ?? "",
      render: (r) => <Maybe value={r.draft.source_ip} mono />,
    },
  ];
}
