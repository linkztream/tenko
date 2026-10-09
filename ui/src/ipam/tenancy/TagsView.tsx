// Tags (/ipam/tags, IPAM-08): every tag with how many live objects carry it, by kind. A tag
// leads to the hosts and addresses that carry it.
import { A } from "@solidjs/router";
import { createMemo, For } from "solid-js";
import { api } from "../../api/client";
import { createLiveQuery } from "../../api/live";
import type { TagCount } from "../../api/types";
import { paths } from "../../app/paths";
import { Count } from "../../grid/cells";
import { DataGrid } from "../../grid/DataGrid";
import type { Column } from "../../grid/types";
import { t } from "../../i18n";
import { IpamNav } from "../IpamNav";
import { kindWord } from "../words";
import "../ipam.css";

export default function TagsView() {
  const live = createLiveQuery<TagCount[]>({
    topics: ["ipam"],
    fetch: async (signal) => {
      const list = await api.get("/api/v1/tags", { signal });
      return { value: list.items as TagCount[], revision: list.revision };
    },
  });
  const rows = createMemo(() => [...(live.value.latest ?? [])].sort((a, b) => b.count - a.count || a.tag.localeCompare(b.tag)));

  const columns: Column<TagCount>[] = [
    { id: "tag", header: () => t("ipam.col.tag"), width: 220, fixed: true, text: (r) => r.tag, render: (r) => <span class="tag">{r.tag}</span> },
    { id: "count", header: () => t("ipam.tags.count"), width: 110, align: "right", render: (r) => <Count value={r.count} /> },
    {
      id: "kinds",
      header: () => t("ipam.tags.by_kind"),
      render: (r) => (
        <For each={Object.entries(r.by_kind).filter(([, n]) => n > 0)}>
          {([kind, n]) => (
            <span class="tag-kind">
              <Count value={n} /> {kindWord(kind, n)}
            </span>
          )}
        </For>
      ),
    },
    {
      id: "links",
      header: () => t("ipam.tags.show"),
      width: 240,
      render: (r) => (
        <>
          <A href={paths.hosts({ q: `tag:${r.tag}` })} tabIndex={-1}>
            {t("ipam.nav.hosts")}
          </A>
          {" · "}
          <A href={paths.addresses({ q: `tag:${r.tag}` })} tabIndex={-1}>
            {t("ipam.nav.addresses")}
          </A>
        </>
      ),
    },
  ];

  return (
    <div class="page list-page" data-testid="page-ipam-tags">
      <IpamNav />
      <div class="page-head">
        <div>
          <h1 tabIndex={-1}>
            {t("ipam.nav.tags")}
            <span class="sub">{t("ipam.tags.sub")}</span>
          </h1>
        </div>
      </div>
      <div class="list-body">
        <DataGrid
          id="tags"
          label={t("ipam.nav.tags")}
          noSelection
          columns={columns}
          rows={rows()}
          rowId={(r) => r.tag}
          rowKey={(r) => r.tag}
          loading={live.value.loading}
          initial={live.value.latest === undefined}
          error={live.value.error}
          onRetry={live.refetch}
          empty={
            <div class="empty">
              <h3>{t("ipam.tags.empty")}</h3>
            </div>
          }
        />
      </div>
    </div>
  );
}
