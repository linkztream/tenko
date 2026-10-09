// Sites (/ipam/sites, IPAM-04): optionally nested, with the matching Active Directory site.
import { createResource, createSignal, For, Show, untrack } from "solid-js";
import { api } from "../../api/client";
import { fetchAll } from "../../api/paginate";
import type { Site, SiteInput, SitePatch, Tag } from "../../api/types";
import { Icon } from "../../components/Icon";
import { Tags, TimeAgo } from "../../grid/cells";
import type { ListSource } from "../../grid/source";
import type { Column } from "../../grid/types";
import { t } from "../../i18n";
import { TagsInput } from "../fields/CustomFieldsEditor";
import { IpamNav } from "../IpamNav";
import { writeQuery } from "../plan/describe";
import { CollectionPage } from "./CollectionPage";
import { FormDialog, TextField } from "./FormDialog";
import "../ipam.css";

/** The ids of a site and every site below it (a site cannot move under them). */
export function descendants(sites: readonly Site[], id: string): Set<string> {
  const out = new Set([id]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const s of sites) {
      if (s.parent && out.has(s.parent) && !out.has(s.id)) {
        out.add(s.id);
        grew = true;
      }
    }
  }
  return out;
}

/** "Home / Garage": the path of a site through its parents. */
export function sitePath(sites: readonly Site[], site: Site): string {
  const names = [site.name];
  const seen = new Set([site.id]);
  let cur = site.parent ? sites.find((s) => s.id === site.parent) : undefined;
  while (cur && !seen.has(cur.id)) {
    names.unshift(cur.name);
    seen.add(cur.id);
    cur = cur.parent ? sites.find((s) => s.id === cur!.parent) : undefined;
  }
  return names.join(" / ");
}

function SiteForm(props: { site?: Site; sites: Site[]; onDone: () => void; onClose: () => void }) {
  const site = untrack(() => props.site);
  const [name, setName] = createSignal(site?.name ?? "");
  const [parent, setParent] = createSignal(site?.parent ?? "");
  const [adSite, setAdSite] = createSignal(site?.ad_site ?? "");
  const [description, setDescription] = createSignal(site?.meta.description ?? "");
  const [tags, setTags] = createSignal<Tag[]>([...(site?.meta.tags ?? [])]);
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const excluded = () => (site ? descendants(props.sites, site.id) : new Set<string>());

  const validate = () => {
    const e: Record<string, string> = {};
    if (!name().trim()) e.name = t("ipam.tenancy.name_required");
    setErrors(e);
    return Object.keys(e).length === 0;
  };
  const send = (o: { dryRun: boolean; acknowledge: string[] }) => {
    if (!site) {
      const body: SiteInput = {
        name: name().trim(),
        parent: parent() || null,
        ad_site: adSite().trim() || null,
        description: description().trim() || null,
        tags: tags(),
      };
      return api.post("/api/v1/sites", { query: writeQuery(o.dryRun, o.acknowledge), body });
    }
    const patch: SitePatch = {};
    if (name().trim() !== site.name) patch.name = name().trim();
    if ((parent() || null) !== (site.parent ?? null)) patch.parent = parent() || null;
    if ((adSite().trim() || null) !== (site.ad_site ?? null)) patch.ad_site = adSite().trim() || null;
    if ((description().trim() || null) !== (site.meta.description ?? null)) patch.description = description().trim() || null;
    if (JSON.stringify(tags()) !== JSON.stringify(site.meta.tags ?? [])) patch.tags = tags();
    return api.patch("/api/v1/sites/{id}", { path: { id: site.id }, query: writeQuery(o.dryRun, o.acknowledge), body: patch, ifMatch: site.meta.revision });
  };

  return (
    <FormDialog
      title={site ? t("ipam.site.edit_title", { name: site.name }) : t("ipam.site.create_title")}
      submitLabel={site ? t("ipam.tenancy.save") : t("ipam.site.create")}
      testid="dialog-site-form"
      validate={validate}
      send={send}
      doneTitle={() => (site ? t("ipam.tenancy.saved", { name: name() }) : t("ipam.tenancy.created", { name: name() }))}
      onDone={() => props.onDone()}
      onClose={props.onClose}
    >
      <TextField id="name" label={t("ipam.col.name")} value={name()} onInput={setName} error={errors().name} />
      <div class="field">
        <label for="site-parent">{t("ipam.site.parent")}</label>
        <select id="site-parent" class="select" value={parent()} onChange={(e) => setParent(e.currentTarget.value)}>
          <option value="">{t("ipam.tenancy.none")}</option>
          <For each={props.sites.filter((s) => !excluded().has(s.id) && !s.meta.deleted)}>
            {(s) => <option value={s.id}>{sitePath(props.sites, s)}</option>}
          </For>
        </select>
      </div>
      <TextField id="ad_site" label={t("ipam.site.ad_site")} value={adSite()} onInput={setAdSite} help={t("ipam.site.ad_site_help")} />
      <TextField id="description" label={t("ipam.col.description")} value={description()} onInput={setDescription} />
      <TagsInput label={t("ipam.col.tags")} value={tags()} onChange={setTags} />
    </FormDialog>
  );
}

export default function SitesView() {
  const [all, { refetch }] = createResource(() => fetchAll<Site>("/api/v1/sites", { query: { deleted: "include" } }).then((r) => r.items));
  const [creating, setCreating] = createSignal(false);
  const [source, setSource] = createSignal<ListSource<Site>>();
  const sites = () => all() ?? [];
  const reload = () => {
    void refetch();
    source()?.reload();
  };

  const columns: Column<Site>[] = [
    { id: "name", header: () => t("ipam.col.name"), width: 260, sort: "name", fixed: true, text: (s) => sitePath(sites(), s), render: (s) => sitePath(sites(), s) },
    { id: "ad_site", header: () => t("ipam.site.ad_site"), width: 240, render: (s) => s.ad_site ?? "" },
    { id: "description", header: () => t("ipam.col.description"), render: (s) => s.meta.description ?? "" },
    { id: "tags", header: () => t("ipam.col.tags"), width: 160, render: (s) => <Tags tags={s.meta.tags} /> },
    { id: "updated", header: () => t("ipam.col.updated"), width: 130, sort: "updated", hidden: true, render: (s) => <TimeAgo at={s.meta.updated.at} /> },
  ];

  return (
    <div class="page list-page" data-testid="page-ipam-sites">
      <IpamNav />
      <div class="page-head">
        <div>
          <h1 tabIndex={-1}>{t("ipam.nav.sites")}</h1>
        </div>
        <div class="actions">
          <button type="button" class="btn primary" data-testid="site-create" onClick={() => setCreating(true)}>
            <Icon name="plus" />
            {t("ipam.site.create")}
          </button>
        </div>
      </div>
      <CollectionPage<Site>
        id="sites"
        collection="sites"
        kind="site"
        path="/api/v1/sites"
        label={t("ipam.nav.sites")}
        filterLabel={t("ipam.site.filter_label")}
        filterPlaceholder={t("ipam.site.filter_placeholder")}
        defaultSort={{ field: "name", desc: false }}
        columns={columns}
        rowLabel={(s) => s.name}
        sourceRef={(s) => setSource(() => s)}
        edit={(s, close) => (
          <SiteForm
            site={s}
            sites={sites()}
            onDone={() => {
              void refetch();
              close(true);
            }}
            onClose={() => close(false)}
          />
        )}
        empty={
          <div class="empty">
            <h3>{t("ipam.site.empty")}</h3>
          </div>
        }
      />
      <Show when={creating()}>
        <SiteForm
          sites={sites()}
          onClose={() => setCreating(false)}
          onDone={() => {
            setCreating(false);
            reload();
          }}
        />
      </Show>
    </div>
  );
}
