// VLANs (/ipam/vlans, IPAM-03): id, name, site, status and VXLAN network identifier, each with
// its color from the generated palette (decision 11) and the id as the redundant cue.
import { createMemo, createResource, createSignal, For, Show, untrack } from "solid-js";
import { api } from "../../api/client";
import { fetchAll } from "../../api/paginate";
import type { Site, Status, Tag, Vlan, VlanInput, VlanPatch } from "../../api/types";
import { STATUSES } from "../../api/types";
import { may, writesAll } from "../../auth/gate";
import { Icon } from "../../components/Icon";
import { StatusBadge, Tags, TimeAgo } from "../../grid/cells";
import type { ListSource } from "../../grid/source";
import type { Column, RowAction } from "../../grid/types";
import { t } from "../../i18n";
import { TagsInput } from "../fields/CustomFieldsEditor";
import { IpamNav } from "../IpamNav";
import { writeQuery } from "../plan/describe";
import { createVlanStyles } from "../vlan/palette";
import { PrefixesDialog } from "../vlan/PrefixesDialog";
import { ProvisionDialog } from "../vlan/ProvisionDialog";
import { VlanChip } from "../vlan/VlanChip";
import { statusWord } from "../words";
import { CollectionPage } from "./CollectionPage";
import { FormDialog, TextField } from "./FormDialog";
import "../ipam.css";

function VlanForm(props: { vlan?: Vlan; sites: Site[]; onDone: () => void; onClose: () => void }) {
  const vlan = untrack(() => props.vlan);
  const [vid, setVid] = createSignal(vlan ? String(vlan.vid) : "");
  const [name, setName] = createSignal(vlan?.name ?? "");
  const [site, setSite] = createSignal(vlan?.site ?? "");
  const [status, setStatus] = createSignal<Status>(vlan?.status ?? "active");
  const [vni, setVni] = createSignal(vlan?.vni != null ? String(vlan.vni) : "");
  const [description, setDescription] = createSignal(vlan?.meta.description ?? "");
  const [tags, setTags] = createSignal<Tag[]>([...(vlan?.meta.tags ?? [])]);
  const [errors, setErrors] = createSignal<Record<string, string>>({});

  const validate = () => {
    const e: Record<string, string> = {};
    const n = Number(vid());
    if (!Number.isInteger(n) || n < 1 || n > 4094) e.vid = t("ipam.vlan.vid_invalid");
    if (!name().trim()) e.name = t("ipam.tenancy.name_required");
    if (vni().trim() && !(Number.isInteger(Number(vni())) && Number(vni()) >= 0 && Number(vni()) <= 16_777_215)) e.vni = t("ipam.vlan.vni_invalid");
    setErrors(e);
    return Object.keys(e).length === 0;
  };

  const send = (o: { dryRun: boolean; acknowledge: string[] }) => {
    const vniValue = vni().trim() ? Number(vni()) : null;
    if (!vlan) {
      const body: VlanInput = {
        vid: Number(vid()),
        name: name().trim(),
        site: site() || null,
        status: status(),
        vni: vniValue,
        description: description().trim() || null,
        tags: tags(),
      };
      return api.post("/api/v1/vlans", { query: writeQuery(o.dryRun, o.acknowledge), body });
    }
    const patch: VlanPatch = {};
    if (Number(vid()) !== vlan.vid) patch.vid = Number(vid());
    if (name().trim() !== vlan.name) patch.name = name().trim();
    if ((site() || null) !== (vlan.site ?? null)) patch.site = site() || null;
    if (status() !== vlan.status) patch.status = status();
    if (vniValue !== (vlan.vni ?? null)) patch.vni = vniValue;
    if ((description().trim() || null) !== (vlan.meta.description ?? null)) patch.description = description().trim() || null;
    if (JSON.stringify(tags()) !== JSON.stringify(vlan.meta.tags ?? [])) patch.tags = tags();
    return api.patch("/api/v1/vlans/{id}", { path: { id: vlan.id }, query: writeQuery(o.dryRun, o.acknowledge), body: patch, ifMatch: vlan.meta.revision });
  };

  return (
    <FormDialog
      title={vlan ? t("ipam.vlan.edit_title", { vid: vlan.vid }) : t("ipam.vlan.create_title")}
      submitLabel={vlan ? t("ipam.tenancy.save") : t("ipam.vlan.create")}
      testid="dialog-vlan-form"
      validate={validate}
      send={send}
      doneTitle={() => (vlan ? t("ipam.tenancy.saved", { name: `${vid()} ${name()}` }) : t("ipam.tenancy.created", { name: `${vid()} ${name()}` }))}
      onDone={() => props.onDone()}
      onClose={props.onClose}
    >
      <div class="field-row">
        <TextField id="vid" label={t("ipam.col.vid")} value={vid()} onInput={setVid} error={errors().vid} type="number" />
        <TextField id="name" label={t("ipam.col.name")} value={name()} onInput={setName} error={errors().name} />
      </div>
      <div class="field-row">
        <div class="field">
          <label for="vlan-site">{t("ipam.col.site")}</label>
          <select id="vlan-site" class="select" value={site()} onChange={(e) => setSite(e.currentTarget.value)}>
            <option value="">{t("ipam.tenancy.none")}</option>
            <For each={props.sites}>{(s) => <option value={s.id}>{s.name}</option>}</For>
          </select>
        </div>
        <div class="field">
          <label for="vlan-status">{t("ipam.col.status")}</label>
          <select id="vlan-status" class="select" value={status()} onChange={(e) => setStatus(e.currentTarget.value as Status)}>
            <For each={STATUSES}>{(s) => <option value={s}>{statusWord(s)}</option>}</For>
          </select>
        </div>
      </div>
      <TextField id="vni" label={t("ipam.col.vni")} value={vni()} onInput={setVni} error={errors().vni} type="number" help={t("ipam.vlan.vni_help")} />
      <TextField id="description" label={t("ipam.col.description")} value={description()} onInput={setDescription} />
      <TagsInput label={t("ipam.col.tags")} value={tags()} onChange={setTags} />
    </FormDialog>
  );
}

export default function VlansView() {
  const [sites] = createResource(() => fetchAll<Site>("/api/v1/sites").then((r) => r.items));
  const [source, setSource] = createSignal<ListSource<Vlan>>();
  const styles = createVlanStyles(() => source()?.rows().map((v) => v.vid) ?? []);
  const siteName = (id?: string | null) => (id ? sites()?.find((s) => s.id === id)?.name : undefined);
  const [creating, setCreating] = createSignal(false);
  // The VLAN provision dialog: for a new VLAN ({}) or an existing one to put onto the network.
  const [provisioning, setProvisioning] = createSignal<{ vlan?: Vlan } | null>(null);
  const [listing, setListing] = createSignal<Vlan | null>(null);
  const rowActions: RowAction<Vlan>[] = [
    { id: "provision", label: () => t("ipam.vlan.provision.row_action"), disabled: (v) => !!v.meta.deleted, hidden: () => !writesAll(), run: (v) => setProvisioning({ vlan: v }) },
    { id: "prefixes", label: () => t("ipam.vlan.prefixes.row_action"), run: (v) => setListing(v) },
  ];

  const columns = createMemo<Column<Vlan>[]>(() => [
    {
      id: "vid",
      header: () => t("ipam.col.vid"),
      width: 110,
      sort: "vid",
      fixed: true,
      text: (v) => String(v.vid),
      render: (v) => <VlanChip vid={v.vid} style={styles().get(v.vid)} />,
    },
    { id: "name", header: () => t("ipam.col.name"), width: 200, sort: "name", text: (v) => v.name, render: (v) => v.name },
    { id: "site", header: () => t("ipam.col.site"), width: 150, render: (v) => siteName(v.site) ?? "" },
    { id: "status", header: () => t("ipam.col.status"), width: 120, render: (v) => <StatusBadge status={v.status} /> },
    { id: "vni", header: () => t("ipam.col.vni"), width: 110, align: "right", render: (v) => (v.vni != null ? <span class="num">{v.vni}</span> : "") },
    { id: "description", header: () => t("ipam.col.description"), render: (v) => v.meta.description ?? "" },
    { id: "tags", header: () => t("ipam.col.tags"), width: 160, hidden: true, render: (v) => <Tags tags={v.meta.tags} /> },
    { id: "updated", header: () => t("ipam.col.updated"), width: 130, sort: "updated", hidden: true, render: (v) => <TimeAgo at={v.meta.updated.at} /> },
  ]);

  return (
    <div class="page list-page" data-testid="page-ipam-vlans">
      <IpamNav />
      <div class="page-head">
        <div>
          <h1 tabIndex={-1}>{t("ipam.nav.vlans")}</h1>
        </div>
        <div class="actions">
          {/* Provisioning writes through a network controller: refused to scoped principals. */}
          <Show when={writesAll()}>
            <button type="button" class="btn" data-testid="vlan-provision" onClick={() => setProvisioning({})}>
              <Icon name="plus" />
              {t("ipam.vlan.provision.action")}
            </button>
          </Show>
          <Show when={may.create("vlan")}>
            <button type="button" class="btn primary" data-testid="vlan-create" onClick={() => setCreating(true)}>
              <Icon name="plus" />
              {t("ipam.vlan.create")}
            </button>
          </Show>
        </div>
      </div>
      <CollectionPage<Vlan>
        id="vlans"
        collection="vlans"
        kind="vlan"
        path="/api/v1/vlans"
        label={t("ipam.nav.vlans")}
        filterLabel={t("ipam.vlan.filter_label")}
        filterPlaceholder={t("ipam.vlan.filter_placeholder")}
        fields={[{ name: "status", values: STATUSES }]}
        defaultSort={{ field: "vid", desc: false }}
        columns={columns()}
        rowLabel={(v) => `${v.vid} ${v.name}`}
        sourceRef={(s) => setSource(() => s)}
        actions={rowActions}
        mayWrite={(v) => may.vlan(v)}
        edit={(v, close) => <VlanForm vlan={v} sites={sites() ?? []} onDone={() => close(true)} onClose={() => close(false)} />}
        empty={
          <div class="empty">
            <h3>{t("ipam.vlan.empty")}</h3>
          </div>
        }
      />
      <Show when={provisioning()} keyed>
        {(p) => (
          <ProvisionDialog
            vlan={p.vlan}
            onClose={() => setProvisioning(null)}
            onDone={() => {
              setProvisioning(null);
              source()?.reload();
            }}
          />
        )}
      </Show>
      <Show when={listing()} keyed>
        {(v) => <PrefixesDialog vlan={v} onClose={() => setListing(null)} />}
      </Show>
      <Show when={creating()}>
        <VlanForm
          sites={sites() ?? []}
          onClose={() => setCreating(false)}
          onDone={() => {
            setCreating(false);
            source()?.reload();
          }}
        />
      </Show>
    </div>
  );
}
