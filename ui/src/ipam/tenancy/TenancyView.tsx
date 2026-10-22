// Tenants and VRFs (/ipam/tenants, IPAM-01): independent address spaces, so overlapping
// private networks of separate customers or labs can coexist. Two grids on one page.
import { createMemo, createResource, createSignal, For, Show, untrack, type Accessor } from "solid-js";
import { api } from "../../api/client";
import { fetchAll } from "../../api/paginate";
import type { Tag, Tenant, TenantInput, TenantPatch, Vrf, VrfInput, VrfPatch, WriteResponse } from "../../api/types";
import { writesAll } from "../../auth/gate";
import { Icon } from "../../components/Icon";
import { Tags } from "../../grid/cells";
import type { ListSource } from "../../grid/source";
import type { Column } from "../../grid/types";
import { listZones } from "../../dns/api";
import { isReverse } from "../../dns/model";
import { t } from "../../i18n";
import { TagsInput } from "../fields/CustomFieldsEditor";
import { Field, SelectInput, serverFieldMessage, tracked, withCurrent, WriteForm, type Option } from "../formKit";
import { IpamNav } from "../IpamNav";
import { writeQuery } from "../plan/describe";
import { CollectionPage } from "./CollectionPage";
import { FormDialog, TextField } from "./FormDialog";
import "../ipam.css";

/** The primary forward zones a tenant can pick as its default zone; undefined while the DNS service gives none. */
function useZoneChoices(tenant: Tenant | undefined): Accessor<Option[] | undefined> {
  // Only an edit shows the setting; a server without the DNS service (404, 409) hides it.
  const [zones] = createResource(
    () => tenant !== undefined,
    async (editing) => {
      if (!editing) return undefined;
      try {
        return (await listZones()).items;
      } catch {
        return undefined;
      }
    },
  );
  return createMemo(() => {
    const all = zones();
    if (all === undefined) return undefined;
    const forward = all
      .filter((z) => z.kind === "primary" && !isReverse(z) && !z.name.endsWith(".arpa") && (z.tenant == null || z.tenant === tenant?.id))
      .sort((a, b) => a.name.localeCompare(b.name));
    return [{ value: "", label: t("ipam.tenant.default_zone_none") }, ...forward.map((z) => ({ value: z.id, label: z.name }))];
  });
}

function TenantForm(props: { tenant?: Tenant; onDone: () => void; onClose: () => void }) {
  const tenant = untrack(() => props.tenant);
  const [name, setName] = createSignal(tenant?.name ?? "");
  const [description, setDescription] = createSignal(tenant?.meta.description ?? "");
  const [tags, setTags] = createSignal<Tag[]>([...(tenant?.meta.tags ?? [])]);
  const [zone, setZone] = createSignal(tenant?.dns?.default_zone ?? "");
  const zoneChoices = useZoneChoices(tenant);
  const nameMissing = () => name().trim() === "";

  // The fields that changed, for an edit. The default zone is sent as the whole `dns` member:
  // `{}` clears it.
  const patch = createMemo<TenantPatch>(() => {
    const out: TenantPatch = {};
    if (!tenant) return out;
    if (name().trim() !== tenant.name) out.name = name().trim();
    if ((description().trim() || null) !== (tenant.meta.description ?? null)) out.description = description().trim() || null;
    if (JSON.stringify(tags()) !== JSON.stringify(tenant.meta.tags ?? [])) out.tags = tags();
    if (zoneChoices() !== undefined && zone() !== (tenant.dns?.default_zone ?? "")) out.dns = zone() === "" ? {} : { default_zone: zone() };
    return out;
  });

  return (
    <WriteForm<Tenant>
      name="tenant-form"
      title={tenant ? t("ipam.tenant.edit_title", { name: tenant.name }) : t("ipam.tenant.create_title")}
      submitLabel={tenant ? t("ipam.tenancy.save") : t("ipam.tenant.create")}
      changed={!tenant || Object.keys(patch()).length > 0}
      placed={["name", "description", "tags", "dns.default_zone"]}
      validate={() => !nameMissing()}
      planTitle={() => (tenant ? t("ipam.tenant.edit_title", { name: tenant.name }) : t("ipam.tenant.create_title"))}
      planConfirm={tenant ? t("ipam.tenancy.save") : t("ipam.tenant.create")}
      send={(o) =>
        (tenant
          ? api.patch("/api/v1/tenants/{id}", {
              path: { id: tenant.id },
              query: writeQuery(o.dryRun, o.acknowledge),
              body: patch(),
              ifMatch: tenant.meta.revision,
            })
          : api.post("/api/v1/tenants", {
              query: writeQuery(o.dryRun, o.acknowledge),
              body: { name: name().trim(), description: description().trim() || null, tags: tags() } satisfies TenantInput,
            })) as Promise<WriteResponse<Tenant>>
      }
      doneTitle={() => (tenant ? t("ipam.tenancy.saved", { name: name() }) : t("ipam.tenancy.created", { name: name() }))}
      onDone={() => props.onDone()}
      onClose={props.onClose}
    >
      {(flow) => (
        <>
          <Field
            name="name"
            label={t("ipam.col.name")}
            error={serverFieldMessage(flow.error(), "name") ?? (flow.submitted() && nameMissing() ? t("ipam.tenancy.name_required") : undefined)}
          >
            {(c) => <input class="input" type="text" autocomplete="off" {...c} value={name()} onInput={(e) => tracked(setName, flow)(e.currentTarget.value)} />}
          </Field>
          <Field name="description" label={t("ipam.col.description")} error={serverFieldMessage(flow.error(), "description")}>
            {(c) => (
              <input class="input" type="text" autocomplete="off" {...c} value={description()} onInput={(e) => tracked(setDescription, flow)(e.currentTarget.value)} />
            )}
          </Field>
          <Show when={zoneChoices()}>
            {(choices) => (
              <Field
                name="dns.default_zone"
                label={t("ipam.tenant.default_zone")}
                help={t("ipam.tenant.default_zone_help")}
                error={serverFieldMessage(flow.error(), "dns.default_zone")}
              >
                {(c) => (
                  <SelectInput
                    {...c}
                    data-testid="tenant-default-zone"
                    value={zone()}
                    options={withCurrent(choices(), zone(), (id) => id.slice(0, 8))}
                    onChange={tracked(setZone, flow)}
                  />
                )}
              </Field>
            )}
          </Show>
          <TagsInput label={t("ipam.col.tags")} value={tags()} onChange={tracked(setTags, flow)} error={serverFieldMessage(flow.error(), "tags")} />
        </>
      )}
    </WriteForm>
  );
}

function VrfForm(props: { vrf?: Vrf; tenants: Tenant[]; onDone: () => void; onClose: () => void }) {
  const vrf = untrack(() => props.vrf);
  const [name, setName] = createSignal(vrf?.name ?? "");
  const [tenant, setTenant] = createSignal(vrf?.tenant ?? "");
  const [rd, setRd] = createSignal(vrf?.rd ?? "");
  const [description, setDescription] = createSignal(vrf?.meta.description ?? "");
  const [tags, setTags] = createSignal<Tag[]>([...(vrf?.meta.tags ?? [])]);
  const [error, setError] = createSignal<string | undefined>();
  const send = (o: { dryRun: boolean; acknowledge: string[] }) => {
    if (!vrf) {
      const body: VrfInput = {
        name: name().trim(),
        tenant: tenant() || null,
        rd: rd().trim() || null,
        description: description().trim() || null,
        tags: tags(),
      };
      return api.post("/api/v1/vrfs", { query: writeQuery(o.dryRun, o.acknowledge), body });
    }
    const patch: VrfPatch = {};
    if (name().trim() !== vrf.name) patch.name = name().trim();
    if ((rd().trim() || null) !== (vrf.rd ?? null)) patch.rd = rd().trim() || null;
    if ((description().trim() || null) !== (vrf.meta.description ?? null)) patch.description = description().trim() || null;
    if (JSON.stringify(tags()) !== JSON.stringify(vrf.meta.tags ?? [])) patch.tags = tags();
    return api.patch("/api/v1/vrfs/{id}", { path: { id: vrf.id }, query: writeQuery(o.dryRun, o.acknowledge), body: patch, ifMatch: vrf.meta.revision });
  };
  return (
    <FormDialog
      title={vrf ? t("ipam.vrf.edit_title", { name: vrf.name }) : t("ipam.vrf.create_title")}
      submitLabel={vrf ? t("ipam.tenancy.save") : t("ipam.vrf.create")}
      testid="dialog-vrf-form"
      validate={() => {
        setError(name().trim() ? undefined : t("ipam.tenancy.name_required"));
        return !!name().trim();
      }}
      send={send}
      doneTitle={() => (vrf ? t("ipam.tenancy.saved", { name: name() }) : t("ipam.tenancy.created", { name: name() }))}
      onDone={() => props.onDone()}
      onClose={props.onClose}
    >
      <TextField id="name" label={t("ipam.col.name")} value={name()} onInput={setName} error={error()} />
      <Show when={!vrf}>
        <div class="field">
          <label for="vrf-tenant">{t("ipam.col.tenant")}</label>
          <select id="vrf-tenant" class="select" value={tenant()} onChange={(e) => setTenant(e.currentTarget.value)}>
            <option value="">{t("ipam.vrf.default_tenant")}</option>
            <For each={props.tenants.filter((tn) => !tn.meta.deleted)}>{(tn) => <option value={tn.id}>{tn.name}</option>}</For>
          </select>
        </div>
      </Show>
      <TextField id="rd" label={t("ipam.vrf.rd")} value={rd()} onInput={setRd} mono help={t("ipam.vrf.rd_help")} />
      <TextField id="description" label={t("ipam.col.description")} value={description()} onInput={setDescription} />
      <TagsInput label={t("ipam.col.tags")} value={tags()} onChange={setTags} />
    </FormDialog>
  );
}

export default function TenancyView() {
  const [tenants, { refetch }] = createResource(() => fetchAll<Tenant>("/api/v1/tenants", { query: { deleted: "include" } }).then((r) => r.items));
  const [creating, setCreating] = createSignal<"tenant" | "vrf" | null>(null);
  const [tenantSource, setTenantSource] = createSignal<ListSource<Tenant>>();
  const [vrfSource, setVrfSource] = createSignal<ListSource<Vrf>>();
  const tenantName = (id: string) => tenants()?.find((tn) => tn.id === id)?.name ?? "";

  const tenantColumns: Column<Tenant>[] = [
    { id: "name", header: () => t("ipam.col.name"), width: 240, sort: "name", fixed: true, text: (tn) => tn.name, render: (tn) => tn.name },
    { id: "description", header: () => t("ipam.col.description"), render: (tn) => tn.meta.description ?? "" },
    { id: "tags", header: () => t("ipam.col.tags"), width: 160, render: (tn) => <Tags tags={tn.meta.tags} /> },
  ];
  const vrfColumns: Column<Vrf>[] = [
    { id: "name", header: () => t("ipam.col.name"), width: 200, sort: "name", fixed: true, text: (v) => v.name, render: (v) => v.name },
    { id: "tenant", header: () => t("ipam.col.tenant"), width: 200, render: (v) => tenantName(v.tenant) },
    { id: "rd", header: () => t("ipam.vrf.rd"), width: 160, render: (v) => <span class="mono">{v.rd ?? ""}</span> },
    { id: "description", header: () => t("ipam.col.description"), render: (v) => v.meta.description ?? "" },
  ];

  return (
    <div class="page tenancy-page" data-testid="page-ipam-tenancy">
      <IpamNav />
      <div class="page-head">
        <div>
          <h1 tabIndex={-1}>{t("ipam.nav.tenancy")}</h1>
        </div>
        <div class="actions">
          <Show when={writesAll()}>
            <button type="button" class="btn" data-testid="tenant-create" onClick={() => setCreating("tenant")}>
              <Icon name="plus" />
              {t("ipam.tenant.create")}
            </button>
            <button type="button" class="btn primary" data-testid="vrf-create" onClick={() => setCreating("vrf")}>
              <Icon name="plus" />
              {t("ipam.vrf.create")}
            </button>
          </Show>
        </div>
      </div>
      <div class="tenancy-split">
        <section aria-label={t("ipam.tenant.title")}>
          <h2 class="split-title">{t("ipam.tenant.title")}</h2>
          <CollectionPage<Tenant>
            id="tenants"
            class="collection half"
            collection="tenants"
            kind="tenant"
            path="/api/v1/tenants"
            label={t("ipam.tenant.title")}
            filterLabel={t("ipam.tenant.filter_label")}
            filterPlaceholder={t("ipam.tenancy.filter_placeholder")}
            defaultSort={{ field: "name", desc: false }}
            columns={tenantColumns}
            rowLabel={(tn) => tn.name}
            sourceRef={(s) => setTenantSource(() => s)}
            edit={(tn, close) => (
              <TenantForm
                tenant={tn}
                onDone={() => {
                  void refetch();
                  close(true);
                }}
                onClose={() => close(false)}
              />
            )}
            empty={<div class="empty"><h3>{t("ipam.tenant.empty")}</h3></div>}
          />
        </section>
        <section aria-label={t("ipam.vrf.title")}>
          <h2 class="split-title">{t("ipam.vrf.title")}</h2>
          <CollectionPage<Vrf>
            id="vrfs"
            class="collection half"
            collection="vrfs"
            kind="vrf"
            path="/api/v1/vrfs"
            label={t("ipam.vrf.title")}
            filterLabel={t("ipam.vrf.filter_label")}
            filterPlaceholder={t("ipam.tenancy.filter_placeholder")}
            defaultSort={{ field: "name", desc: false }}
            columns={vrfColumns}
            rowLabel={(v) => v.name}
            sourceRef={(s) => setVrfSource(() => s)}
            edit={(v, close) => <VrfForm vrf={v} tenants={tenants() ?? []} onDone={() => close(true)} onClose={() => close(false)} />}
            empty={<div class="empty"><h3>{t("ipam.vrf.empty")}</h3></div>}
          />
        </section>
      </div>
      <Show when={creating() === "tenant"}>
        <TenantForm
          onClose={() => setCreating(null)}
          onDone={() => {
            setCreating(null);
            void refetch();
            tenantSource()?.reload();
          }}
        />
      </Show>
      <Show when={creating() === "vrf"}>
        <VrfForm
          tenants={tenants() ?? []}
          onClose={() => setCreating(null)}
          onDone={() => {
            setCreating(null);
            vrfSource()?.reload();
          }}
        />
      </Show>
    </div>
  );
}
