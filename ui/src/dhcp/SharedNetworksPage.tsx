// The shared networks of the DHCP area (/dhcp/shared-networks): scopes that share one link. A row
// has the name, the listener interface, the scopes it holds (linked) and a description. Create, edit
// (with the revision) and delete; a shared network that scopes name is not deleted, and the
// confirmation shows the server's message.
import { A } from "@solidjs/router";
import { createResource, createSignal, For, Show, untrack } from "solid-js";
import { createLiveQuery, latest } from "../api/live";
import { ConfirmDialog, Dialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { ErrorNotice } from "../components/Notice";
import { PageHead } from "../components/PageHead";
import { toast } from "../components/toast";
import { DataGrid } from "../grid/DataGrid";
import type { Column, RowAction } from "../grid/types";
import { t } from "../i18n";
import { mayWriteDhcp } from "./access";
import { createSharedNetwork, deleteSharedNetwork, listScopes, listSharedNetworks, updateSharedNetwork, type SharedNetwork } from "./api";
import { DhcpNav } from "./DhcpNav";
import { validDhcpName } from "./model";
import { describedBy, DhcpProblem, errorFor, Field, fieldErrors, hasField, unavailable } from "./Parts";
import { dhcpPaths } from "./paths";
import "./dhcp.css";

function NetworkDialog(props: { network?: SharedNetwork; onClose: () => void; onDone: () => void }) {
  let nameInput!: HTMLInputElement;
  const network = untrack(() => props.network);
  const [name, setName] = createSignal(network?.name ?? "");
  const [iface, setIface] = createSignal(network?.interface ?? "");
  const [description, setDescription] = createSignal(network?.description ?? "");
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);

  const submit = async (event: Event) => {
    event.preventDefault();
    if (busy()) return;
    const e: Record<string, string> = {};
    if (!validDhcpName(name().trim())) e.name = t("dhcp.check.name");
    setErrors(e);
    if (Object.keys(e).length > 0) return;
    setBusy(true);
    setError(undefined);
    try {
      const body = { name: name().trim(), interface: iface().trim(), description: description().trim() };
      if (network) await updateSharedNetwork(network, body);
      else await createSharedNetwork({ name: body.name, ...(body.interface ? { interface: body.interface } : {}), ...(body.description ? { description: body.description } : {}) });
      toast({ kind: "ok", title: network ? t("dhcp.network.saved", { name: body.name }) : t("dhcp.network.created", { name: body.name }) });
      props.onDone();
    } catch (err) {
      const fields = fieldErrors(err);
      if (hasField(fields, ["name", "interface"])) setErrors(fields);
      else setError(err);
    } finally {
      setBusy(false);
    }
  };

  const title = () => (network ? t("dhcp.network.edit_title", { name: network.name }) : t("dhcp.network.create_title"));
  return (
    <Dialog label={title()} onClose={props.onClose} class="dialog dhcp-dialog" testid="dialog-network-form" initialFocus={() => nameInput}>
      <h2 class="dialog-title">{title()}</h2>
      <form class="dialog-body dhcp-form" onSubmit={(e) => void submit(e)} novalidate>
        <Field id="name" label={t("dhcp.network.field.name")} error={errorFor(errors(), "name")} help={t("dhcp.field.name_help")}>
          <input
            ref={nameInput}
            id="dhcp-f-name"
            class="input mono"
            value={name()}
            spellcheck={false}
            autocomplete="off"
            aria-invalid={errors().name ? "true" : undefined}
            aria-describedby={describedBy("name", errors().name, "help")}
            data-testid="field-name"
            onInput={(e) => setName(e.currentTarget.value)}
          />
        </Field>
        <Field id="interface" label={t("dhcp.network.field.interface")} error={errorFor(errors(), "interface")} help={t("dhcp.network.field.interface_help")}>
          <input
            id="dhcp-f-interface"
            class="input mono"
            value={iface()}
            spellcheck={false}
            aria-describedby={describedBy("interface", errors().interface, "help")}
            data-testid="field-interface"
            onInput={(e) => setIface(e.currentTarget.value)}
          />
        </Field>
        <Field id="description" label={t("dhcp.field.description")}>
          <input id="dhcp-f-description" class="input" value={description()} data-testid="field-description" onInput={(e) => setDescription(e.currentTarget.value)} />
        </Field>
        <ErrorNotice error={error()} />
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {network ? t("dhcp.network.save") : t("dhcp.network.create")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

function DeleteNetworkDialog(props: { network: SharedNetwork; onClose: () => void; onDone: () => void }) {
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  return (
    <ConfirmDialog
      title={t("dhcp.network.delete_title", { name: props.network.name })}
      testid="dialog-network-delete"
      danger
      busy={busy()}
      confirmLabel={t("dhcp.network.delete_confirm")}
      cancelLabel={t("common.action.cancel")}
      onClose={props.onClose}
      onConfirm={() => {
        setBusy(true);
        setError(undefined);
        deleteSharedNetwork(props.network)
          .then(() => {
            toast({ kind: "ok", title: t("dhcp.network.deleted", { name: props.network.name }) });
            props.onDone();
          })
          .catch(setError)
          .finally(() => setBusy(false));
      }}
      body={
        <>
          <p>{t("dhcp.network.delete_body")}</p>
          <ErrorNotice error={error()} />
        </>
      }
    />
  );
}

export default function SharedNetworksPage() {
  const [dialog, setDialog] = createSignal<{ kind: "edit"; network?: SharedNetwork } | { kind: "delete"; network: SharedNetwork } | null>(null);
  const query = createLiveQuery({
    topics: ["dhcp"],
    fetch: async (signal) => {
      const page = await listSharedNetworks(signal);
      return { value: page.items, revision: page.revision };
    },
  });
  // The scopes come by identifier; their networks are the words shown.
  const [scopes] = createResource(async () => (await listScopes()).items);
  const cidrOf = (prefix: string) => (scopes.error ? undefined : scopes.latest?.find((s) => s.prefix === prefix)?.cidr) ?? prefix;
  const blocked = () => unavailable(query.value.error);
  const networks = () => latest(query);
  const close = (changed: boolean) => {
    setDialog(null);
    if (changed) query.refetch();
  };

  const columns: Column<SharedNetwork>[] = [
    { id: "name", header: () => t("dhcp.col.name"), width: 200, fixed: true, text: (n) => n.name, render: (n) => <span class="mono">{n.name}</span> },
    { id: "interface", header: () => t("dhcp.col.interface"), width: 160, text: (n) => n.interface ?? "", render: (n) => <span class="mono">{n.interface ?? ""}</span> },
    {
      id: "scopes",
      header: () => t("dhcp.col.scopes"),
      text: (n) => n.scopes.map(cidrOf).join(", "),
      render: (n) => (
        <span class="dhcp-chips">
          <For each={n.scopes}>
            {(prefix) => (
              <A class="tag mono" href={dhcpPaths.scope(prefix)} data-testid="network-scope" data-key={cidrOf(prefix)}>
                {cidrOf(prefix)}
              </A>
            )}
          </For>
        </span>
      ),
    },
    { id: "description", header: () => t("dhcp.col.description"), width: 240, render: (n) => <span class="muted">{n.description ?? ""}</span> },
  ];
  const actions: RowAction<SharedNetwork>[] = [
    { id: "edit", label: () => t("dhcp.do.edit"), hidden: () => !mayWriteDhcp(), run: (n) => setDialog({ kind: "edit", network: n }) },
    { id: "delete", label: () => t("dhcp.do.delete"), danger: true, hidden: () => !mayWriteDhcp(), run: (n) => setDialog({ kind: "delete", network: n }) },
  ];

  return (
    <div class="page dhcp-page list-page" data-testid="page-dhcp-networks">
      <DhcpNav />
      <PageHead
        title={t("dhcp.shared_networks.title")}
        sub={t("dhcp.network.sub")}
        actions={
          <Show when={mayWriteDhcp() && !blocked()}>
            <button type="button" class="btn primary" data-testid="dhcp-network-create" onClick={() => setDialog({ kind: "edit" })}>
              <Icon name="plus" />
              {t("dhcp.network.create")}
            </button>
          </Show>
        }
      />
      <Show
        when={!blocked()}
        fallback={
          <div class="page-body">
            <DhcpProblem error={query.value.error} />
          </div>
        }
      >
        <div class="dhcp-list-body">
          <DataGrid
            id="dhcp-networks"
            label={t("dhcp.shared_networks.title")}
            noSelection
            columns={columns}
            rows={networks() ?? []}
            rowId={(n) => n.id}
            rowKey={(n) => n.name}
            rowLabel={(n) => n.name}
            loading={query.value.loading}
            initial={networks() === undefined && !query.value.error}
            error={query.value.error}
            onRetry={query.refetch}
            onOpen={(n) => (mayWriteDhcp() ? setDialog({ kind: "edit", network: n }) : undefined)}
            rowActions={actions}
            empty={
              <div class="empty" data-testid="dhcp-networks-empty">
                <h3>{t("dhcp.network.empty")}</h3>
                <p>{t("dhcp.network.empty_body")}</p>
              </div>
            }
          />
        </div>
      </Show>
      <Show when={dialog()} keyed>
        {(d) =>
          d.kind === "edit" ? (
            <NetworkDialog network={d.network} onClose={() => close(false)} onDone={() => close(true)} />
          ) : (
            <DeleteNetworkDialog network={d.network} onClose={() => close(false)} onDone={() => close(true)} />
          )
        }
      </Show>
    </div>
  );
}
