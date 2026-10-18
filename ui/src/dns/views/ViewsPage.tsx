// The views of the DNS area (/dns/views, DNS-20, docs/dns.md section 11): the views in the
// order they are tried, each with its rules in words, the zone scopes it sees with their
// weights and shares, and its recursion access list. A view moves by drag and drop onto
// another row or with the up and down buttons (a change of `order` with the view's
// revision; the others make room). Create, edit and delete; the refusal of a delete while a
// forwarding rule names the view comes with the names. Below the list, what a query no view
// matches gets: the implicit default view, which is no row.
import { createResource, createSignal, For, Show } from "solid-js";
import { createLiveQuery, latest } from "../../api/live";
import { session } from "../../auth/session";
import { Icon } from "../../components/Icon";
import { ErrorNotice } from "../../components/Notice";
import { PageHead } from "../../components/PageHead";
import { toast } from "../../components/toast";
import { DataGrid } from "../../grid/DataGrid";
import type { Column, RowAction } from "../../grid/types";
import { t } from "../../i18n";
import { mayWriteDns } from "../access";
import { listAcls, listZones } from "../api";
import { DnsNav } from "../DnsNav";
import { DnsProblem, unavailable } from "../Parts";
import type { Acl, Zone } from "../types";
import { listViews, updateView, type ViewItem } from "./api";
import { DeleteViewDialog, ViewDialog } from "./ViewDialog";
import { droppedAt, minuteText, movedTo, ruleValues, shares, viewOrder, type MatchRule } from "./model";
import "../dns.css";
import "./views.css";

/** A rule in words: the test and its values. */
export function ruleWords(rule: MatchRule): string {
  if (rule.test === "time_of_day") {
    return t("dns.view.rule.words.time_of_day", { from: minuteText(rule.from_minute), to: minuteText(rule.to_minute) });
  }
  const values = rule.test === "transport" ? rule.transports.map((tr) => t(`dns.view.transport.${tr}`)) : ruleValues(rule);
  return t(`dns.view.rule.words.${rule.test}`, { values: values.join(", ") });
}

/** What the page reads beside the views: the zones (names and scopes) and the access lists. */
async function references(): Promise<{ zones: Zone[]; acls: Acl[] }> {
  const [zones, acls] = await Promise.all([listZones().catch(() => ({ items: [] as Zone[] })), listAcls().catch(() => ({ items: [] as Acl[] }))]);
  return { zones: zones.items, acls: acls.items };
}

/** What a query no view matches gets (docs/dns.md section 11). */
function DefaultView() {
  const profile = () => session()?.profile ?? "home";
  return (
    <section class="page-section dns-view-default" aria-labelledby="dns-view-default-title" data-testid="view-default" data-key={profile()}>
      <h2 id="dns-view-default-title">{t("dns.view.default.title")}</h2>
      <p>{t("dns.view.default.body", { profile: t(`profile.${profile()}.name`) })}</p>
    </section>
  );
}

export default function ViewsPage() {
  const [dialog, setDialog] = createSignal<{ kind: "edit"; view?: ViewItem } | { kind: "delete"; view: ViewItem } | null>(null);
  const [dragging, setDragging] = createSignal<string | null>(null);
  const [moveError, setMoveError] = createSignal<unknown>();
  const query = createLiveQuery({
    topics: ["dns"],
    fetch: async (signal) => {
      const page = await listViews(signal);
      return { value: [...page.items].sort(viewOrder), revision: page.revision };
    },
  });
  const [refs, { refetch: refetchRefs }] = createResource(references);
  const blocked = () => unavailable(query.value.error);
  const views = () => latest(query);
  const zoneName = (id: string) => refs.latest?.zones.find((z) => z.id === id)?.name ?? id;
  const aclName = (id: string) => refs.latest?.acls.find((a) => a.id === id)?.name;

  const close = (changed: boolean) => {
    setDialog(null);
    if (changed) {
      query.refetch();
      void refetchRefs();
    }
  };

  /** Moves a view to a position (from 1): a change of its `order`. */
  const move = async (view: ViewItem, position: number | undefined) => {
    if (position === undefined || !mayWriteDns()) return;
    setMoveError(undefined);
    try {
      await updateView(view, { order: position });
      toast({ kind: "ok", title: t("dns.view.moved", { name: view.name, order: position }) });
    } catch (err) {
      setMoveError(err);
    } finally {
      query.refetch();
    }
  };
  const step = (view: ViewItem, delta: -1 | 1) => void move(view, movedTo(views() ?? [], view.id, delta));

  const columns: Column<ViewItem>[] = [
    {
      id: "order",
      header: () => t("dns.view.col.order"),
      width: 130,
      fixed: true,
      text: (v) => String(v.order),
      render: (v) => (
        <div
          class="dns-view-order"
          classList={{ "drop-target": dragging() !== null && dragging() !== v.id }}
          data-testid="view-order"
          data-key={String(v.order)}
          onDragOver={(e) => {
            if (dragging() !== null && dragging() !== v.id) e.preventDefault();
          }}
          onDrop={(e) => {
            e.preventDefault();
            const id = dragging();
            setDragging(null);
            const moved = id ? (views() ?? []).find((x) => x.id === id) : undefined;
            if (moved) void move(moved, droppedAt(views() ?? [], moved.id, v.id));
          }}
        >
          <Show when={mayWriteDns()}>
            <span
              class="dns-view-drag"
              draggable="true"
              title={t("dns.view.drag", { name: v.name })}
              data-testid="view-drag"
              onDragStart={(e) => {
                // The row's own handler refuses drags of a grid without drag items: not this one.
                e.stopPropagation();
                setDragging(v.id);
                if (e.dataTransfer) {
                  e.dataTransfer.effectAllowed = "move";
                  e.dataTransfer.setData("text/plain", v.name);
                }
              }}
              onDragEnd={() => setDragging(null)}
            >
              <Icon name="drag" size="sm" />
            </span>
          </Show>
          <span class="mono">{v.order}</span>
          <Show when={mayWriteDns()}>
            <button
              type="button"
              class="icon-btn"
              aria-label={t("dns.view.move_up", { name: v.name })}
              disabled={movedTo(views() ?? [], v.id, -1) === undefined}
              data-testid="view-move-up"
              onClick={() => step(v, -1)}
            >
              <Icon name="chev-u" size="sm" />
            </button>
            <button
              type="button"
              class="icon-btn"
              aria-label={t("dns.view.move_down", { name: v.name })}
              disabled={movedTo(views() ?? [], v.id, 1) === undefined}
              data-testid="view-move-down"
              onClick={() => step(v, 1)}
            >
              <Icon name="chev-d" size="sm" />
            </button>
          </Show>
        </div>
      ),
    },
    {
      id: "name",
      header: () => t("dns.view.col.name"),
      width: 200,
      text: (v) => v.name,
      render: (v) => (
        <span class="dns-view-name">
          <span>{v.name}</span>
          <Show when={v.description}>
            <span class="muted">{v.description}</span>
          </Show>
        </span>
      ),
    },
    {
      id: "rules",
      header: () => t("dns.view.col.rules"),
      text: (v) => (v.rules ?? []).map(ruleWords).join("; "),
      render: (v) => (
        <Show when={(v.rules ?? []).length > 0} fallback={<span class="tag" data-testid="view-every">{t("dns.view.every_query")}</span>}>
          <span class="dns-chips">
            <For each={v.rules ?? []}>
              {(rule) => (
                <span class="tag" data-testid="view-rule" data-kind={rule.test}>
                  {ruleWords(rule)}
                </span>
              )}
            </For>
          </span>
        </Show>
      ),
    },
    {
      id: "scopes",
      header: () => t("dns.view.col.scopes"),
      width: 340,
      text: (v) => (v.scope_map ?? []).map((s) => `${zoneName(s.zone)}:${s.scope}`).join(" "),
      render: (v) => {
        const map = () => v.scope_map ?? [];
        return (
          <Show when={map().length > 0} fallback={<span class="muted">{t("dns.view.default_scopes")}</span>}>
            <span class="dns-chips dns-view-scopes">
              <For each={map()}>
                {(s, i) => (
                  <span class="tag" data-testid="view-scope" data-key={`${zoneName(s.zone)}:${s.scope}`} data-weight={String(s.weight)}>
                    {t("dns.view.scope_chip", { zone: zoneName(s.zone), scope: s.scope, weight: s.weight, share: shares(map())[i()] ?? 100 })}
                  </span>
                )}
              </For>
            </span>
          </Show>
        );
      },
    },
    {
      id: "recursion",
      header: () => t("dns.view.col.recursion"),
      width: 180,
      text: (v) => (v.recursion ? (aclName(v.recursion) ?? v.recursion) : t("dns.view.recursion.default")),
      render: (v) => (
        <Show when={v.recursion} fallback={<span class="muted" data-testid="view-recursion" data-state="default">{t("dns.view.recursion.default")}</span>}>
          {(id) => (
            <Show
              when={aclName(id())}
              fallback={
                <span class="tag warn" data-testid="view-recursion" data-state="missing">
                  {t("dns.view.recursion.missing")}
                </span>
              }
            >
              {(name) => (
                <span class="tag" data-testid="view-recursion" data-state="list" data-key={name()}>
                  {name()}
                </span>
              )}
            </Show>
          )}
        </Show>
      ),
    },
  ];
  const actions: RowAction<ViewItem>[] = [
    { id: "edit", label: () => t("dns.do.edit"), hidden: () => !mayWriteDns(), run: (v) => setDialog({ kind: "edit", view: v }) },
    {
      id: "up",
      label: () => t("dns.view.action.up"),
      hidden: () => !mayWriteDns(),
      disabled: (v) => movedTo(views() ?? [], v.id, -1) === undefined,
      run: (v) => step(v, -1),
    },
    {
      id: "down",
      label: () => t("dns.view.action.down"),
      hidden: () => !mayWriteDns(),
      disabled: (v) => movedTo(views() ?? [], v.id, 1) === undefined,
      run: (v) => step(v, 1),
    },
    { id: "delete", label: () => t("dns.do.delete"), danger: true, hidden: () => !mayWriteDns(), run: (v) => setDialog({ kind: "delete", view: v }) },
  ];

  return (
    <div class="page dns-page list-page" data-testid="page-dns-views">
      <DnsNav />
      <PageHead
        title={t("dns.view.title")}
        sub={t("dns.view.sub")}
        actions={
          <Show when={mayWriteDns() && !blocked()}>
            <button type="button" class="btn primary" data-testid="dns-view-create" onClick={() => setDialog({ kind: "edit" })}>
              <Icon name="plus" />
              {t("dns.view.create")}
            </button>
          </Show>
        }
      />
      <Show when={!blocked()} fallback={<div class="page-body"><DnsProblem error={query.value.error} /></div>}>
        <Show when={moveError()}>
          <div class="dns-view-notes">
            <ErrorNotice error={moveError()} />
          </div>
        </Show>
        <div class="dns-list-body">
          <DataGrid
            id="dns-views"
            label={t("dns.view.title")}
            noSelection
            columns={columns}
            rows={views() ?? []}
            rowId={(v) => v.id}
            rowKey={(v) => v.name}
            rowLabel={(v) => v.name}
            loading={query.value.loading}
            initial={views() === undefined && !query.value.error}
            error={query.value.error}
            onRetry={query.refetch}
            onOpen={(v) => (mayWriteDns() ? setDialog({ kind: "edit", view: v }) : undefined)}
            rowActions={actions}
            empty={
              <div class="empty" data-testid="dns-views-empty">
                <h3>{t("dns.view.empty")}</h3>
                <p>{t("dns.view.empty_body")}</p>
              </div>
            }
          />
        </div>
        <DefaultView />
      </Show>
      <Show when={dialog()} keyed>
        {(d) =>
          d.kind === "edit" ? (
            <ViewDialog
              view={d.view}
              count={(views() ?? []).length}
              zones={refs.latest?.zones ?? []}
              acls={refs.latest?.acls ?? []}
              onClose={() => close(false)}
              onDone={() => close(true)}
            />
          ) : (
            <DeleteViewDialog view={d.view} onClose={() => close(false)} onDone={() => close(true)} />
          )
        }
      </Show>
    </div>
  );
}
