// The owners of a primary zone's names (the Owners tab): in a zone with secure dynamic updates
// (GSS-TSIG, Kerberos) the principal that creates a name owns it. A table of name, principal,
// SID, how the owner got the name, since when and the hold of a removed name, with the filters
// name (a subtree) and owner, paged with the server's cursor. Release removes the owner and
// makes the dynamic records of the name claimable by the host they name; Reassign and "Assign a
// name" give a name to a principal (the name is held for it for the zone's owner hold).
import type { PathsWith } from "../api/client";
import { createMemo, createSignal, onCleanup, Show } from "solid-js";
import { ApiError, errorMessage } from "../api/problem";
import { ConfirmDialog, Dialog } from "../components/Dialog";
import { Icon } from "../components/Icon";
import { ErrorNotice, Notice } from "../components/Notice";
import { toast } from "../components/toast";
import { DataGrid } from "../grid/DataGrid";
import { createListSource } from "../grid/source";
import { TimeAgo } from "../grid/cells";
import type { Column, RowAction } from "../grid/types";
import { formatDateTime, t } from "../i18n";
import { assignOwner, OWNERS_PATH, releaseOwner, type NameOwner, type Zone } from "./api";
import { mayWriteDns } from "./access";
import { canonical, relativeName, validName } from "./model";
import { describedBy, Field, fieldErrors } from "./Parts";

/** A security identifier: `S-1-` and at least one more sub-authority. */
const SID = /^S-1-\d+(-\d+)+$/;

/** A principal as the server wants it: `NAME$@REALM`. */
const PRINCIPAL = /^[^@\s]+@[^@\s]+$/;

/** A typed name as a name of the zone: relative to it unless it already ends with the zone, `@` is the apex. */
function qualify(typed: string, zone: string): string {
  const raw = typed.trim().toLowerCase();
  if (raw === "@") return zone;
  if (raw.endsWith(".")) return canonical(raw);
  return raw === zone || raw.endsWith(`.${zone}`) ? raw : `${raw}.${zone}`;
}

/** Whether the zone keeps owners: it has Kerberos settings in its update policy. */
export function keepsOwners(zone: Pick<Zone, "update">): boolean {
  return zone.update?.kerberos != null;
}

/** The dialog that gives a name to a principal: a new assignment (with a name field) or a reassignment of a listed owner. */
function AssignDialog(props: { zone: Zone; owner?: NameOwner | undefined; onClose: () => void; onDone: () => void }) {
  let first!: HTMLInputElement;
  const [name, setName] = createSignal("");
  const [principal, setPrincipal] = createSignal("");
  const [sid, setSid] = createSignal("");
  const [errors, setErrors] = createSignal<Record<string, string>>({});
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);
  const zoneName = () => props.zone.name;
  const target = () => props.owner?.name ?? qualify(name(), zoneName());
  const title = () => (props.owner ? t("dns.owners.reassign_title", { name: relativeName(props.owner.name, zoneName()) }) : t("dns.owners.assign_title"));

  const submit = async (event: Event) => {
    event.preventDefault();
    if (busy()) return;
    const e: Record<string, string> = {};
    if (!props.owner && (name().trim() === "" || !validName(canonical(target())))) e.name = t("dns.check.name");
    if (!PRINCIPAL.test(principal().trim())) e.principal = t("dns.owners.principal_invalid");
    if (sid().trim() !== "" && !SID.test(sid().trim().toUpperCase())) e.sid = t("dns.owners.sid_invalid");
    setErrors(e);
    if (Object.keys(e).length > 0) return;
    setBusy(true);
    setError(undefined);
    try {
      const body = { principal: principal().trim(), sid: sid().trim() === "" ? null : sid().trim().toUpperCase() };
      await assignOwner(props.zone.id, canonical(target()), body, props.owner?.revision);
      toast({ kind: "ok", title: t("dns.owners.assigned", { name: relativeName(canonical(target()), zoneName()) }) });
      props.onDone();
    } catch (err) {
      const fields = err instanceof ApiError && err.code === "dns.owner.invalid" ? fieldErrors(err) : {};
      if (Object.keys(fields).length > 0) setErrors(fields);
      else setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog label={title()} onClose={props.onClose} class="dialog wide dns-dialog" testid="dialog-owner-assign" initialFocus={() => first}>
      <h2 class="dialog-title">{title()}</h2>
      <form class="dialog-body dns-form" onSubmit={(e) => void submit(e)} novalidate>
        <Show
          when={props.owner}
          fallback={
            <Field id="name" label={t("dns.owners.col.name")} error={errors().name} help={t("dns.owners.name_help", { zone: zoneName() })}>
              <input
                ref={first}
                id="dns-f-name"
                class="input mono"
                value={name()}
                spellcheck={false}
                autocomplete="off"
                aria-invalid={errors().name ? "true" : undefined}
                aria-describedby={describedBy("name", errors().name, t("dns.owners.name_help", { zone: zoneName() }))}
                data-testid="field-name"
                onInput={(e) => setName(e.currentTarget.value)}
              />
            </Field>
          }
        >
          {(owner) => (
            <>
              <p>{t("dns.owners.reassign_body")}</p>
              <dl class="kv">
                <dt>{t("dns.owners.col.name")}</dt>
                <dd class="mono">{relativeName(owner().name, zoneName())}</dd>
                <dt>{t("dns.owners.current")}</dt>
                <dd class="mono" data-testid="owner-current">
                  {owner().principal}
                </dd>
              </dl>
            </>
          )}
        </Show>
        <Field id="principal" label={t("dns.owners.col.principal")} error={errors().principal} help={t("dns.owners.principal_help")}>
          <input
            ref={(el) => {
              if (props.owner) first = el;
            }}
            id="dns-f-principal"
            class="input mono"
            value={principal()}
            spellcheck={false}
            autocomplete="off"
            aria-invalid={errors().principal ? "true" : undefined}
            aria-describedby={describedBy("principal", errors().principal, t("dns.owners.principal_help"))}
            data-testid="field-principal"
            onInput={(e) => setPrincipal(e.currentTarget.value)}
          />
        </Field>
        <Field id="sid" label={t("dns.owners.col.sid")} error={errors().sid} help={t("dns.owners.sid_help")}>
          <input
            id="dns-f-sid"
            class="input mono"
            value={sid()}
            spellcheck={false}
            autocomplete="off"
            aria-invalid={errors().sid ? "true" : undefined}
            aria-describedby={describedBy("sid", errors().sid, t("dns.owners.sid_help"))}
            data-testid="field-sid"
            onInput={(e) => setSid(e.currentTarget.value)}
          />
        </Field>
        <Show when={!props.owner}>
          <p class="muted">{t("dns.owners.assign_hold")}</p>
        </Show>
        <ErrorNotice error={error()} />
        <div class="dialog-actions">
          <button type="button" class="btn ghost" data-testid="form-cancel" onClick={() => props.onClose()}>
            {t("common.action.cancel")}
          </button>
          <button type="submit" class="btn primary" data-testid="form-submit" disabled={busy()}>
            {props.owner ? t("dns.owners.reassign") : t("dns.owners.assign")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

type Dialogs = { kind: "assign" } | { kind: "reassign"; owner: NameOwner } | { kind: "release"; owner: NameOwner };

export function OwnersTab(props: { zone: Zone }) {
  const zoneName = () => props.zone.name;
  const [nameText, setNameText] = createSignal("");
  const [name, setName] = createSignal("");
  const [ownerText, setOwnerText] = createSignal("");
  const [owner, setOwner] = createSignal("");
  const [dialog, setDialog] = createSignal<Dialogs | null>(null);
  const [busy, setBusy] = createSignal(false);
  const [releaseError, setReleaseError] = createSignal<unknown>();

  const timers: Record<string, ReturnType<typeof setTimeout>> = {};
  onCleanup(() => Object.values(timers).forEach(clearTimeout));
  const debounce = (key: string, text: string, set: (v: string) => void) => {
    clearTimeout(timers[key]);
    timers[key] = setTimeout(() => set(text.trim()), 200);
  };

  const keeps = () => keepsOwners(props.zone);
  const source = createListSource<NameOwner>({
    path: OWNERS_PATH as PathsWith<"get">,
    pathParams: () => ({ id: props.zone.id }),
    query: () => ({ name: name() ? canonical(qualify(name(), zoneName())) : undefined, owner: owner() || undefined }),
    rowId: (o) => `${o.scope}/${o.name}`,
    enabled: keeps,
    topics: ["dns"],
    relevant: (e) => e.objects.some((o) => o.kind === "zone" && o.id === props.zone.id),
  });
  const written = () => {
    setDialog(null);
    source.reload();
  };

  const release = async (row: NameOwner) => {
    setBusy(true);
    setReleaseError(undefined);
    try {
      const answer = await releaseOwner(props.zone.id, row.name);
      toast({ kind: "ok", title: t("dns.owners.released", { name: relativeName(row.name, zoneName()), count: answer.claimable }) });
      written();
    } catch (err) {
      setReleaseError(err);
    } finally {
      setBusy(false);
    }
  };

  const columns: Column<NameOwner>[] = [
    {
      id: "name",
      header: () => t("dns.owners.col.name"),
      width: 240,
      fixed: true,
      text: (o) => relativeName(o.name, zoneName()),
      render: (o) => <span class="mono">{relativeName(o.name, zoneName())}</span>,
    },
    { id: "principal", header: () => t("dns.owners.col.principal"), width: 240, text: (o) => o.principal, render: (o) => <span class="mono">{o.principal}</span> },
    {
      id: "sid",
      header: () => t("dns.owners.col.sid"),
      width: 260,
      text: (o) => o.sid ?? "",
      render: (o) => (
        <Show when={o.sid} fallback={<span class="muted">–</span>}>
          <span class="mono muted">{o.sid}</span>
        </Show>
      ),
    },
    {
      id: "how",
      header: () => t("dns.owners.col.how"),
      width: 120,
      text: (o) => t(`dns.owners.how.${o.how}`),
      render: (o) => (
        <span class="tag" data-testid="owner-how" data-kind={o.how} title={t(`dns.owners.how_hint.${o.how}`)}>
          {t(`dns.owners.how.${o.how}`)}
        </span>
      ),
    },
    { id: "since", header: () => t("dns.owners.col.since"), width: 140, text: (o) => formatDateTime(o.since), render: (o) => <TimeAgo at={o.since} /> },
    {
      id: "hold",
      header: () => t("dns.owners.col.hold"),
      width: 220,
      text: (o) => (o.hold_until ? t("dns.owners.held_until", { when: formatDateTime(o.hold_until) }) : ""),
      render: (o) => (
        <Show when={o.hold_until} fallback={<span class="muted">–</span>}>
          {(until) => (
            <span data-testid="owner-hold" class="tag discrepancy">
              {t("dns.owners.held_until", { when: formatDateTime(until()) })}
            </span>
          )}
        </Show>
      ),
    },
  ];

  const actions: RowAction<NameOwner>[] = [
    { id: "reassign", label: () => t("dns.owners.reassign"), hidden: () => !mayWriteDns(), run: (o) => setDialog({ kind: "reassign", owner: o }) },
    {
      id: "release",
      label: () => t("dns.owners.release"),
      danger: true,
      hidden: () => !mayWriteDns(),
      run: (o) => {
        setReleaseError(undefined);
        setDialog({ kind: "release", owner: o });
      },
    },
  ];

  const rowKey = (o: NameOwner) => relativeName(o.name, zoneName());
  const filtered = createMemo(() => name() !== "" || owner() !== "");

  return (
    <Show
      when={keeps()}
      fallback={
        <div class="page-body" data-testid="zone-owners">
          <Notice kind="info" role="status" testid="owners-off">
            {t("dns.owners.off")}
          </Notice>
        </div>
      }
    >
      <div class="dns-records" data-testid="zone-owners">
        <div class="filterbar" role="toolbar" aria-label={t("dns.owners.filter_label")} data-testid="filterbar">
          <label class="query">
            <Icon name="search" size="sm" />
            <input
              class="dns-search"
              value={nameText()}
              placeholder={t("dns.owners.filter_name")}
              aria-label={t("dns.owners.filter_name")}
              spellcheck={false}
              data-testid="filter-name"
              onInput={(e) => {
                setNameText(e.currentTarget.value);
                debounce("name", e.currentTarget.value, setName);
              }}
            />
          </label>
          <label class="query">
            <Icon name="search" size="sm" />
            <input
              class="dns-search"
              value={ownerText()}
              placeholder={t("dns.owners.filter_owner")}
              aria-label={t("dns.owners.filter_owner")}
              spellcheck={false}
              data-testid="filter-owner"
              onInput={(e) => {
                setOwnerText(e.currentTarget.value);
                debounce("owner", e.currentTarget.value, setOwner);
              }}
            />
          </label>
          <Show when={mayWriteDns()}>
            <span class="grow" />
            <button type="button" class="btn sm" data-testid="owner-assign" onClick={() => setDialog({ kind: "assign" })}>
              <Icon name="plus" size="sm" />
              {t("dns.owners.assign_action")}
            </button>
          </Show>
        </div>
        <div class="dns-list-body">
          <DataGrid
            id="dns-owners"
            label={t("dns.owners.label", { zone: zoneName() })}
            noSelection
            columns={columns}
            rows={source.rows()}
            rowId={(o) => `${o.scope}/${o.name}`}
            rowKey={rowKey}
            rowLabel={(o) => `${rowKey(o)} ${o.principal}`}
            loading={source.loading()}
            initial={source.initial()}
            hasMore={source.hasMore()}
            onLoadMore={source.loadMore}
            error={source.error()}
            onRetry={source.reload}
            flashed={(id) => source.flashed(id)}
            rowActions={actions}
            empty={
              <div class="empty" data-testid="dns-owners-empty">
                <h3>{filtered() ? t("grid.empty.filtered") : t("dns.owners.empty")}</h3>
                <Show when={!filtered()}>
                  <p class="muted">{t("dns.owners.empty_body")}</p>
                </Show>
              </div>
            }
          />
        </div>
        <Show when={dialog()} keyed>
          {(d) => {
            switch (d.kind) {
              case "assign":
                return <AssignDialog zone={props.zone} onClose={() => setDialog(null)} onDone={written} />;
              case "reassign":
                return <AssignDialog zone={props.zone} owner={d.owner} onClose={() => setDialog(null)} onDone={written} />;
              case "release":
                return (
                  <ConfirmDialog
                    title={t("dns.owners.release_title", { name: rowKey(d.owner) })}
                    testid="dialog-owner-release"
                    danger
                    busy={busy()}
                    confirmLabel={t("dns.owners.release")}
                    cancelLabel={t("common.action.cancel")}
                    body={
                      <>
                        <p>{t("dns.owners.release_body", { name: rowKey(d.owner), principal: d.owner.principal })}</p>
                        <p>{t("dns.owners.release_claimable")}</p>
                        <p>{t("dns.owners.release_reassign")}</p>
                        <Show when={releaseError()}>
                          {(err) => (
                            <Notice kind="bad" role="alert" testid="owner-release-error">
                              {errorMessage(err())}
                            </Notice>
                          )}
                        </Show>
                      </>
                    }
                    onClose={() => setDialog(null)}
                    onConfirm={() => void release(d.owner)}
                  />
                );
            }
          }}
        </Show>
      </div>
    </Show>
  );
}
