// The security profile and the toggles TGL-01 to TGL-07 (SECURITY-PROFILES.md): what the
// profile is, which settings differ from it, which are weaker than Home, and the ways to
// change them. The shell banner follows every change (`updateBanner`).
import { createEffect, createSignal, For, Show } from "solid-js";
import { api } from "../api/client";
import { createLiveQuery } from "../api/live";
import { isApiError } from "../api/problem";
import type { SecuritySettingsView, SettingsPatch, ToggleState } from "../api/types";
import { updateBanner } from "../auth/session";
import { Icon } from "../components/Icon";
import { ErrorNotice, Notice } from "../components/Notice";
import { toast } from "../components/toast";
import { formatList, t } from "../i18n";
import { ProfileDialog } from "./ProfileDialog";
import { patchFor } from "./toggleEdit";
import { ToggleDialog } from "./ToggleDialog";
import { formatToggle, TOGGLE_TOTAL, TOGGLES, type ToggleDef } from "./toggles";
import "./settings.css";

interface Row {
  def: ToggleDef;
  state: ToggleState;
}

export default function SecurityPage() {
  const live = createLiveQuery<SecuritySettingsView>({
    topics: ["admin"],
    fetch: async (signal) => {
      const value = await api.get("/api/v1/settings/security", { signal });
      return { value, revision: value.revision ?? undefined };
    },
  });

  // The view on screen: the last answer of the server, from a read or from our own change.
  const [view, setView] = createSignal<SecuritySettingsView>();
  createEffect(() => {
    const state = live.value.state;
    if (state === "ready" || state === "refreshing") setView(live.value());
  });

  const [editing, setEditing] = createSignal<ToggleDef>();
  const [changingProfile, setChangingProfile] = createSignal(false);
  const [resetting, setResetting] = createSignal<string>();
  const [actionError, setActionError] = createSignal<unknown>(null);

  /** Sends a change against the revision on screen; the banner and the view follow the answer. */
  const save = async (patch: SettingsPatch): Promise<SecuritySettingsView> => {
    try {
      const next = await api.patch("/api/v1/settings/security", {
        body: patch,
        ifMatch: view()?.revision ?? undefined,
      });
      setView(next);
      updateBanner(next.banner);
      return next;
    } catch (err) {
      // Someone else changed the settings: read them again so the next try has the new revision.
      if (isApiError(err, "sys.store.precondition_failed")) live.refetch();
      throw err;
    }
  };

  const rows = (v: SecuritySettingsView): Row[] =>
    TOGGLES.flatMap((def) => {
      const state = v.toggles.find((s) => s.id === def.id);
      return state ? [{ def, state }] : [];
    });

  const reset = async (row: Row) => {
    setResetting(row.def.id);
    setActionError(null);
    try {
      await save(patchFor(row.def.setting, row.state.profile_default));
      toast({
        kind: "ok",
        title: t("settings.security.reset_done", { name: t(row.def.name) }),
        body: formatToggle(row.def.setting, row.state.profile_default),
      });
    } catch (err) {
      setActionError(err);
    } finally {
      setResetting(undefined);
    }
  };

  return (
    <div class="page-body">
      <Show
        when={view()}
        fallback={
          <Show
            when={live.value.error}
            fallback={
              <p class="muted" role="status">
                {t("common.loading")}
              </p>
            }
          >
            <ErrorNotice error={live.value.error} />
            <div>
              <button type="button" class="btn" onClick={() => live.refetch()}>
                {t("common.action.retry")}
              </button>
            </div>
          </Show>
        }
      >
        {(v) => (
          <>
            <ProfileSection view={v()} onChange={() => setChangingProfile(true)} />

            <section class="page-section" aria-labelledby="sec-toggles">
              <h2 id="sec-toggles">
                {t("settings.security.toggles.heading")}
                <span class="aside">{t("settings.security.toggles.range")}</span>
              </h2>
              <Show when={v().vault_has_operator_secrets}>
                <Notice kind="info" title={t("settings.security.vault.title")}>
                  {t("settings.security.vault.body")}
                </Notice>
              </Show>
              <ErrorNotice error={actionError()} />
              <div class="table-wrap">
                <table class="plain toggles" aria-label={t("settings.security.toggles.table")}>
                  <thead>
                    <tr>
                      <th scope="col">{t("settings.security.col.id")}</th>
                      <th scope="col">{t("settings.security.col.setting")}</th>
                      <th scope="col">{t("settings.security.col.value")}</th>
                      <th scope="col">{t("settings.security.col.profile")}</th>
                      <th scope="col">{t("settings.security.col.status")}</th>
                      <th scope="col" class="r">
                        <span class="sr-only">{t("settings.security.col.actions")}</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={rows(v())}>
                      {(row) => (
                        <tr
                          data-toggle={row.def.id}
                          classList={{ differs: row.state.deviates, weak: row.state.weaker_than_home }}
                        >
                          <td class="mono">{row.def.id}</td>
                          <td>{t(row.def.name)}</td>
                          <td>{formatToggle(row.def.setting, row.state.value)}</td>
                          <td class="muted">{formatToggle(row.def.setting, row.state.profile_default)}</td>
                          <td>
                            <Markers state={row.state} />
                          </td>
                          <td class="r actions">
                            <Show when={row.state.deviates}>
                              <button
                                type="button"
                                class="btn sm ghost"
                                disabled={resetting() === row.def.id}
                                aria-label={t("settings.security.reset_row", { name: t(row.def.name) })}
                                onClick={() => void reset(row)}
                              >
                                {t("settings.security.reset")}
                              </button>
                            </Show>
                            <button
                              type="button"
                              class="btn sm"
                              aria-label={t("settings.security.edit_row", { name: t(row.def.name) })}
                              onClick={() => setEditing(row.def)}
                            >
                              {t("common.action.edit")}
                            </button>
                          </td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
              </div>
              <p class="muted">{t("settings.security.more", { shown: TOGGLES.length, total: TOGGLE_TOTAL })}</p>
            </section>

            <Show when={editing()}>
              {(def) => <ToggleDialog view={v()} def={def()} save={save} onClose={() => setEditing(undefined)} />}
            </Show>
            <Show when={changingProfile()}>
              <ProfileDialog view={v()} save={save} onClose={() => setChangingProfile(false)} />
            </Show>
          </>
        )}
      </Show>
    </div>
  );
}

/** The profile in force, how far the settings are from it, and the loud states. */
function ProfileSection(props: { view: SecuritySettingsView; onChange: () => void }) {
  const profile = () => props.view.settings.profile;
  const lab = () => props.view.banner.lab || profile() === "lab";
  const weakNames = () =>
    TOGGLES.flatMap((def) =>
      props.view.toggles.some((s) => s.id === def.id && s.weaker_than_home) ? [t(def.name)] : [],
    );
  const deviations = () => props.view.toggles.filter((s) => s.deviates).length;

  return (
    <section class="page-section" aria-labelledby="sec-profile">
      <h2 id="sec-profile">{t("settings.security.profile.heading")}</h2>
      <div class="card profile-card">
        <div class="profile-main">
          <div class="profile-name">
            <strong>{t(`profile.${profile()}.name`)}</strong>
            <Show when={lab()}>
              <span class="deviation weak">
                <Icon name="alert" size="xs" />
                {t("settings.security.profile.lab_tag")}
              </span>
            </Show>
          </div>
          <p>{t(`profile.${profile()}.description`)}</p>
          <p class="muted" data-testid="deviation-count">
            {t("settings.security.profile.deviations", { count: deviations() })}
          </p>
        </div>
        <button type="button" class="btn" onClick={() => props.onChange()}>
          {t("settings.security.profile.change")}
        </button>
      </div>
      <Show when={lab()}>
        <Notice kind="bad" title={t("settings.security.profile.lab_title")}>
          {t("settings.security.profile.lab_body")}
        </Notice>
      </Show>
      <Show when={!lab() && weakNames().length > 0}>
        <Notice kind="bad" title={t("settings.security.marker.weak")}>
          {t("settings.security.profile.weak_body", { count: weakNames().length, names: formatList(weakNames()) })}
        </Notice>
      </Show>
    </section>
  );
}

/** The markers of a toggle: differs from the profile, weaker than Home, or follows the profile. */
function Markers(props: { state: ToggleState }) {
  return (
    <span class="markers">
      <Show
        when={props.state.deviates || props.state.weaker_than_home}
        fallback={
          <span class="muted follows">
            <Icon name="check" size="xs" />
            {t("settings.security.marker.follows")}
          </span>
        }
      >
        <Show when={props.state.deviates}>
          <span class="deviation">
            <Icon name="info" size="xs" />
            {t("settings.security.marker.differs")}
          </span>
        </Show>
        <Show when={props.state.weaker_than_home}>
          <span class="deviation weak">
            <Icon name="alert" size="xs" />
            {t("settings.security.marker.weak")}
          </span>
        </Show>
      </Show>
    </span>
  );
}
