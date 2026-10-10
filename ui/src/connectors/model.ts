// The words and rules of the connectors views, as pure functions over `t`: capabilities,
// the supervised process state, the health of an instance in one word (with its glyph), the
// messages of settings problems (local checks and the host's field errors share the codes),
// and the secrets a purpose is offered.
import { ApiError } from "../api/problem";
import type { IconName } from "../components/Icon";
import { t, tDynamic } from "../i18n";
import type { Capability, ConnectorView, PluginInfo, SecretDecl, SupervisorStatus } from "./api";
import { fieldOfPath, type Problem } from "./schema";

/** The job titles and step summaries the server sends for connector jobs; the jobs views translate them. */
export const CONNECTOR_JOB_KEYS = ["connect.job.edit", "connect.job.run", "connect.job.write_preview", "connect.job.poll_preview"] as const;

export function capabilityWord(capability: Capability): string {
  return t(`connectors.capability.${capability}`);
}

export function processWord(state: SupervisorStatus["state"]): string {
  return t(`connectors.process.${state}`);
}

/**
 * The health of an instance in one word:
 * - `off`: disabled;
 * - `failing`: the plugin does not run (starting, backoff, circuit open, failed or stopped);
 * - `degraded`: it runs, but the remote system is degraded or unreachable, the last check
 *   failed, or the last run failed;
 * - `healthy`: everything that is known is fine.
 */
export type HealthWord = "healthy" | "degraded" | "failing" | "off";

export function connectorHealth(c: Pick<ConnectorView, "enabled" | "health" | "last_run">): HealthWord {
  if (!c.enabled) return "off";
  if (c.health.process.state !== "running") return "failing";
  const remote = c.health.remote?.health;
  if (c.health.remote_error || remote === "degraded" || remote === "unreachable" || c.last_run?.outcome === "failed") return "degraded";
  return "healthy";
}

export function healthWord(h: HealthWord): string {
  return t(`connectors.health.${h}`);
}

export function healthIcon(h: HealthWord): IconName {
  switch (h) {
    case "healthy":
      return "check";
    case "degraded":
      return "alert";
    case "failing":
      return "conflict";
    case "off":
      return "pause";
  }
}

/** The plugin of an instance, by name. */
export function pluginOf(plugins: readonly PluginInfo[] | undefined, name: string): PluginInfo | undefined {
  return plugins?.find((p) => p.name === name);
}

/** The plugin's own words for itself, or its name. */
export function pluginTitle(plugin: PluginInfo | undefined, name: string): string {
  return plugin?.manifest?.name ?? name;
}

// ---------------------------------------------------------------------------------
// Settings problems

/** The message of a local settings problem, in the words of the host's codes. */
export function problemMessage(p: Problem): string {
  const { min, max } = p.params;
  // Lengths and list sizes are counts (the messages agree in number); ranges are values.
  const counted = (base: "length" | "items") =>
    min && max
      ? t(`connectors.problem.${base}`, { min: Number(min), max: Number(max) })
      : max
        ? t(`connectors.problem.${base}_max`, { max: Number(max) })
        : t(`connectors.problem.${base}_min`, { min: Number(min ?? 0) });
  switch (p.kind) {
    case "length":
    case "items":
      return counted(p.kind);
    case "range":
      return min && max
        ? t("connectors.problem.range", { min, max })
        : max
          ? t("connectors.problem.range_max", { max })
          : t("connectors.problem.range_min", { min: min ?? "0" });
    case "type":
      return t("connectors.problem.type", { type: p.params.type ?? "" });
    case "enum":
      return t("connectors.problem.enum", { values: p.params.values ?? "" });
    case "pattern":
      return t("connectors.problem.pattern", { pattern: p.params.pattern ?? "" });
    case "format":
      return t("connectors.problem.format", { format: p.params.format ?? "" });
    default:
      return t(`connectors.problem.${p.kind}`);
  }
}

/** Local problems as messages by field path (an array's items under their own path). */
export function problemMessages(problems: readonly Problem[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const p of problems) if (!(p.path in out)) out[p.path] = problemMessage(p);
  return out;
}

/**
 * The field errors of a server answer as messages by path: `settings.*` for the settings
 * form, `secrets.<purpose>` for the secret choices, `name` and the intervals for the rest.
 * A code this UI has no words for shows the host's English detail.
 */
export function serverMessages(err: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!(err instanceof ApiError)) return out;
  for (const fe of err.fieldErrors) {
    const kind = fe.code.startsWith("connect.settings.") ? fe.code.slice("connect.settings.".length) : null;
    const own = kind ? tDynamic(`connectors.problem.${kind}`, { ...fe.params }) : tDynamic(`errors.${fe.code}`, { ...fe.params });
    const text = own && !own.startsWith("connectors.problem.") ? own : (fe.params?.detail ?? err.detail);
    if (!(fe.field in out)) out[fe.field] = text;
    const field = fieldOfPath(fe.field);
    if (!(field in out)) out[field] = text;
  }
  // Problems that name their field in the parameters (`connect.secret.*`, `connect.instance.*`).
  const field = err.params.field;
  if (field && !(field in out)) out[field] = tDynamic(`errors.${err.code}`, { ...err.params }) ?? err.detail;
  return out;
}

// ---------------------------------------------------------------------------------
// Secrets by purpose

export interface SecretOption {
  id: string;
  name: string;
  tags: readonly string[];
}

/** The secrets to offer for a purpose: those tagged with it first, then the rest, by name. */
export function secretsForPurpose(decl: SecretDecl, secrets: readonly SecretOption[]): { tagged: SecretOption[]; other: SecretOption[] } {
  const byName = [...secrets].sort((a, b) => a.name.localeCompare(b.name));
  return {
    tagged: byName.filter((s) => s.tags.includes(decl.purpose)),
    other: byName.filter((s) => !s.tags.includes(decl.purpose)),
  };
}
