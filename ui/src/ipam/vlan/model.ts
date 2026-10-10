// Pure helpers of the VLAN provision dialog (docs/topology.md, section 8): the form values and
// their local checks, the request they build, the DHCP relay list, the key that makes a retry
// of one confirmation safe, and the words of the preview (reason of a manual step, mode of the
// network step, the steps of the job and the warnings of the network step). Nothing here
// touches the API or the DOM.
import type { PlanWarning } from "../../api/types";
import { t, tDynamic, type MessageKey } from "../../i18n";
import { formatIp, parseCidr, parseIp } from "../ip";
import { warningText } from "../plan/describe";
import type { ControllerMode, VlanProvisionRequest, VlanStepPreview } from "./api";

/** The most DHCP relay targets of a network (the server refuses more). */
export const MAX_RELAYS = 8;
/** The longest network name on the controller, in characters. */
export const MAX_NETWORK_NAME = 64;
const MAX_VID = 4094;
const MAX_VNI = 16_777_215;

/** How the network gets onto the switches and access points: the controller writes it, or a person. */
export type ControllerChoice = "auto" | "manual";

/** The values of the form. Texts stay texts until the request is built. */
export interface ProvisionForm {
  /** The existing VLAN to put onto the network; empty for a new VLAN. */
  vlanId: string;
  vid: string;
  name: string;
  site: string;
  vni: string;
  description: string;
  withPrefix: boolean;
  cidr: string;
  /** The VRF of the network; empty means the default VRF. */
  vrf: string;
  controller: ControllerChoice;
  /** The network controller when the preview listed several; empty means none chosen. */
  connector: string;
  networkName: string;
  dhcpRelay: string;
}

/** The form of a new VLAN, or of the existing VLAN to put onto the network. */
export function emptyForm(existing?: { id: string; vid: number; name: string }): ProvisionForm {
  return {
    vlanId: existing?.id ?? "",
    vid: existing ? String(existing.vid) : "",
    name: existing?.name ?? "",
    site: "",
    vni: "",
    description: "",
    withPrefix: false,
    cidr: "",
    vrf: "",
    controller: "auto",
    connector: "",
    networkName: "",
    dhcpRelay: "",
  };
}

// ---------------------------------------------------------------------------------
// DHCP relay addresses

export interface RelayList {
  /** The valid addresses in their canonical form, each once, in the order typed. */
  addresses: string[];
  /** What was typed and is not an IPv4 or IPv6 address. */
  invalid: string[];
}

/** Splits a list of addresses separated by commas, semicolons or white space. */
export function parseRelays(text: string): RelayList {
  const addresses: string[] = [];
  const invalid: string[] = [];
  for (const token of text.split(/[\s,;]+/)) {
    if (token === "") continue;
    const ip = parseIp(token);
    if (ip === null) {
      invalid.push(token);
      continue;
    }
    const canonical = formatIp(ip);
    if (!addresses.includes(canonical)) addresses.push(canonical);
  }
  return { addresses, invalid };
}

// ---------------------------------------------------------------------------------
// Local checks

/** Why a field is refused locally; the dialog turns it into a message with `problemText`. */
export type FieldProblem =
  | { code: "vid_invalid" }
  | { code: "name_required" }
  | { code: "vni_invalid" }
  | { code: "cidr_required" }
  | { code: "cidr_invalid" }
  | { code: "network_name_long" }
  | { code: "relay_invalid"; address: string }
  | { code: "relay_too_many" };

/** The fields that carry a local check, named as the form fields (`field-<name>`). */
export type FormErrors = Partial<Record<"vid" | "name" | "vni" | "cidr" | "network-name" | "dhcp-relay", FieldProblem>>;

/**
 * Checks the form like the VLAN form does (VLAN id 1 to 4094, a name, a VNI) and the network
 * (a CIDR without host bits, a network name of at most 64 characters, at most 8 relay addresses
 * that are IP addresses). An existing VLAN has no id or name to check.
 */
export function validateForm(form: ProvisionForm): FormErrors {
  const errors: FormErrors = {};
  if (form.vlanId === "") {
    const vid = form.vid.trim();
    if (!/^\d+$/.test(vid) || Number(vid) < 1 || Number(vid) > MAX_VID) errors.vid = { code: "vid_invalid" };
    if (form.name.trim() === "") errors.name = { code: "name_required" };
    const vni = form.vni.trim();
    if (vni !== "" && (!/^\d+$/.test(vni) || Number(vni) > MAX_VNI)) errors.vni = { code: "vni_invalid" };
  }
  if (form.withPrefix) {
    const cidr = form.cidr.trim();
    if (cidr === "") errors.cidr = { code: "cidr_required" };
    else if (!cidr.includes("/") || parseCidr(cidr) === null) errors.cidr = { code: "cidr_invalid" };
  }
  if ([...form.networkName.trim()].length > MAX_NETWORK_NAME) errors["network-name"] = { code: "network_name_long" };
  if (form.controller === "auto") {
    const relays = parseRelays(form.dhcpRelay);
    const first = relays.invalid[0];
    if (first !== undefined) errors["dhcp-relay"] = { code: "relay_invalid", address: first };
    else if (relays.addresses.length > MAX_RELAYS) errors["dhcp-relay"] = { code: "relay_too_many" };
  }
  return errors;
}

/** The translated message of a local problem. */
export function problemText(problem: FieldProblem): string {
  switch (problem.code) {
    case "vid_invalid":
      return t("ipam.vlan.vid_invalid");
    case "name_required":
      return t("ipam.tenancy.name_required");
    case "vni_invalid":
      return t("ipam.vlan.vni_invalid");
    case "cidr_required":
      return t("ipam.field.cidr_required");
    case "cidr_invalid":
      return t("ipam.field.cidr_invalid");
    case "network_name_long":
      return t("ipam.vlan.provision.network_name_long", { max: MAX_NETWORK_NAME });
    case "relay_invalid":
      return t("ipam.vlan.provision.relay_invalid", { address: problem.address });
    case "relay_too_many":
      return t("ipam.vlan.provision.relay_too_many", { max: MAX_RELAYS });
  }
}

// ---------------------------------------------------------------------------------
// The request

/**
 * The request of a provision from the form: an existing VLAN (`vlan`) or a new one (`create`),
 * the network prefix when asked for, `manual` for a network made by hand (no connector then,
 * the server refuses both), the network name and the relay addresses of an automatic step, and
 * the warning codes acknowledged so far. Empty optional values are left out.
 */
export function buildRequest(form: ProvisionForm, acknowledge: readonly string[] = []): VlanProvisionRequest {
  const request: VlanProvisionRequest = {};
  if (form.vlanId !== "") {
    request.vlan = form.vlanId;
  } else {
    const create: NonNullable<VlanProvisionRequest["create"]> = { vid: Number(form.vid.trim()), name: form.name.trim() };
    if (form.site !== "") create.site = form.site;
    if (form.vni.trim() !== "") create.vni = Number(form.vni.trim());
    if (form.description.trim() !== "") create.description = form.description.trim();
    request.create = create;
  }
  if (form.withPrefix) {
    const prefix: NonNullable<VlanProvisionRequest["prefix"]> = { cidr: form.cidr.trim() };
    if (form.vrf !== "") prefix.vrf = form.vrf;
    request.prefix = prefix;
  }
  if (form.controller === "manual") {
    request.manual = true;
  } else {
    if (form.connector !== "") request.connector = form.connector;
    const relays = parseRelays(form.dhcpRelay).addresses;
    if (relays.length > 0) request.dhcp_relay = relays;
  }
  if (form.networkName.trim() !== "") request.network_name = form.networkName.trim();
  if (acknowledge.length > 0) request.acknowledge = [...acknowledge];
  return request;
}

/** The `Idempotency-Key` of one confirmation, with the request it was made for. */
export interface ConfirmKey {
  body: string;
  key: string;
}

/**
 * The key to send with a request: the earlier one when the request is the same (a retry of this
 * one confirmation answers the first result), a new one when anything in it changed (the server
 * refuses another request under a used key).
 */
export function confirmKey(previous: ConfirmKey | null, request: VlanProvisionRequest, make: () => string): ConfirmKey {
  const body = JSON.stringify(request);
  return previous !== null && previous.body === body ? previous : { body, key: make() };
}

// ---------------------------------------------------------------------------------
// Words of the preview

const REASON: Readonly<Record<string, MessageKey>> = {
  "ipam.vlan.no_controller": "ipam.vlan.provision.reason.no_controller",
  "ipam.vlan.manual_requested": "ipam.vlan.provision.reason.manual_requested",
  "ipam.vlan.controller_ambiguous": "ipam.vlan.provision.reason.controller_ambiguous",
  "ipam.vlan.controller_read_only": "ipam.vlan.provision.reason.controller_read_only",
};

/** Why the network step is left to a person; a code this UI does not know reads as the general sentence. */
export function reasonText(code: string | null | undefined): string {
  const key = code ? REASON[code] : undefined;
  return t((key ?? "ipam.vlan.provision.reason.unknown") as "ipam.vlan.provision.reason.unknown");
}

/** The mode of the network step in one word. */
export function modeWord(mode: ControllerMode): string {
  switch (mode) {
    case "automatic":
      return t("ipam.vlan.provision.mode.automatic");
    case "unchanged":
      return t("ipam.vlan.provision.mode.unchanged");
    case "manual":
      return t("ipam.vlan.provision.mode.manual");
  }
}

/** What the mode of the network step means, in one sentence. */
export function modeHint(mode: ControllerMode): string {
  switch (mode) {
    case "automatic":
      return t("ipam.vlan.provision.mode_hint.automatic");
    case "unchanged":
      return t("ipam.vlan.provision.mode_hint.unchanged");
    case "manual":
      return t("ipam.vlan.provision.mode_hint.manual");
  }
}

/** What a step of the preview needs to be worded: the VLAN, whether it exists, the mode of the network step. */
export interface StepContext {
  vlan: { vid: number; name: string };
  existing: boolean;
  mode: ControllerMode;
}

/**
 * The text of a step of the job, by its kind (`ipam.intent`, `l2.network`, `l2.manual`,
 * `activate`), from the VLAN and the step's own values. A kind this UI does not know, or a step
 * without the values its text needs, reads as the server's English text.
 */
export function stepText(step: VlanStepPreview, context: StepContext): string {
  const p = step.params;
  const { vid, name } = context.vlan;
  switch (step.kind) {
    case "ipam.intent":
      if (context.existing) {
        return p.cidr ? t("ipam.vlan.provision.step.intent_prefix", { cidr: p.cidr, vid, name }) : step.text;
      }
      return p.cidr
        ? t("ipam.vlan.provision.step.intent_both", { cidr: p.cidr, vid, name })
        : t("ipam.vlan.provision.step.intent_vlan", { vid, name });
    case "l2.network":
      if (!p.name || !p.vid || !p.connector) return step.text;
      return context.mode === "unchanged"
        ? t("ipam.vlan.provision.step.network_check", { connector: p.connector, name: p.name, vid: p.vid })
        : t("ipam.vlan.provision.step.network", { connector: p.connector, name: p.name, vid: p.vid });
    case "l2.manual":
      return p.name && p.vid ? t("ipam.vlan.provision.step.manual", { name: p.name, vid: p.vid }) : step.text;
    case "activate":
      return t("ipam.vlan.provision.step.activate", { vid });
    default:
      return step.text;
  }
}

// ---------------------------------------------------------------------------------
// Warnings of the network step

interface NetworkWarning {
  key: MessageKey;
  /** The members of `params` the text needs. */
  params: readonly string[];
}

/** The warnings of the network step, which the server words in English only. */
const NETWORK_WARNINGS: Readonly<Record<string, NetworkWarning>> = {
  "ipam.vlan.controller_ambiguous": { key: "ipam.vlan.provision.warning.controller_ambiguous", params: [] },
  "ipam.vlan.controller_read_only": { key: "ipam.vlan.provision.warning.controller_read_only", params: ["connector"] },
  "ipam.vlan.network_changes": { key: "ipam.vlan.provision.warning.network_changes", params: ["vid"] },
};

/** Whether the warning is about the network step rather than the IPAM plan. */
export function isNetworkWarning(warning: Pick<PlanWarning, "code">): boolean {
  return warning.code in NETWORK_WARNINGS;
}

/** The IPAM plan's warnings and those of the network step, kept apart. */
export function splitWarnings(warnings: readonly PlanWarning[]): { plan: PlanWarning[]; network: PlanWarning[] } {
  return {
    plan: warnings.filter((w) => !isNetworkWarning(w)),
    network: warnings.filter(isNetworkWarning),
  };
}

/** The translated text of a warning of the network step; the plan's warnings read as everywhere else. */
export function networkWarningText(warning: PlanWarning): string {
  const known = NETWORK_WARNINGS[warning.code];
  const params = warning.params ?? {};
  if (!known || !known.params.every((name) => params[name] !== undefined)) return warningText(warning);
  return tDynamic(known.key, Object.fromEntries(known.params.map((name) => [name, params[name]]))) ?? warningText(warning);
}
