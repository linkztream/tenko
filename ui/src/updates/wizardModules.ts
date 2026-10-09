// What the first-run wizard needs to know about the module choice (OPS-25): the DOM id of the
// first control, for the gate to point at, and the gate itself. The wizard's own gate table
// (src/setup/gates.ts) lists the messages of its other steps; this one is added by the
// controller, so the choice of modules follows the same rules: Continue is refused with a
// message in the footer and the control to fix gets the focus.
import type { Gate, GateMessage } from "../setup/gates";
import { MODULE_NAMES, type ModuleName } from "./modules";

/** The DOM id of the control the gate points at (the first module). */
export const MODULES_FOCUS = "wz-module-ipam";

/** The message of the gate: at least one module must stay selected. */
export const MODULES_GATE_MESSAGE = "setup.gate.modules_none";

/** The module choice of the wizard: every module is selected until the operator clears one. */
export function allModules(): Record<ModuleName, boolean> {
  return { ipam: true, dns: true, dhcp: true, discovery: true };
}

/** The modules that are ticked, in canonical order. */
export function chosenModules(modules: Record<ModuleName, boolean>): ModuleName[] {
  return MODULE_NAMES.filter((name) => modules[name]);
}

/** The gate of the roles step for a choice, or null while at least one module is selected. */
export function modulesGate(modules: Record<ModuleName, boolean>): Gate | null {
  if (chosenModules(modules).length > 0) return null;
  // The union of gate messages belongs to gates.ts; the message text is a regular key.
  return { message: MODULES_GATE_MESSAGE as unknown as GateMessage, focus: MODULES_FOCUS };
}
