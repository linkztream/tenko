// The rows of the mock's reconciliation view as one source for `GET /api/v1/ipam/reconcile` and the
// findings derived from them (findings-store.ts), so the Discovery list and the reconciliation view
// show the same rows. The seed (ipam-reconcile-model.ts) unless a test sets rows of its own with
// `setMockViewRows` (23 ghost addresses, say); a reset of the mock returns to the seed.
//
// The findings of the view's rows are on in the browser's mock (npm run dev:mock) and off in the
// unit tests unless a test turns them on (`setMockViewFindings`): the tests of the shell and the
// start page count the proposals, jobs and alarms of the seed, as they did before the view's rows
// became findings. A reset of the mock returns to the default of its environment.
import { onMockReset } from "./db";
import { seedRows, type ReconcileRow } from "./ipam-reconcile-model";
import { HOST_IDS, IPAM_IDS } from "./ipam/api";
import { RECONCILE_IDS } from "./reconcile-store";

let override: ReconcileRow[] | null = null;
let findingsDefault = false;
let findingsOn = false;

/** Turns the findings of the view's rows on or off until the next reset. */
export function setMockViewFindings(on: boolean): void {
  findingsOn = on;
}

/** The default of this environment: on in the browser's mock. */
export function setMockViewFindingsDefault(on: boolean): void {
  findingsDefault = on;
  findingsOn = on;
}

/** Whether the rows of the view are findings. */
export function mockViewFindings(): boolean {
  return findingsOn;
}

/** Replaces the rows of the view; null returns to the seed. */
export function setMockViewRows(rows: readonly ReconcileRow[] | null): void {
  override = rows === null ? null : structuredClone([...rows]);
}

onMockReset(() => {
  override = null;
  findingsOn = findingsDefault;
});

/** The rows of the view, in the order of the answer. */
export function mockViewRows(now = Date.now()): ReconcileRow[] {
  if (override) return override;
  return seedRows(
    {
      vrf: IPAM_IDS.vrf.default,
      prefix: IPAM_IDS.prefix.lan,
      host: (name) => HOST_IDS[name] ?? name,
      proposal: RECONCILE_IDS.proposal.mediaPc,
    },
    now,
  );
}
