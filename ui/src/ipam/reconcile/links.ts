// The address of the reconciliation view and its filters in the URL. Kept apart from the view so
// that the IPAM navigation and the host page link to it without loading the view.

/** `/ipam/reconcile`, narrowed by a prefix id, a host id or a kind when given. */
export function reconcilePath(query?: { prefix?: string | undefined; host?: string | undefined; kind?: string | undefined }): string {
  const sp = new URLSearchParams();
  for (const [name, value] of Object.entries(query ?? {})) if (value) sp.set(name, value);
  const qs = sp.toString();
  return qs ? `/ipam/reconcile?${qs}` : "/ipam/reconcile";
}
