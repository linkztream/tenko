// The state of the import mock: the uploads by identifier (staged for 24 hours) and the
// operator secrets earlier imports stored in the vault (kept as digests, so a second import of
// the same file reports them as already stored). Both are cleared when the mock resets.
import type { Analysis } from "./import-analysis";
import type { SourceFile } from "./import-cells";
import type { Mapping } from "./import-mapping";
import { onMockReset } from "./db";

export type ImportState = "uploaded" | "mapped" | "applying" | "applied" | "failed";

/** How long a staged upload lives. */
export const UPLOAD_TTL_MS = 24 * 60 * 60 * 1000;

export interface ImportRecord {
  id: string;
  /** The user who uploaded it; nobody else sees it. */
  owner: string;
  created: number;
  expires: number;
  files: SourceFile[];
  /** The analysis of the files and the suggested mapping. */
  analysis: Analysis;
  /** The user's mapping, null while the suggestion applies. */
  mapping: Mapping | null;
  state: ImportState;
  jobId: string | null;
  /** The Idempotency-Key of the apply request, so a retry gets the same job. */
  applyKey: string | null;
}

const imports = new Map<string, ImportRecord>();
const vault = new Map<string, string>();

onMockReset(() => {
  imports.clear();
  vault.clear();
});

/** The uploads of the mock by identifier. Read it in tests; the routes change it. */
export function importRecords(): Map<string, ImportRecord> {
  return imports;
}

/** The credential digests the vault holds, by host name. */
export function vaultDigests(): Map<string, string> {
  return vault;
}
