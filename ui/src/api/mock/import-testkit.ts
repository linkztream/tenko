// Helpers of the import tests. jsdom replaces the global FormData and File, and `fetch` sends a
// jsdom file under the name `blob`; the upload tests use Node's own FormData and File so the
// mock sees the name of the file, as a browser would send it. Both classes are found by
// parsing a tiny form with a Response, which is Node's.
import { vi } from "vitest";

let NodeFile: typeof File | null = null;

/** Makes `new FormData()` Node's for the rest of the test file (`releaseNodeFormData` undoes it). */
export async function useNodeFormData(): Promise<void> {
  const body = '--b\r\nContent-Disposition: form-data; name="f"; filename="f.txt"\r\n\r\nx\r\n--b--\r\n';
  const response = new Response(body, { headers: { "content-type": "multipart/form-data; boundary=b" } });
  const form = await response.formData();
  NodeFile = (form.get("f") as File).constructor as typeof File;
  vi.stubGlobal("FormData", form.constructor);
}

export function releaseNodeFormData(): void {
  vi.unstubAllGlobals();
  NodeFile = null;
}

/** A file as a browser's file picker gives it (call `useNodeFormData` first). */
export function testFile(name: string, content: string | Uint8Array): File {
  if (!NodeFile) throw new Error("call useNodeFormData() before creating test files");
  return new NodeFile([content as BlobPart], name);
}

/** A form with one part `files` per file. */
export function filesForm(files: readonly File[]): FormData {
  const form = new FormData();
  for (const file of files) form.append("files", file, file.name);
  return form;
}
