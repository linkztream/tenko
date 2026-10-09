// One handler for every operation of the OpenAPI document that answers 501, like the
// backend does while an operation is a stub. They are registered after the happy paths,
// so an operation with a real mock handler never reaches its stub.
import { http, type HttpHandler } from "msw";
import { apiOperations } from "../generated/operations";
import { notImplemented } from "./reply";
import { mswPath } from "./route";

/** Sort key that puts static segments before parameters (`~` sorts after letters). */
function key(path: string): string {
  return path.replace(/\{[^}]+\}/g, "~");
}

// `/prefixes/tree` must be tried before `/prefixes/:id`.
const ordered = [...apiOperations].sort((a, b) => (key(a.path) < key(b.path) ? -1 : key(a.path) > key(b.path) ? 1 : 0));

export const stubs: HttpHandler[] = ordered.map((operation) =>
  http[operation.method](mswPath(operation.path), () =>
    notImplemented(operation.method.toUpperCase(), operation.path).toResponse(),
  ),
);
