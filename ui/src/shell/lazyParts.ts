// The parts of the shell that load after the first page (the findings store, the rail badges, the
// status item and their words). The shell registers each load here; the test setup awaits them
// after every test, so a chunk never resolves after the test environment is gone.
const pending = new Set<Promise<unknown>>();

/** Registers a load of a lazy part; answers it unchanged. */
export function trackLazyPart<T>(load: Promise<T>): Promise<T> {
  pending.add(load);
  const done = () => pending.delete(load);
  load.then(done, done);
  return load;
}

/** Resolves once every lazy part that has started loading is in (or failed). */
export async function lazyPartsSettled(): Promise<void> {
  while (pending.size > 0) await Promise.allSettled([...pending]);
}
