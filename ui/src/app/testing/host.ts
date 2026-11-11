// The unit tests run in one time zone and one locale on every host (docs/testing/rules.md),
// so that a date, a number or a sort order does not depend on the machine: the gate's
// workstation is set to Swedish and Central European time, the hosted runners to American
// English and UTC.
//
// The time zone is set by vite.config.ts before the workers start (Node reads `TZ`); this
// file checks it. The locale cannot be set from outside on every platform (on Windows ICU
// reads the user's settings, not `LANG`), so the default locale of the `Intl` constructors
// and of the `toLocale*` and `localeCompare` methods is set here: a call that names a locale
// keeps it, a call that names none gets `TEST_LOCALE` instead of the host's. The first setup
// file, so it runs before any module of the application is loaded.

export const TEST_LOCALE = "en-US";
export const TEST_TIME_ZONE = "UTC";

const zone = new Intl.DateTimeFormat().resolvedOptions().timeZone;
if (zone !== TEST_TIME_ZONE) {
  throw new Error(`the unit tests run in ${TEST_TIME_ZONE}, this worker in ${zone}: start them through vitest with ui/vite.config.ts`);
}

const FIXED = Symbol.for("tenko.test.locale");

/** The locales argument with the test locale in place of "the host's default". */
function locales(value: unknown): unknown {
  return value === undefined || (Array.isArray(value) && value.length === 0) ? TEST_LOCALE : value;
}

type Patchable = Record<string, unknown> & { [FIXED]?: true };

if (!(Intl as unknown as Patchable)[FIXED]) {
  // The constructors: `new Intl.DateTimeFormat()` and the call without `new` alike; the
  // proxies keep their prototypes, static methods and `instanceof`.
  for (const name of ["DateTimeFormat", "NumberFormat", "Collator", "PluralRules", "RelativeTimeFormat", "ListFormat", "DisplayNames", "Segmenter"] as const) {
    const original = (Intl as unknown as Record<string, unknown>)[name];
    if (typeof original !== "function") continue;
    (Intl as unknown as Record<string, unknown>)[name] = new Proxy(original, {
      construct: (target, [first, ...rest], newTarget) => Reflect.construct(target as new (...a: unknown[]) => object, [locales(first), ...rest], newTarget),
      apply: (target, self, [first, ...rest]) => Reflect.apply(target as (...a: unknown[]) => unknown, self, [locales(first), ...rest]),
    });
  }
  // The methods that take the locale as their first argument.
  const methods: [object, string][] = [
    [Date.prototype, "toLocaleString"],
    [Date.prototype, "toLocaleDateString"],
    [Date.prototype, "toLocaleTimeString"],
    [Number.prototype, "toLocaleString"],
    [BigInt.prototype, "toLocaleString"],
    [Array.prototype, "toLocaleString"],
    [String.prototype, "toLocaleUpperCase"],
    [String.prototype, "toLocaleLowerCase"],
  ];
  for (const [proto, name] of methods) {
    const original = (proto as Record<string, unknown>)[name] as (...a: unknown[]) => unknown;
    Object.defineProperty(proto, name, {
      configurable: true,
      writable: true,
      value: function (this: unknown, first?: unknown, ...rest: unknown[]) {
        return original.call(this, locales(first), ...rest);
      },
    });
  }
  // `localeCompare(that, locales, options)` takes the locale second.
  const compare = String.prototype.localeCompare;
  Object.defineProperty(String.prototype, "localeCompare", {
    configurable: true,
    writable: true,
    value: function (this: string, that: string, first?: unknown, ...rest: unknown[]) {
      return compare.call(this, that, locales(first) as string, ...(rest as [Intl.CollatorOptions?]));
    },
  });
  (Intl as unknown as Patchable)[FIXED] = true;
}
