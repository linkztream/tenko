/**
 * Numbers that can grow are shown with SI suffixes and at most three significant digits
 * (982, 1.0K, 1.2K, 48K, 1.3M, 48M, 1.3G), so a tile never grows when a counter does. The
 * exact value belongs in the tooltip: see `exact` and `siTitle`.
 *
 * Locale-dependent parts (decimal separator, sign, digits) come from `Intl.NumberFormat`;
 * the formatters are cached per locale. A locale must be a valid BCP 47 tag, otherwise
 * `Intl` throws a RangeError. Nothing here touches the DOM.
 */

/** Suffix of unit `i` (1-based) is `SUFFIXES.charAt(i - 1)`; unit 0 has none. */
const SUFFIXES = "KMGTP";
const MAX_UNIT = SUFFIXES.length;

type FormatCache = Map<string, Intl.NumberFormat>;

const integerFormats: FormatCache = new Map();
const decimalFormats: FormatCache = new Map();
const exactFormats: FormatCache = new Map();

const INTEGER: Intl.NumberFormatOptions = {
  maximumFractionDigits: 0,
  useGrouping: false,
  // A value that rounds to zero is "0", never "-0".
  signDisplay: "negative",
};
const DECIMAL: Intl.NumberFormatOptions = {
  ...INTEGER,
  minimumFractionDigits: 1,
  maximumFractionDigits: 1,
};

function cached(cache: FormatCache, locale: string, options?: Intl.NumberFormatOptions): Intl.NumberFormat {
  let format = cache.get(locale);
  if (format === undefined) {
    format = new Intl.NumberFormat(locale, options);
    cache.set(locale, format);
  }
  return format;
}

/**
 * Compact form of `value`: the rounded integer below 1000, otherwise a mantissa and one of
 * K, M, G, T, P. A mantissa below 10 keeps one decimal ("1.0K", "9.9K"), from 10 up it is an
 * integer ("48K", "123K"). Rounding that reaches 1000 carries into the next unit, so 999.5
 * gives "1.0K" and 999 950 gives "1.0M". Negative values keep their sign. `null`,
 * `undefined`, NaN and infinities give an empty string.
 *
 * P is the last unit: from 999.5P (just under 1e18) the mantissa keeps growing ("1000P").
 * Counters are JS numbers and stay below 9.1P (`Number.MAX_SAFE_INTEGER`), so that range is
 * not reachable.
 */
export function si(value: number | null | undefined, locale = "en"): string {
  if (value == null || !Number.isFinite(value)) return "";

  let mantissa = Math.abs(value);
  let unit = 0;
  while (mantissa >= 1000 && unit < MAX_UNIT) {
    mantissa /= 1000;
    unit++;
  }

  let rounded = unit === 0 || mantissa >= 10 ? Math.round(mantissa) : Math.round(mantissa * 10) / 10;
  if (rounded >= 1000 && unit < MAX_UNIT) {
    // The mantissa is below 1000, so it can only have rounded up to exactly 1000.
    rounded = 1;
    unit++;
  }

  const format =
    unit > 0 && rounded < 10 ? cached(decimalFormats, locale, DECIMAL) : cached(integerFormats, locale, INTEGER);
  return format.format(value < 0 ? -rounded : rounded) + SUFFIXES.charAt(unit - 1);
}

/** The full value with the locale's grouping: "48,213" in English. For tooltips. */
export function exact(value: number, locale = "en"): string {
  return cached(exactFormats, locale).format(value);
}

/**
 * Tooltip text for a value shown through `si`: the exact value, followed by `unit` after a
 * space when given ("48,213 queries"). Empty when `si` shows nothing.
 */
export function siTitle(value: number | null | undefined, locale = "en", unit?: string): string {
  if (value == null || !Number.isFinite(value)) return "";
  const text = exact(value, locale);
  return unit ? `${text} ${unit}` : text;
}
