// The filter field of a grid: free text plus `field:value` terms ("mode:reserved
// tag:camera 192.0.2"), turned into the query parameters of a list endpoint. Only known
// field names make a term a filter, so an IPv6 address or a MAC with colons stays text.
// Values may be quoted ("name:\"lab rack\""). Free text goes to `q`.

export interface QueryField {
  /** The name typed before the colon (case-insensitive). */
  name: string;
  /** The query parameter (default: the name). */
  param?: string;
  /** Allowed values; another value makes the term invalid. */
  values?: readonly string[];
  /** Several terms of this field are joined with commas (`status=active,planned`). */
  multi?: boolean;
}

export interface ParsedQuery {
  /** Parameters for the list endpoint, `q` included when there is free text. */
  params: Record<string, string>;
  /** The free text. */
  text: string;
  /** Terms with a known field but a value it does not allow. */
  invalid: { field: string; value: string }[];
}

/** Splits on whitespace, keeping quoted parts together (`a:"b c"` is one term). */
export function tokenize(input: string): string[] {
  const out: string[] = [];
  let current = "";
  let quoted = false;
  for (const ch of input) {
    if (ch === '"') {
      quoted = !quoted;
      continue;
    }
    if (!quoted && /\s/.test(ch)) {
      if (current) out.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  if (current) out.push(current);
  return out;
}

export function parseQuery(input: string, fields: readonly QueryField[]): ParsedQuery {
  const byName = new Map(fields.map((f) => [f.name.toLowerCase(), f]));
  const params: Record<string, string> = {};
  const text: string[] = [];
  const invalid: ParsedQuery["invalid"] = [];
  for (const term of tokenize(input)) {
    const colon = term.indexOf(":");
    const field = colon > 0 ? byName.get(term.slice(0, colon).toLowerCase()) : undefined;
    if (!field) {
      text.push(term);
      continue;
    }
    const value = term.slice(colon + 1);
    if (value === "") continue;
    if (field.values && !field.values.includes(value)) {
      invalid.push({ field: field.name, value });
      continue;
    }
    const param = field.param ?? field.name;
    params[param] = field.multi && params[param] ? `${params[param]},${value}` : value;
  }
  const free = text.join(" ").trim();
  if (free) params.q = free;
  return { params, text: free, invalid };
}

/** Writes parameters back as terms (for a filter chip that edits the field). */
export function formatTerms(params: Readonly<Record<string, string | undefined>>): string {
  return Object.entries(params)
    .filter(([k, v]) => k !== "q" && v)
    .map(([k, v]) => (/\s/.test(v ?? "") ? `${k}:"${v}"` : `${k}:${v}`))
    .join(" ");
}
