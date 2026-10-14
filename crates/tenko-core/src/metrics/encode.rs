//! The `OpenMetrics` text encoder (`application/openmetrics-text; version=1.0.0`).
//!
//! Per family: `# TYPE`, `# HELP` and, with a unit, `# UNIT`, then its samples. Counter
//! samples carry `_total`; a histogram series is its cumulative `_bucket` samples with the
//! `le` bounds in seconds and `+Inf` last, then `_sum` (seconds) and `_count`. The text ends
//! with `# EOF`.

use std::fmt::Write as _;

use super::{Desc, Kind, Labels, Snapshot, Value};

/// Writes `snapshot` to `out` as `OpenMetrics` text, ending with `# EOF\n`.
pub fn encode(snapshot: &Snapshot, out: &mut String) {
    for family in &snapshot.families {
        let desc = family.desc;
        let name = desc.name;
        let _ = writeln!(out, "# TYPE {name} {}", desc.kind.as_str());
        out.push_str("# HELP ");
        out.push_str(name);
        out.push(' ');
        escape_help(desc.help, out);
        out.push('\n');
        if let Some(unit) = desc.unit {
            let _ = writeln!(out, "# UNIT {name} {unit}");
        }
        for series in &family.series {
            match &series.value {
                Value::Counter(total) => {
                    sample(out, name, "_total", desc, &series.labels, None);
                    let _ = writeln!(out, " {total}");
                }
                Value::Gauge(value) => {
                    sample(out, name, "", desc, &series.labels, None);
                    out.push(' ');
                    float(*value, out);
                    out.push('\n');
                }
                Value::Histogram(value) => {
                    let Kind::Histogram { bounds, per_second } = desc.kind else {
                        continue;
                    };
                    for (index, cumulative) in value.buckets.iter().enumerate() {
                        let mut le = String::new();
                        match bounds.get(index) {
                            Some(bound) => seconds(*bound, per_second, &mut le),
                            None => le.push_str("+Inf"),
                        }
                        sample(out, name, "_bucket", desc, &series.labels, Some(&le));
                        let _ = writeln!(out, " {cumulative}");
                    }
                    sample(out, name, "_sum", desc, &series.labels, None);
                    out.push(' ');
                    seconds(value.sum, per_second, out);
                    out.push('\n');
                    sample(out, name, "_count", desc, &series.labels, None);
                    let _ = writeln!(out, " {}", value.count());
                }
            }
        }
    }
    out.push_str("# EOF\n");
}

/// Writes the sample name and its label set, without the value.
fn sample(
    out: &mut String,
    name: &str,
    suffix: &str,
    desc: &Desc,
    labels: &Labels,
    le: Option<&str>,
) {
    out.push_str(name);
    out.push_str(suffix);
    if labels.is_empty() && le.is_none() {
        return;
    }
    out.push('{');
    let mut first = true;
    for (label, value) in desc.labels.iter().zip(labels.iter()) {
        if !first {
            out.push(',');
        }
        first = false;
        out.push_str(label);
        out.push_str("=\"");
        escape_label(value, out);
        out.push('"');
    }
    if let Some(le) = le {
        if !first {
            out.push(',');
        }
        out.push_str("le=\"");
        out.push_str(le);
        out.push('"');
    }
    out.push('}');
}

/// Escapes a label value: backslash, double quote and line feed.
fn escape_label(value: &str, out: &mut String) {
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
}

/// Escapes a help text: backslash, double quote and line feed.
fn escape_help(help: &str, out: &mut String) {
    escape_label(help, out);
}

/// Writes a float as `OpenMetrics` wants it: `+Inf`, `-Inf`, `NaN`, else the shortest
/// text that reads back as the same value.
fn float(value: f64, out: &mut String) {
    if value.is_nan() {
        out.push_str("NaN");
    } else if value == f64::INFINITY {
        out.push_str("+Inf");
    } else if value == f64::NEG_INFINITY {
        out.push_str("-Inf");
    } else {
        let _ = write!(out, "{value}");
    }
}

/// Writes `value / per_second` exactly in decimal, with at least one fractional digit
/// (`250` microseconds is `0.00025`, `1_000_000` is `1.0`). `per_second` is a power of ten.
pub(crate) fn seconds(value: u64, per_second: u64, out: &mut String) {
    let per_second = per_second.max(1);
    let whole = value / per_second;
    let fraction = value % per_second;
    let digits = per_second.ilog10() as usize;
    let _ = write!(out, "{whole}.");
    if digits == 0 || fraction == 0 {
        out.push('0');
        return;
    }
    let text = format!("{fraction:0digits$}");
    out.push_str(text.trim_end_matches('0'));
}
