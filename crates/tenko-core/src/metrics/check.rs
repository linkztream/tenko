//! A strict checker of `OpenMetrics` text as [`super::encode`] writes it, for the tests of
//! the crates that serve metrics: `GET /metrics` must parse.

use std::collections::{BTreeMap, BTreeSet};

/// Checks `text` strictly: every family has a `# TYPE` before its samples and appears
/// once; `# HELP` and `# UNIT` belong to the current family and come before its samples; a
/// unit is the suffix of the family name; counters end in `_total`; a histogram series has
/// `le` buckets in ascending order, cumulative, ending in `+Inf` that equals its `_count`,
/// and a `_sum`; label syntax and values parse; no sample line appears twice; the text ends
/// with `# EOF\n`.
///
/// # Errors
///
/// The first violation, as English text.
pub fn check(text: &str) -> Result<(), String> {
    let body = text
        .strip_suffix("# EOF\n")
        .ok_or("the text does not end with # EOF")?;
    if body.contains("# EOF") {
        return Err("# EOF before the end".into());
    }
    let mut families: BTreeSet<String> = BTreeSet::new();
    let mut current: Option<(String, String)> = None;
    let mut sampled = false;
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut histograms: BTreeMap<(String, String), Histo> = BTreeMap::new();
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("# ") {
            let mut parts = rest.splitn(3, ' ');
            let keyword = parts.next().unwrap_or_default();
            let name = parts.next().ok_or(format!("no name: {line}"))?.to_owned();
            let arg = parts.next().ok_or(format!("no argument: {line}"))?;
            match keyword {
                "TYPE" => {
                    if !families.insert(name.clone()) {
                        return Err(format!("family {name} twice"));
                    }
                    if !["counter", "gauge", "histogram"].contains(&arg) {
                        return Err(format!("type {arg}"));
                    }
                    if arg == "counter" && name.ends_with("_total") {
                        return Err(format!("counter family {name} ends in _total"));
                    }
                    current = Some((name, arg.to_owned()));
                    sampled = false;
                }
                "HELP" | "UNIT" => {
                    let Some((family, _)) = &current else {
                        return Err(format!("{keyword} before TYPE"));
                    };
                    if *family != name || sampled {
                        return Err(format!("{keyword} out of place: {line}"));
                    }
                    if keyword == "UNIT" && !name.ends_with(&format!("_{arg}")) {
                        return Err(format!("unit {arg} is not the suffix of {name}"));
                    }
                }
                _ => return Err(format!("unknown comment: {line}")),
            }
            continue;
        }
        let Some((family, kind)) = &current else {
            return Err(format!("sample before TYPE: {line}"));
        };
        sampled = true;
        if !seen.insert(sample_key(line)?) {
            return Err(format!("sample twice: {line}"));
        }
        let (name, labels, value) = parse_sample(line)?;
        let suffix = name
            .strip_prefix(family.as_str())
            .ok_or(format!("{name} outside family {family}"))?;
        match (kind.as_str(), suffix) {
            ("counter", "_total") | ("gauge", "") => {}
            ("histogram", "_bucket" | "_sum" | "_count") => {
                let le = labels.iter().find(|(label, _)| label == "le");
                let rest: Vec<String> = labels
                    .iter()
                    .filter(|(label, _)| label != "le")
                    .map(|(label, value)| format!("{label}={value}"))
                    .collect();
                let entry = histograms
                    .entry((family.clone(), rest.join(",")))
                    .or_default();
                match suffix {
                    "_bucket" => {
                        let (_, le) = le.ok_or("bucket without le")?;
                        entry.buckets.push((parse_value(le)?, value));
                    }
                    "_sum" => entry.sum = true,
                    _ => entry.count = Some(value),
                }
                if suffix != "_bucket" && le.is_some() {
                    return Err(format!("le on {name}"));
                }
            }
            _ => return Err(format!("sample {name} does not fit {kind} {family}")),
        }
    }
    histograms
        .into_iter()
        .try_for_each(|((family, labels), histo)| histo.check(&format!("{family}{{{labels}}}")))
}

/// The samples of one histogram series.
#[derive(Default)]
struct Histo {
    buckets: Vec<(f64, f64)>,
    sum: bool,
    count: Option<f64>,
}

impl Histo {
    fn check(&self, what: &str) -> Result<(), String> {
        if self.buckets.is_empty() || !self.sum {
            return Err(format!("{what}: buckets and _sum needed"));
        }
        if !self.buckets.windows(2).all(|pair| pair[0].0 < pair[1].0) {
            return Err(format!("{what}: le not ascending"));
        }
        if !self.buckets.windows(2).all(|pair| pair[0].1 <= pair[1].1) {
            return Err(format!("{what}: buckets not cumulative"));
        }
        let (last_le, last) = self.buckets[self.buckets.len() - 1];
        if last_le != f64::INFINITY {
            return Err(format!("{what}: no +Inf bucket last"));
        }
        if self.count != Some(last) {
            return Err(format!("{what}: +Inf is not the count"));
        }
        Ok(())
    }
}

/// The name and labels of a sample line, as written.
fn sample_key(line: &str) -> Result<String, String> {
    let (key, _) = line.rsplit_once(' ').ok_or(format!("no value: {line}"))?;
    Ok(key.to_owned())
}

/// A parsed sample: name, labels and value.
type Sample = (String, Vec<(String, String)>, f64);

/// Splits a sample line into its name, its labels and its value.
fn parse_sample(line: &str) -> Result<Sample, String> {
    let name_end = line
        .find(['{', ' '])
        .ok_or(format!("malformed sample: {line}"))?;
    let name = &line[..name_end];
    if !valid_name(name) {
        return Err(format!("bad name {name}"));
    }
    let mut rest = &line[name_end..];
    let mut labels = Vec::new();
    if let Some(inner) = rest.strip_prefix('{') {
        let mut chars = inner.char_indices().peekable();
        let mut label = String::new();
        loop {
            let (_, c) = chars.next().ok_or("unterminated label set")?;
            match c {
                '}' => {
                    rest = &inner[chars.peek().map_or(inner.len(), |(at, _)| *at)..];
                    break;
                }
                ',' => {}
                '=' => {
                    if chars.next().map(|(_, c)| c) != Some('"') {
                        return Err(format!("label {label} without quote"));
                    }
                    let mut value = String::new();
                    loop {
                        let (_, c) = chars.next().ok_or("unterminated label value")?;
                        match c {
                            '"' => break,
                            '\\' => match chars.next().map(|(_, c)| c) {
                                Some('\\') => value.push('\\'),
                                Some('"') => value.push('"'),
                                Some('n') => value.push('\n'),
                                other => return Err(format!("bad escape {other:?}")),
                            },
                            '\n' => return Err("raw line feed in a value".into()),
                            c => value.push(c),
                        }
                    }
                    if !valid_name(&label) {
                        return Err(format!("bad label name {label}"));
                    }
                    labels.push((std::mem::take(&mut label), value));
                }
                c => label.push(c),
            }
        }
    }
    let value = rest
        .strip_prefix(' ')
        .ok_or(format!("no space before the value: {line}"))?;
    Ok((name.to_owned(), labels, parse_value(value)?))
}

fn parse_value(value: &str) -> Result<f64, String> {
    match value {
        "+Inf" => Ok(f64::INFINITY),
        "-Inf" => Ok(f64::NEG_INFINITY),
        "NaN" => Ok(f64::NAN),
        _ if value.contains("inf") || value.contains("nan") => Err(format!("value {value}")),
        _ => value.parse().map_err(|_| format!("value {value}")),
    }
}

fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == ':')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
}
