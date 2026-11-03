//! `$GENERATE range lhs [ttl] [class] type rhs` (the BIND extension): the lines of one
//! directive, made one at a time.
//!
//! The owner (`lhs`) and the rest of the record are templates: `$` is the iterator,
//! `${offset,width,base}` the iterator moved by `offset`, at least `width` digits wide, in
//! the base `d`, `o`, `x`, `X`, `n` or `N` (the last two are nibbles in reverse order,
//! separated by dots, for reverse zones); `\$` and `$$` are a `$`. A directive makes at most
//! `max` lines, and a width is at most 255, so a line is never more than a fixed multiple
//! of the directive's own length.

/// The widest `${offset,width,base}`.
const MAX_WIDTH: usize = 255;

/// The lines one directive makes.
#[derive(Debug)]
pub(super) struct Generate {
    lhs: String,
    rhs: String,
    next: Option<u64>,
    last: u64,
    step: u64,
    /// The directive's line.
    pub(super) line: usize,
}

impl Generate {
    /// The directive from its fields after `$GENERATE`: the range, the owner template and
    /// the rest of the record as written.
    ///
    /// # Errors
    ///
    /// A reason in English for a malformed range or one that makes more than `max` lines.
    pub(super) fn new(
        range: &str,
        lhs: &str,
        rhs: String,
        line: usize,
        max: u32,
    ) -> Result<Self, String> {
        let (bounds, step) = match range.split_once('/') {
            Some((bounds, step)) => (
                bounds,
                step.parse::<u64>()
                    .map_err(|_| "the step is not a number".to_owned())?,
            ),
            None => (range, 1),
        };
        let (low, high) = bounds
            .split_once('-')
            .ok_or_else(|| "the range is start-stop".to_owned())?;
        let first: u64 = low
            .parse()
            .map_err(|_| "the range start is not a number".to_owned())?;
        let last: u64 = high
            .parse()
            .map_err(|_| "the range stop is not a number".to_owned())?;
        if step == 0 || last < first {
            return Err("the range runs from start up to stop by a step above zero".to_owned());
        }
        let count = (last - first) / step + 1;
        if count > u64::from(max) {
            return Err(format!("the range makes {count} records, more than {max}"));
        }
        Ok(Self {
            lhs: lhs.to_owned(),
            rhs,
            next: Some(first),
            last,
            step,
            line,
        })
    }

    /// The next line, `None` after the last.
    ///
    /// # Errors
    ///
    /// A reason in English for a malformed template.
    pub(super) fn next_line(&mut self) -> Result<Option<String>, String> {
        let Some(value) = self.next else {
            return Ok(None);
        };
        self.next = value
            .checked_add(self.step)
            .filter(|next| *next <= self.last);
        let mut out = substitute(&self.lhs, value)?;
        out.push(' ');
        out.push_str(&substitute(&self.rhs, value)?);
        Ok(Some(out))
    }
}

/// Replaces `$` and `${offset,width,base}` with the iterator; `\$` and `$$` are a `$`.
fn substitute(template: &str, value: u64) -> Result<String, String> {
    let mut out = String::with_capacity(template.len() + 8);
    let mut rest = template;
    while let Some(index) = rest.find(['$', '\\']) {
        let (head, tail) = rest.split_at(index);
        out.push_str(head);
        if tail.starts_with("\\$") || tail.starts_with("$$") {
            out.push('$');
            rest = &tail[2..];
        } else if tail.starts_with('\\') {
            // Another escape stays for the record's own reader; the octet after the
            // backslash is copied with it, so `\\$` keeps its meaning.
            let mut chars = tail.chars();
            out.push(chars.next().unwrap_or('\\'));
            if let Some(next) = chars.next() {
                out.push(next);
            }
            rest = chars.as_str();
        } else if let Some(spec) = tail.strip_prefix("${") {
            let close = spec.find('}').ok_or("an unclosed ${")?;
            out.push_str(&modifier(&spec[..close], value)?);
            rest = &spec[close + 1..];
        } else {
            out.push_str(&value.to_string());
            rest = &tail[1..];
        }
    }
    out.push_str(rest);
    Ok(out)
}

/// One `${offset,width,base}`.
fn modifier(spec: &str, value: u64) -> Result<String, String> {
    let mut parts = spec.split(',');
    let offset: i64 = parts
        .next()
        .filter(|part| !part.is_empty())
        .map_or(Ok(0), str::parse)
        .map_err(|_| "the offset is not a number".to_owned())?;
    let width: usize = parts
        .next()
        .filter(|part| !part.is_empty())
        .map_or(Ok(0), str::parse)
        .map_err(|_| "the width is not a number".to_owned())?;
    if width > MAX_WIDTH {
        return Err(format!("the width is at most {MAX_WIDTH}"));
    }
    let base = parts.next().unwrap_or("d");
    if parts.next().is_some() {
        return Err("a modifier is ${offset,width,base}".to_owned());
    }
    let shifted = i64::try_from(value)
        .ok()
        .and_then(|value| value.checked_add(offset))
        .filter(|value| *value >= 0)
        .ok_or("the offset moves the value below zero")?;
    let shifted = u64::try_from(shifted).unwrap_or_default();
    Ok(match base {
        "d" => format!("{shifted:0width$}"),
        "o" => format!("{shifted:0width$o}"),
        "x" => format!("{shifted:0width$x}"),
        "X" => format!("{shifted:0width$X}"),
        "n" | "N" => {
            let hex = if base == "n" {
                format!("{shifted:0width$x}")
            } else {
                format!("{shifted:0width$X}")
            };
            let mut nibbles: Vec<String> = hex.chars().rev().map(String::from).collect();
            if width > 0 {
                nibbles.truncate(width);
            }
            nibbles.join(".")
        }
        _ => return Err(format!("the base {base} is not d, o, x, X, n or N")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(range: &str, lhs: &str, rhs: &str, max: u32) -> Result<Vec<String>, String> {
        let mut generate = Generate::new(range, lhs, rhs.to_owned(), 1, max)?;
        let mut out = Vec::new();
        while let Some(line) = generate.next_line()? {
            out.push(line);
        }
        Ok(out)
    }

    #[test]
    fn templates_expand() {
        assert_eq!(
            lines("1-5/2", "host-${0,3,d}", "IN A 198.51.100.$", 10),
            Ok(vec![
                "host-001 IN A 198.51.100.1".to_owned(),
                "host-003 IN A 198.51.100.3".to_owned(),
                "host-005 IN A 198.51.100.5".to_owned(),
            ])
        );
        assert_eq!(
            lines("10-10", "${0,2,n}", "PTR h\\$$$$.x\\.y.", 1),
            Ok(vec!["a.0 PTR h$$10.x\\.y.".to_owned()])
        );
        assert_eq!(
            lines("255-255", "${-5,4,X}.${1,,o}", "A 1", 1),
            Ok(vec!["00FA.400 A 1".to_owned()])
        );
    }

    #[test]
    fn malformed_directives_are_refused() {
        for (range, lhs) in [
            ("1-3", "${0,3"),
            ("1-3", "${0,x}"),
            ("1-3", "${0,3,q}"),
            ("1-3", "${-2}"),
            ("1-3", "${0,256}"),
            ("1-3", "${0,1,d,x}"),
            ("3-1", "$"),
            ("1-3/0", "$"),
            ("1", "$"),
            ("a-3", "$"),
            ("1-b", "$"),
            ("1-3/c", "$"),
            ("0-65536", "$"),
        ] {
            assert!(lines(range, lhs, "A 1", 65_536).is_err(), "{range} {lhs}");
        }
        assert!(lines("0-65535", "$", "A 1", 65_536).is_ok());
        let max = lines(&format!("{0}-{0}", u64::MAX), "$", "A 1", 1).expect("one line");
        assert_eq!(max.len(), 1);
    }
}
