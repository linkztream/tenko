//! A checker for ICU `MessageFormat` text as the web UI parses it.
//!
//! The UI formats messages with `intl-messageformat` over the syntax tree of
//! `@formatjs/icu-messageformat-parser`, called with `ignoreTag` (markup such as `<b>` is
//! literal text) and `requiresOtherClause`. This module follows that parser's grammar, so a
//! message it accepts parses in the browser:
//!
//! - text with arguments `{name}`, `{name, number[, style]}`, `{name, date[, style]}`,
//!   `{name, time[, style]}`, `{name, plural, [offset:n] selector {message} ...}`,
//!   `{name, selectordinal, ...}` and `{name, select, selector {message} ...}`; a plural or
//!   select needs an `other` option and no selector twice; inside a plural `#` is the number;
//! - an apostrophe starts quoted text only before `{`, `}`, `<`, `>` (and `#` inside a plural),
//!   `''` is one apostrophe, and quoted text ends at the next single apostrophe or at the end;
//! - a `}` outside any argument is text;
//! - argument names and selectors are runs of characters that are neither white space nor
//!   pattern syntax, as in the parser's fallback expression.
//!
//! Beyond the grammar the checker bounds what a pack may ask of the browser: the nesting of
//! plurals and selects, the options of one argument and the length of a message.

use std::collections::BTreeMap;

/// The deepest nesting of plural and select arguments.
pub const MAX_DEPTH: usize = 6;
/// The most options of one plural or select argument.
pub const MAX_OPTIONS: usize = 32;
/// The longest message, in characters.
pub const MAX_CHARS: usize = 4_000;

/// How a message uses an argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ArgKind {
    /// `{name}`: any text.
    Text,
    /// `{name, number}`, or the number of a plural.
    Number,
    /// `{name, date}` or `{name, time}`.
    Date,
    /// `{name, select, ...}`.
    Select,
}

/// What a valid message uses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MessageInfo {
    /// The arguments by name, with the most specific use (a name used as text and as a
    /// number is a number).
    pub args: BTreeMap<String, ArgKind>,
}

/// Why a message is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcuError {
    /// The character offset where the problem was found.
    pub offset: usize,
    /// English explanation.
    pub message: String,
}

impl std::fmt::Display for IcuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at offset {}", self.message, self.offset)
    }
}

impl std::error::Error for IcuError {}

/// Checks one message.
///
/// # Errors
///
/// [`IcuError`] for a syntax error, a plural or select without `other`, a repeated
/// selector, or a message over the limits of this module.
pub fn check(message: &str) -> Result<MessageInfo, IcuError> {
    let chars: Vec<char> = message.chars().collect();
    if chars.len() > MAX_CHARS {
        return Err(IcuError {
            offset: MAX_CHARS,
            message: format!("the message is longer than {MAX_CHARS} characters"),
        });
    }
    let mut parser = Parser {
        chars,
        pos: 0,
        info: MessageInfo::default(),
    };
    parser.message(0, Parent::None)?;
    Ok(parser.info)
}

/// The kind of argument a nested message sits in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Parent {
    None,
    Plural,
    Select,
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
    info: MessageInfo,
}

/// Whether the parser treats a character as white space (`_isWhiteSpace`).
fn is_white_space(c: char) -> bool {
    matches!(
        u32::from(c),
        9..=13 | 32 | 0x85 | 0x200e | 0x200f | 0x2028 | 0x2029
    )
}

/// Whether a character ends an identifier: white space or pattern syntax, by the ranges of
/// the parser's fallback expression.
fn ends_identifier(c: char) -> bool {
    let c = u32::from(c);
    matches!(
        c,
        0x09..=0x0d
            | 0x20..=0x2f
            | 0x3a..=0x40
            | 0x5b..=0x5e
            | 0x60
            | 0x7b..=0x7e
            | 0x85
            | 0xa0..=0xa7
            | 0xa9
            | 0xab
            | 0xac
            | 0xae
            | 0xb0
            | 0xb1
            | 0xb6
            | 0xbb
            | 0xbf
            | 0xd7
            | 0xf7
            | 0x1680
            | 0x2000..=0x200a
            | 0x2010..=0x2029
            | 0x202f..=0x203e
            | 0x2041..=0x2053
            | 0x2055..=0x205f
            | 0x2190..=0x245f
            | 0x2500..=0x2775
            | 0x2794..=0x2bff
            | 0x2e00..=0x2e7f
            | 0x3000..=0x3003
            | 0x3008..=0x3020
            | 0x3030
            | 0xfd3e
            | 0xfd3f
            | 0xfe45
            | 0xfe46
    )
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_at(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.pos + ahead).copied()
    }

    fn error<T>(&self, message: impl Into<String>) -> Result<T, IcuError> {
        Err(IcuError {
            offset: self.pos,
            message: message.into(),
        })
    }

    fn bump_space(&mut self) {
        while self.peek().is_some_and(is_white_space) {
            self.pos += 1;
        }
    }

    fn bump_if(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn identifier(&mut self) -> String {
        let start = self.pos;
        while self.peek().is_some_and(|c| !ends_identifier(c)) {
            self.pos += 1;
        }
        self.chars[start..self.pos].iter().collect()
    }

    fn use_arg(&mut self, name: String, kind: ArgKind) {
        let entry = self.info.args.entry(name).or_insert(kind);
        if *entry == ArgKind::Text {
            *entry = kind;
        }
    }

    /// A message up to the end, or up to the `}` that closes a nested one.
    fn message(&mut self, depth: usize, parent: Parent) -> Result<(), IcuError> {
        while let Some(c) = self.peek() {
            match c {
                '{' => self.argument(depth)?,
                '}' if depth > 0 => return Ok(()),
                '\'' => self.quote(parent),
                _ => self.pos += 1,
            }
        }
        Ok(())
    }

    /// An apostrophe: an escaped apostrophe, quoted text or a literal apostrophe.
    fn quote(&mut self, parent: Parent) {
        let starts_quote = match self.peek_at(1) {
            Some('\'') => {
                self.pos += 2;
                return;
            }
            Some('{' | '}' | '<' | '>') => true,
            Some('#') => parent == Parent::Plural,
            _ => false,
        };
        if !starts_quote {
            self.pos += 1;
            return;
        }
        // The apostrophe and the quoted character, then up to the next single apostrophe.
        self.pos += 2;
        while let Some(c) = self.peek() {
            self.pos += 1;
            if c == '\'' {
                if self.peek() == Some('\'') {
                    self.pos += 1;
                } else {
                    break;
                }
            }
        }
    }

    fn argument(&mut self, depth: usize) -> Result<(), IcuError> {
        self.pos += 1;
        self.bump_space();
        match self.peek() {
            None => return self.error("an argument is not closed with }"),
            Some('}') => return self.error("an argument has no name"),
            _ => {}
        }
        let name = self.identifier();
        if name.is_empty() {
            return self.error("an argument name is malformed");
        }
        self.bump_space();
        match self.peek() {
            None => self.error("an argument is not closed with }"),
            Some('}') => {
                self.pos += 1;
                self.use_arg(name, ArgKind::Text);
                Ok(())
            }
            Some(',') => {
                self.pos += 1;
                self.bump_space();
                if self.peek().is_none() {
                    return self.error("an argument is not closed with }");
                }
                self.options(depth, name)
            }
            Some(_) => self.error("an argument name is malformed"),
        }
    }

    fn close_argument(&mut self) -> Result<(), IcuError> {
        if self.bump_if('}') {
            Ok(())
        } else {
            self.error("an argument is not closed with }")
        }
    }

    fn options(&mut self, depth: usize, name: String) -> Result<(), IcuError> {
        let kind = self.identifier();
        match kind.as_str() {
            "" => self.error("an argument has no type after the comma"),
            "number" | "date" | "time" => {
                self.bump_space();
                if self.bump_if(',') {
                    self.bump_space();
                    let style = self.simple_style()?;
                    let style = style.trim_end();
                    if style.is_empty() {
                        return self.error("an argument style is empty");
                    }
                    if let Some(skeleton) = style.strip_prefix("::") {
                        let skeleton = skeleton.trim_start();
                        if kind == "number" {
                            let bad = skeleton
                                .split(is_white_space)
                                .filter(|token| !token.is_empty())
                                .any(|token| token.split('/').any(str::is_empty));
                            if bad {
                                return self.error("a number skeleton is malformed");
                            }
                        } else if skeleton.is_empty() {
                            return self.error("a date or time skeleton is empty");
                        }
                    }
                }
                self.close_argument()?;
                let arg = if kind == "number" {
                    ArgKind::Number
                } else {
                    ArgKind::Date
                };
                self.use_arg(name, arg);
                Ok(())
            }
            "plural" | "selectordinal" | "select" => {
                if depth + 1 > MAX_DEPTH {
                    return self.error(format!(
                        "plurals and selects are nested deeper than {MAX_DEPTH}"
                    ));
                }
                self.bump_space();
                if !self.bump_if(',') {
                    return self.error("a plural or select needs a comma before its options");
                }
                self.bump_space();
                let select = kind == "select";
                let mut first = self.identifier();
                if !select && first == "offset" {
                    if !self.bump_if(':') {
                        return self.error("a plural offset needs a colon");
                    }
                    self.bump_space();
                    self.integer()?;
                    self.bump_space();
                    first = self.identifier();
                }
                let parent = if select {
                    Parent::Select
                } else {
                    Parent::Plural
                };
                self.plural_options(depth, parent, first)?;
                self.close_argument()?;
                self.use_arg(
                    name,
                    if select {
                        ArgKind::Select
                    } else {
                        ArgKind::Number
                    },
                );
                Ok(())
            }
            _ => self.error(format!("an argument type `{kind}` is unknown")),
        }
    }

    /// The style of a number, date or time argument, up to its closing brace.
    fn simple_style(&mut self) -> Result<String, IcuError> {
        let start = self.pos;
        let mut nested = 0_usize;
        while let Some(c) = self.peek() {
            match c {
                '\'' => {
                    self.pos += 1;
                    match self.chars[self.pos..].iter().position(|&c| c == '\'') {
                        Some(n) => self.pos += n + 1,
                        None => return self.error("quoted text in a style is not closed"),
                    }
                }
                '{' => {
                    nested += 1;
                    self.pos += 1;
                }
                '}' if nested == 0 => break,
                '}' => {
                    nested -= 1;
                    self.pos += 1;
                }
                _ => self.pos += 1,
            }
        }
        Ok(self.chars[start..self.pos].iter().collect())
    }

    fn integer(&mut self) -> Result<i64, IcuError> {
        let negative = if self.bump_if('-') {
            true
        } else {
            self.bump_if('+');
            false
        };
        let start = self.pos;
        let mut value: i64 = 0;
        while let Some(digit) = self.peek().and_then(|c| c.to_digit(10)) {
            value = match value
                .checked_mul(10)
                .and_then(|v| v.checked_add(i64::from(digit)))
            {
                // Number.isSafeInteger in the browser.
                Some(v) if v < (1_i64 << 53) => v,
                _ => return self.error("a number is too large"),
            };
            self.pos += 1;
        }
        if self.pos == start {
            return self.error("a number is expected");
        }
        Ok(if negative { -value } else { value })
    }

    fn plural_options(
        &mut self,
        depth: usize,
        parent: Parent,
        first: String,
    ) -> Result<(), IcuError> {
        let mut selectors: Vec<String> = Vec::new();
        let mut selector = first;
        loop {
            if selector.is_empty() {
                let start = self.pos;
                if parent == Parent::Plural && self.bump_if('=') {
                    self.integer()?;
                    selector = self.chars[start..self.pos].iter().collect();
                } else {
                    break;
                }
            }
            if selectors.contains(&selector) {
                return self.error(format!("the selector `{selector}` appears twice"));
            }
            if selectors.len() >= MAX_OPTIONS {
                return self.error(format!("an argument has more than {MAX_OPTIONS} options"));
            }
            self.bump_space();
            if !self.bump_if('{') {
                return self.error(format!("the option `{selector}` needs a message in braces"));
            }
            self.message(depth + 1, parent)?;
            self.close_argument()?;
            selectors.push(selector);
            self.bump_space();
            selector = self.identifier();
        }
        if selectors.is_empty() {
            return self.error("a plural or select has no options");
        }
        if !selectors.iter().any(|s| s == "other") {
            return self.error("a plural or select needs an `other` option");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(message: &str) -> Vec<(String, ArgKind)> {
        check(message)
            .unwrap_or_else(|error| panic!("{message:?}: {error}"))
            .args
            .into_iter()
            .collect()
    }

    fn refused(message: &str) -> String {
        match check(message) {
            Ok(info) => panic!("{message:?} was accepted with {info:?}"),
            Err(error) => error.message,
        }
    }

    #[test]
    fn plain_text_and_arguments() {
        assert_eq!(args("Cancel"), vec![]);
        assert_eq!(args(""), vec![]);
        assert_eq!(
            args("Signed in as {name}"),
            vec![("name".to_owned(), ArgKind::Text)]
        );
        assert_eq!(
            args("{ count , number } of {total, number, ::compact-short} at {when, date, short}"),
            vec![
                ("count".to_owned(), ArgKind::Number),
                ("total".to_owned(), ArgKind::Number),
                ("when".to_owned(), ArgKind::Date),
            ]
        );
        assert_eq!(
            args("{retry_after} s, {0}"),
            vec![
                ("0".to_owned(), ArgKind::Text),
                ("retry_after".to_owned(), ArgKind::Text)
            ]
        );
    }

    #[test]
    fn plurals_and_selects() {
        assert_eq!(
            args("{count, plural, one {# item} other {# items in {name}}}"),
            vec![
                ("count".to_owned(), ArgKind::Number),
                ("name".to_owned(), ArgKind::Text)
            ]
        );
        assert_eq!(
            args("{n, plural, offset:1 =0 {none} =1 {{who}} other {# more}}"),
            vec![
                ("n".to_owned(), ArgKind::Number),
                ("who".to_owned(), ArgKind::Text)
            ]
        );
        assert_eq!(
            args(
                "{kind, select, host {Host} other {Other}} {n, selectordinal, one {#st} other {#th}}"
            ),
            vec![
                ("kind".to_owned(), ArgKind::Select),
                ("n".to_owned(), ArgKind::Number)
            ]
        );
    }

    #[test]
    fn quoting_follows_icu() {
        assert_eq!(
            args("It''s {name}"),
            vec![("name".to_owned(), ArgKind::Text)]
        );
        assert_eq!(args("'{name}' is literal"), vec![]);
        assert_eq!(args("Don't panic"), vec![]);
        assert_eq!(args("'{unterminated quote"), vec![]);
        assert_eq!(
            args("{n, plural, other {'#' is # }}"),
            vec![("n".to_owned(), ArgKind::Number)]
        );
        // Markup is text.
        assert_eq!(
            args("<b>{name}</b> <i>"),
            vec![("name".to_owned(), ArgKind::Text)]
        );
        // A closing brace outside an argument is text.
        assert_eq!(args("a } b"), vec![]);
    }

    #[test]
    fn syntax_errors_are_refused() {
        for message in [
            "{",
            "{name",
            "{}",
            "{ }",
            "{name,}",
            "{name, foo}",
            "{name, number,}",
            "{na me}",
            "{n, plural}",
            "{n, plural,}",
            "{n, plural, one {x}}",
            "{n, plural, one {x} one {y} other {z}}",
            "{n, plural, other x}",
            "{n, plural, other {x}",
            "{n, plural, offset 1 other {x}}",
            "{n, plural, =x {a} other {b}}",
            "{n, select, =1 {a} other {b}}",
            "{d, date, ::}",
            "{n, number, ::a//b}",
            "{n, number, 'x}",
        ] {
            let _ = refused(message);
        }
    }

    #[test]
    fn limits_are_enforced() {
        use std::fmt::Write as _;

        let mut deep = String::from("x");
        for level in 0..=MAX_DEPTH {
            deep = format!("{{v{level}, select, other {{{deep}}}}}");
        }
        assert!(refused(&deep).contains("nested"));
        let mut options = String::new();
        for i in 0..=MAX_OPTIONS {
            write!(options, "o{i} {{x}} ").expect("a string takes text");
        }
        assert!(refused(&format!("{{s, select, {options} other {{y}}}}")).contains("options"));
        assert!(refused(&"a".repeat(MAX_CHARS + 1)).contains("longer"));
    }
}
