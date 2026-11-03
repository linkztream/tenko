//! The tokenizer: a zone file as entries of tokens (RFC 1035, section 5.1).
//!
//! An entry ends at a line end outside parentheses and quotes. Space, tab and carriage
//! return separate tokens; `;` starts a comment up to the line end; `(` and `)` group lines
//! and separate tokens; `"` starts a quoted token that ends at the next unescaped `"` (and
//! may span lines); a backslash escapes the octet after it in either kind of token. A
//! token is kept as the offsets of its text in the source, so every token's line is the
//! source's own line.
//!
//! The source is walked octet by octet with checked indexing. A token starts and ends next
//! to an ASCII octet (a separator, a quote) or at an end of the source, which are always
//! character boundaries, so slicing the source at them cannot fall inside a character.

/// One token of an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Token {
    /// The offset of its text (after the opening quote of a quoted token).
    pub(super) start: usize,
    /// The offset after its text (at the closing quote of a quoted token).
    pub(super) end: usize,
    /// The line it starts on, from 1.
    pub(super) line: usize,
    /// Whether it was quoted.
    pub(super) quoted: bool,
    /// Whether it follows the previous token without a separator (`key="value"`).
    pub(super) glued: bool,
}

impl Token {
    /// The token's text: its content without the quotes, escapes not yet decoded.
    pub(super) fn text(self, src: &str) -> &str {
        src.get(self.start..self.end).unwrap_or_default()
    }

    /// The token as written, with its quotes.
    pub(super) fn raw(self, src: &str) -> &str {
        let (start, end) = if self.quoted {
            (self.start.saturating_sub(1), self.end + 1)
        } else {
            (self.start, self.end)
        };
        src.get(start..end).unwrap_or_default()
    }
}

/// An entry: its tokens and whether its first line starts with white space (the owner is
/// then the previous one).
#[derive(Debug, Default)]
pub(super) struct Entry {
    /// The tokens, at least one.
    pub(super) tokens: Vec<Token>,
    /// Whether the entry's first line starts with white space.
    pub(super) indented: bool,
}

/// A position in a source.
#[derive(Debug, Clone)]
pub(super) struct Lexer {
    pos: usize,
    line: usize,
    line_start: bool,
}

/// A syntax error of the tokenizer: the line and the reason.
pub(super) type LexError = (usize, &'static str);

/// The most tokens of one entry: the data of a record is at most 65,535 octets, which is
/// 131,070 hex digits one to a token, so a longer entry cannot be a record and is refused
/// before its tokens take more memory (32 octets each).
pub(super) const MAX_TOKENS: usize = 1 << 18;

fn push(entry: &mut Entry, token: Token) -> Result<(), LexError> {
    if entry.tokens.len() >= MAX_TOKENS {
        return Err((token.line, "an entry has more than 262144 tokens"));
    }
    entry.tokens.push(token);
    Ok(())
}

impl Lexer {
    /// A lexer at the start of a source whose first line is `line`.
    pub(super) fn new(line: usize) -> Self {
        Self {
            pos: 0,
            line,
            line_start: true,
        }
    }

    /// Reads the next entry into `entry`; `false` at the end of the source.
    ///
    /// # Errors
    ///
    /// The line and reason of an unclosed quote or parenthesis, or of a closing
    /// parenthesis without an opening one.
    pub(super) fn entry(&mut self, src: &str, entry: &mut Entry) -> Result<bool, LexError> {
        let bytes = src.as_bytes();
        entry.tokens.clear();
        entry.indented = false;
        let mut parens = 0usize;
        let mut opened = 0usize;
        let mut glue = false;
        loop {
            let Some(&byte) = bytes.get(self.pos) else {
                if parens > 0 {
                    return Err((
                        opened,
                        "the parenthesis opened on this line is not closed by the end of the file",
                    ));
                }
                return Ok(!entry.tokens.is_empty());
            };
            match byte {
                b' ' | b'\t' | b'\r' => {
                    if self.line_start && entry.tokens.is_empty() {
                        entry.indented = true;
                    }
                    self.pos += 1;
                    glue = false;
                }
                b'\n' => {
                    self.pos += 1;
                    self.line += 1;
                    self.line_start = true;
                    glue = false;
                    if parens == 0 {
                        if !entry.tokens.is_empty() {
                            return Ok(true);
                        }
                        entry.indented = false;
                    }
                }
                b';' => {
                    self.line_start = false;
                    while bytes.get(self.pos).is_some_and(|byte| *byte != b'\n') {
                        self.pos += 1;
                    }
                    glue = false;
                }
                b'(' => {
                    self.line_start = false;
                    if parens == 0 {
                        opened = self.line;
                    }
                    parens += 1;
                    self.pos += 1;
                    glue = false;
                }
                b')' => {
                    self.line_start = false;
                    if parens == 0 {
                        return Err((self.line, "a closing parenthesis without an opening one"));
                    }
                    parens -= 1;
                    self.pos += 1;
                    glue = false;
                }
                b'"' => {
                    self.line_start = false;
                    let token = self.quoted(bytes, glue)?;
                    push(entry, token)?;
                    glue = true;
                }
                _ => {
                    self.line_start = false;
                    let token = self.unquoted(bytes, glue);
                    push(entry, token)?;
                    glue = true;
                }
            }
        }
    }

    /// A quoted token from the quote at the position: up to the next unescaped quote,
    /// across lines.
    fn quoted(&mut self, bytes: &[u8], glued: bool) -> Result<Token, LexError> {
        let line = self.line;
        let start = self.pos + 1;
        let mut index = start;
        loop {
            match bytes.get(index) {
                None => {
                    return Err((
                        line,
                        "the quote opened on this line is not closed by the end of the file",
                    ));
                }
                Some(b'"') => break,
                Some(b'\\') => {
                    index += 1;
                    if bytes.get(index) == Some(&b'\n') {
                        self.line += 1;
                    }
                    if index < bytes.len() {
                        index += 1;
                    }
                }
                Some(b'\n') => {
                    self.line += 1;
                    index += 1;
                }
                Some(_) => index += 1,
            }
        }
        self.pos = index + 1;
        Ok(Token {
            start,
            end: index,
            line,
            quoted: true,
            glued,
        })
    }

    /// An unquoted token from the position: up to the next separator that is not
    /// escaped. A backslash before a line end or at the end of the source stays in the
    /// token, whose decoding refuses it.
    fn unquoted(&mut self, bytes: &[u8], glued: bool) -> Token {
        let start = self.pos;
        let mut index = start;
        loop {
            match bytes.get(index) {
                None | Some(b' ' | b'\t' | b'\r' | b'\n' | b'(' | b')' | b';' | b'"') => break,
                Some(b'\\') => {
                    index += 1;
                    if bytes.get(index).is_some_and(|byte| *byte != b'\n') {
                        index += 1;
                    }
                }
                Some(_) => index += 1,
            }
        }
        self.pos = index;
        Token {
            start,
            end: index,
            line: self.line,
            quoted: false,
            glued,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A token's text, line, quoting and glue.
    type Seen = (String, usize, bool, bool);

    fn entries(src: &str) -> Result<Vec<(bool, Vec<Seen>)>, LexError> {
        let mut lexer = Lexer::new(1);
        let mut entry = Entry::default();
        let mut out = Vec::new();
        while lexer.entry(src, &mut entry)? {
            out.push((
                entry.indented,
                entry
                    .tokens
                    .iter()
                    .map(|token| {
                        (
                            token.text(src).to_owned(),
                            token.line,
                            token.quoted,
                            token.glued,
                        )
                    })
                    .collect(),
            ));
        }
        Ok(out)
    }

    fn texts(src: &str) -> Vec<Vec<String>> {
        entries(src)
            .expect("lexes")
            .into_iter()
            .map(|(_, tokens)| tokens.into_iter().map(|token| token.0).collect())
            .collect()
    }

    #[test]
    fn entries_end_at_line_ends_outside_parentheses() {
        assert_eq!(
            texts("a 1 IN A 192.0.2.1\n\n; comment\nb TXT ( \"x y\" ; c\n  z )\r\nc A 1"),
            [
                vec!["a", "1", "IN", "A", "192.0.2.1"],
                vec!["b", "TXT", "x y", "z"],
                vec!["c", "A", "1"],
            ]
        );
        let lines: Vec<usize> = entries("a TXT (\n\"b\nc\" d\n)\ne A 1\n")
            .expect("lexes")
            .into_iter()
            .flat_map(|(_, tokens)| tokens.into_iter().map(|token| token.1))
            .collect();
        assert_eq!(lines, [1, 1, 2, 3, 5, 5, 5]);
    }

    #[test]
    fn escapes_keep_separators_inside_tokens() {
        assert_eq!(
            texts("a\\ b\\;c\\(d \"q\\\"r\" e\\"),
            [vec!["a\\ b\\;c\\(d", "q\\\"r", "e\\"]]
        );
        let (_, tokens) = &entries("x key=\"a b\" k2=v\"w\"").expect("lexes")[0];
        let glued: Vec<bool> = tokens.iter().map(|token| token.3).collect();
        assert_eq!(glued, [false, false, true, false, true]);
    }

    #[test]
    fn indentation_marks_an_omitted_owner() {
        let indented: Vec<bool> = entries("a A 1\n  A 2\n\t\n;x\n\tA 3\n(\n A 4 )\n")
            .expect("lexes")
            .into_iter()
            .map(|(indented, _)| indented)
            .collect();
        assert_eq!(indented, [false, true, true, true]);
    }

    #[test]
    fn unbalanced_input_is_refused_with_its_line() {
        assert_eq!(
            entries("a A 1\nb TXT ( \"x\"\n").map(|_| ()),
            Err((
                2,
                "the parenthesis opened on this line is not closed by the end of the file"
            ))
        );
        assert_eq!(
            entries("a A 1\n\nb TXT \"x\n\n").map(|_| ()),
            Err((
                3,
                "the quote opened on this line is not closed by the end of the file"
            ))
        );
        assert_eq!(
            entries("a A 1 )").map(|_| ()),
            Err((1, "a closing parenthesis without an opening one"))
        );
        // A quoted parenthesis or one in a comment does not count.
        assert!(entries("a TXT \"(\" ; (\n").is_ok());
    }

    #[test]
    fn multibyte_text_is_never_cut() {
        assert_eq!(texts("å\\é \"ü\\\"\" ;ö"), [vec!["å\\é", "ü\\\""]]);
        for cut in 0..=12 {
            let src = "aé\"é\\é\" é";
            let src = src.get(..cut).unwrap_or(src);
            let _ = entries(src);
        }
    }
}
