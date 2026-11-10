//! Zone files (RFC 1035, section 5): the reader of the import and the writer of the export
//! (MIG-15), both Tenko's own code.
//!
//! # Reading
//!
//! [`Reader`] reads a file one entry at a time and yields one record with its line, or a
//! [`Loss`] for a record the import cannot take. The tokenizer (`lexer`) follows
//! RFC 1035: blank lines and `;` comments, `(` `)` across lines, quoted strings, `\X` and
//! `\DDD` escapes. An entry is `owner [ttl] [class] type data`: the owner `@` is the
//! origin, a relative name is completed with the origin, an entry whose line starts with
//! white space has the previous owner; the TTL and the class come in either order and are
//! optional. The TTL is a number of seconds or a duration with BIND's units (`1h30m`, `2d`,
//! `1w`), and a record without one takes `$TTL`, else the last TTL given, else 3600 s. The
//! class is IN (another class is a loss); the type is its mnemonic (any case) or `TYPEnnn`.
//!
//! `$ORIGIN` and `$TTL` are honored (the zone apex is the first origin); `$INCLUDE` is
//! refused, since the import reads one uploaded file; `$GENERATE` (the BIND extension) is
//! expanded one line at a time, at most
//! [`ZoneConfig::max_generate`](super::ZoneConfig::max_generate) records per directive,
//! with `$`, `${offset,width,base}` (bases `d`, `o`, `x`, `X`, `n`, `N`), `\$` and `$$`;
//! the lines it makes carry the directive's line.
//!
//! The data of every type the model holds is read in its presentation form (`parse`,
//! `svcb`), and so is that of a few types the model keeps opaque; every type also reads
//! the generic form of RFC 3597 (`\# length hex`). The parsed data goes through the
//! model's own check ([`Rdata::from_wire`]).
//!
//! **The Windows dialect** (WP13.4, MIG-07). A file that the Windows DNS Server wrote
//! (`dnscmd /ZoneExport`, or the `%SystemRoot%System32dns*.dns` file of a file-backed
//! zone) marks each record that carries an aging timestamp with `[AGE:n]` after its owner
//! name, `n` the hours since 1601-01-01 UTC: those are the records Windows calls dynamic,
//! registered by a client or a controller. Read with [`Dialect::Windows`], the mark is taken
//! (one per record, digits only, at most ten) and the record is [`FileRecord::aged`] when
//! `n` is above zero; WINS and WINS-R records, which Tenko does not serve (CON-12), are
//! losses rather than syntax errors. Read as [`Dialect::Rfc1035`], the default, a mark is
//! the syntax error it is in any other zone file.
//!
//! A syntax error stops the read with `dns.zonefile.invalid`, the line of the token where
//! it was found and a reason; so does a quote or a parenthesis still open at the end of
//! the file (with the line that opened it). The losses: a record of a class other than
//! IN, an owner outside the zone, a name or data the model refuses (outside the name
//! character set of the model, an invalid length), a record of a type whose data is
//! written in a form the reader does not know (only the generic form is read for it), and
//! a record that breaks a rule of its type.
//!
//! Hardening: the reader indexes the text only within checked bounds and slices it only at
//! ASCII separators; names, labels, character strings and record data keep their limits
//! (255, 63, 255 and 65,535 octets); nothing recurses on the input; what it allocates is
//! bounded by the length of the text (the reader keeps one copy of it, one entry's tokens
//! and one `$GENERATE` line at a time).
//!
//! # Writing
//!
//! [`header`] writes `$ORIGIN` and `$TTL`; [`write_rrset`] writes one RRset, one line per
//! record: the owner relative to the apex (`@` for the apex), the TTL, `IN`, the type and
//! the data in presentation format (`present`), its records in canonical order (by wire
//! form). The export writes the apex SOA first, then every RRset in key order, which is the
//! canonical name order of RFC 4034, types ascending, so the same data always gives the
//! same bytes.

mod generate;
mod lexer;
mod parse;
mod present;
mod svcb;
mod text;
mod types;

use std::fmt::Write as _;

use tenko_core::dns::{DnsName, Rdata, RrSet, Rtype};

use super::{ZoneError, ZoneResult, relative_name};
use generate::Generate;
use lexer::{Entry, LexError, Lexer};
use parse::Fields;

/// The code of a loss: a record of another class than IN.
pub const LOSS_CLASS: &str = "dns.zonefile.class";
/// The code of a loss: a record whose owner is outside the zone.
pub const LOSS_OUTSIDE: &str = "dns.zonefile.outside_zone";
/// The code of a loss: a name or data the model refuses.
pub const LOSS_DATA: &str = "dns.zonefile.data";
/// The code of a loss: an RRset that breaks a rule of its type or conflicts with others.
pub const LOSS_RULE: &str = "dns.zonefile.rule";
/// The code of a loss: an RRset of another origin that the import does not replace.
pub const LOSS_ORIGIN: &str = "dns.zonefile.origin";
/// The code of a loss: a record the file repeats.
pub const LOSS_DUPLICATE: &str = "dns.zonefile.duplicate";
/// The code of a loss: an SOA record that is not the apex SOA, or a second one.
pub const LOSS_SOA: &str = "dns.zonefile.soa";
// WP13.4: the Windows dialect.
/// The code of a loss: a WINS or WINS-R record of a Windows file, which is not served.
pub const LOSS_WINS: &str = "dns.zonefile.wins";

/// The most digits of the hours of an `[AGE:n]` mark (`u32::MAX` hours is far past 2400).
const MAX_AGE_DIGITS: usize = 10;

/// The dialect a zone file is read in.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dialect {
    /// RFC 1035 with BIND's `$GENERATE` and TTL units: every zone file.
    #[default]
    Rfc1035,
    /// A file the Windows DNS Server wrote: the `[AGE:n]` marks of its dynamic records are
    /// read, and its WINS and WINS-R records are losses.
    Windows,
}

/// The hours of an `[AGE:n]` mark, or `None` when the token is no mark.
fn age_mark(token: &str) -> Option<Result<u32, String>> {
    let inner = token.strip_prefix('[')?.strip_suffix(']')?;
    let (label, hours) = inner.split_once(':')?;
    if !label.eq_ignore_ascii_case("AGE") {
        return None;
    }
    if hours.is_empty()
        || hours.len() > MAX_AGE_DIGITS
        || !hours.bytes().all(|b| b.is_ascii_digit())
    {
        return Some(Err(format!(
            "`{token}`: an aging mark is [AGE:n] with n the hours, digits only"
        )));
    }
    Some(
        hours
            .parse::<u32>()
            .map_err(|_| format!("`{token}`: the hours of an aging mark are too large")),
    )
}

/// Whether a type token names a WINS or WINS-R record of a Windows file.
fn is_wins(token: &str) -> bool {
    ["WINS", "WINS-R", "WINSR"]
        .iter()
        .any(|known| token.eq_ignore_ascii_case(known))
}

/// The TTL of a record without one before any `$TTL` or TTL in the file.
const DEFAULT_TTL: u32 = 3_600;

/// One record of a zone file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRecord {
    /// The line it starts on, from 1.
    pub line: usize,
    /// The owner name.
    pub name: DnsName,
    /// The type.
    pub rtype: Rtype,
    /// The TTL.
    pub ttl: u32,
    /// The data, canonical.
    pub rdata: Rdata,
    // WP13.4
    /// In the Windows dialect: the record carried an aging timestamp (`[AGE:n]`, `n` above
    /// zero), so Windows calls it dynamic. Always `false` in the RFC 1035 dialect.
    pub aged: bool,
}

/// A record the import does not take, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loss {
    /// The line, from 1.
    pub line: usize,
    /// The stable code.
    pub code: &'static str,
    /// What was lost, in English.
    pub detail: String,
}

/// What the reader yields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// A record.
    Record(FileRecord),
    /// A record the import does not take.
    Loss(Loss),
}

/// What the reader carries from one entry to the next.
#[derive(Debug)]
struct State {
    apex: DnsName,
    /// The current origin in wire form.
    origin: Vec<u8>,
    /// The `$TTL` value.
    dollar_ttl: Option<u32>,
    /// The last TTL a record gave.
    last_ttl: u32,
    /// The last owner in wire form; empty before the first.
    owner: Vec<u8>,
    /// The data of the current record in wire form.
    data: Vec<u8>,
    /// The dialect (WP13.4).
    dialect: Dialect,
}

/// Reads the records of a zone file one by one.
pub struct Reader {
    text: String,
    lexer: Lexer,
    entry: Entry,
    generate: Option<Generate>,
    state: State,
    max_generate: u32,
    done: bool,
}

impl std::fmt::Debug for Reader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reader")
            .field("apex", &self.state.apex)
            .finish_non_exhaustive()
    }
}

fn lex_error((line, reason): LexError) -> ZoneError {
    ZoneError::zone_file(line, reason)
}

impl Reader {
    /// A reader over `text` for the zone `apex`; `$GENERATE` makes at most `max_generate`
    /// records per directive.
    ///
    /// # Errors
    ///
    /// None today; the signature keeps room for checks before the first entry.
    pub fn new(text: &str, apex: &DnsName, max_generate: u32) -> ZoneResult<Self> {
        Self::with_dialect(text, apex, max_generate, Dialect::Rfc1035)
    }

    /// A reader over `text` in `dialect` (WP13.4).
    ///
    /// # Errors
    ///
    /// None today; the signature keeps room for checks before the first entry.
    pub fn with_dialect(
        text: &str,
        apex: &DnsName,
        max_generate: u32,
        dialect: Dialect,
    ) -> ZoneResult<Self> {
        Ok(Self {
            text: text.to_owned(),
            lexer: Lexer::new(1),
            entry: Entry::default(),
            generate: None,
            state: State {
                apex: apex.clone(),
                origin: apex.to_wire(),
                dollar_ttl: None,
                last_ttl: DEFAULT_TTL,
                owner: Vec::new(),
                data: Vec::new(),
                dialect,
            },
            max_generate,
            done: false,
        })
    }

    /// The next record or loss; `None` at the end, and after an error.
    ///
    /// # Errors
    ///
    /// `dns.zonefile.invalid` with the line and the reason of a syntax error, `$INCLUDE`,
    /// a malformed `$GENERATE` or one that makes too many records.
    pub fn next_item(&mut self) -> ZoneResult<Option<Item>> {
        if self.done {
            return Ok(None);
        }
        let next = self.read();
        if !matches!(next, Ok(Some(_))) {
            self.done = true;
        }
        next
    }

    fn read(&mut self) -> ZoneResult<Option<Item>> {
        loop {
            if let Some(generate) = &mut self.generate {
                let line = generate.line;
                let bad =
                    |reason: String| ZoneError::zone_file(line, format!("$GENERATE: {reason}"));
                let Some(text) = generate.next_line().map_err(bad)? else {
                    self.generate = None;
                    continue;
                };
                let mut lexer = Lexer::new(line);
                if !lexer.entry(&text, &mut self.entry).map_err(lex_error)? {
                    continue;
                }
                if self
                    .entry
                    .tokens
                    .first()
                    .is_some_and(|token| !token.quoted && token.text(&text).starts_with('$'))
                {
                    return Err(bad("a generated line is a directive".to_owned()));
                }
                let item = self.state.record(&text, &self.entry)?;
                if lexer.entry(&text, &mut self.entry).map_err(lex_error)? {
                    return Err(bad("a generated line holds more than one record".to_owned()));
                }
                return Ok(Some(item));
            }
            if !self
                .lexer
                .entry(&self.text, &mut self.entry)
                .map_err(lex_error)?
            {
                return Ok(None);
            }
            let Some(first) = self.entry.tokens.first().copied() else {
                continue;
            };
            if !self.entry.indented && !first.quoted && first.text(&self.text).starts_with('$') {
                self.directive()?;
                continue;
            }
            return self.state.record(&self.text, &self.entry).map(Some);
        }
    }

    /// `$ORIGIN`, `$TTL`, `$INCLUDE` (refused) or `$GENERATE`.
    fn directive(&mut self) -> ZoneResult<()> {
        let src = self.text.as_str();
        let tokens = self.entry.tokens.as_slice();
        let first = tokens[0];
        let line = first.line;
        let name = first.text(src);
        let argument = |index: usize, what: &str| {
            tokens
                .get(index)
                .copied()
                .ok_or_else(|| ZoneError::zone_file(line, format!("{name}: {what} is missing")))
        };
        let only = |count: usize| match tokens.get(count) {
            Some(extra) => Err(ZoneError::zone_file(
                extra.line,
                format!(
                    "{name}: `{}` is more than the directive takes",
                    extra.text(src)
                ),
            )),
            None => Ok(()),
        };
        if name.eq_ignore_ascii_case("$ORIGIN") {
            let token = argument(1, "the origin")?;
            only(2)?;
            let mut origin = Vec::new();
            text::name(token.text(src), &self.state.origin, &mut origin)
                .map_err(|reason| ZoneError::zone_file(token.line, format!("$ORIGIN: {reason}")))?;
            self.state.origin = origin;
        } else if name.eq_ignore_ascii_case("$TTL") {
            let token = argument(1, "the TTL")?;
            only(2)?;
            let ttl = text::ttl(token.text(src)).ok_or_else(|| {
                ZoneError::zone_file(
                    token.line,
                    format!(
                        "$TTL is a number of seconds or a duration such as 1h30m, not `{}`",
                        token.text(src)
                    ),
                )
            })?;
            self.state.dollar_ttl = Some(ttl);
        } else if name.eq_ignore_ascii_case("$INCLUDE") {
            return Err(ZoneError::zone_file(
                line,
                "$INCLUDE is refused: the import reads one file",
            ));
        } else if name.eq_ignore_ascii_case("$GENERATE") {
            let range = argument(1, "the range")?;
            let lhs = argument(2, "the owner")?;
            if tokens.len() < 5 {
                return Err(ZoneError::zone_file(
                    line,
                    "$GENERATE: the type and the data are missing",
                ));
            }
            let mut rhs = String::new();
            for token in &tokens[3..] {
                if !rhs.is_empty() && !token.glued {
                    rhs.push(' ');
                }
                rhs.push_str(token.raw(src));
            }
            let generate =
                Generate::new(range.text(src), lhs.raw(src), rhs, line, self.max_generate)
                    .map_err(|reason| ZoneError::zone_file(line, format!("$GENERATE: {reason}")))?;
            self.generate = Some(generate);
        } else {
            return Err(ZoneError::zone_file(
                line,
                format!("{name} is not a directive the reader knows"),
            ));
        }
        Ok(())
    }
}

/// `[ttl] [class] type` from `tokens[*index]` on, the TTL and the class in either order
/// (a token that reads as a TTL is one, then a type, then a class, as RFC 1035 has it).
fn ttl_class_type(
    src: &str,
    tokens: &[lexer::Token],
    index: &mut usize,
    last_line: usize,
) -> ZoneResult<(Option<u32>, Option<u16>, Rtype)> {
    let mut ttl = None;
    let mut class = None;
    loop {
        let token = tokens
            .get(*index)
            .ok_or_else(|| ZoneError::zone_file(last_line, "the record type is missing"))?;
        let field = token.text(src);
        *index += 1;
        if ttl.is_none()
            && let Some(value) = text::ttl(field)
        {
            ttl = Some(value);
            continue;
        }
        if let Some(rtype) = types::parse(field) {
            return Ok((ttl, class, rtype));
        }
        if class.is_none()
            && let Some(value) = types::parse_class(field)
        {
            class = Some(value);
            continue;
        }
        return Err(ZoneError::zone_file(
            token.line,
            format!("`{field}` is not a TTL, a class or a record type"),
        ));
    }
}

impl State {
    // WP13.4: the Windows dialect.
    /// In the Windows dialect, the aging mark right after the owner (taken, moving `index`
    /// past it): whether the record is aged; or the loss of a WINS or WINS-R record. Outside
    /// the dialect: not aged.
    fn windows_prefix(
        &self,
        src: &str,
        tokens: &[lexer::Token],
        index: &mut usize,
        line: usize,
    ) -> ZoneResult<Result<bool, Loss>> {
        if self.dialect != Dialect::Windows {
            return Ok(Ok(false));
        }
        let mut aged = false;
        if let Some(token) = tokens.get(*index)
            && !token.quoted
            && let Some(mark) = age_mark(token.text(src))
        {
            let hours = mark.map_err(|reason| ZoneError::zone_file(token.line, reason))?;
            aged = hours > 0;
            *index += 1;
        }
        // The type comes within the first three tokens (`[ttl] [class] type`); a known
        // type ends the search, so that data reading `WINS` is data.
        let wins = tokens
            .get(*index..)
            .unwrap_or_default()
            .iter()
            .take(3)
            .take_while(|token| token.quoted || types::parse(token.text(src)).is_none())
            .find(|token| !token.quoted && is_wins(token.text(src)));
        Ok(match wins {
            Some(wins) => Err(Loss {
                line,
                code: LOSS_WINS,
                detail: format!(
                    "a {} record of a Windows zone is not served",
                    wins.text(src).to_ascii_uppercase()
                ),
            }),
            None => Ok(aged),
        })
    }

    /// One record entry.
    fn record(&mut self, src: &str, entry: &Entry) -> ZoneResult<Item> {
        let tokens = entry.tokens.as_slice();
        let Some(first) = tokens.first() else {
            return Err(ZoneError::zone_file(1, "an empty entry"));
        };
        let line = first.line;
        let last_line = tokens.last().map_or(line, |token| token.line);
        let mut index = 0;
        if entry.indented {
            if self.owner.is_empty() {
                return Err(ZoneError::zone_file(
                    line,
                    "the first record has no owner name",
                ));
            }
        } else {
            self.owner.clear();
            text::name(first.text(src), &self.origin, &mut self.owner).map_err(|reason| {
                ZoneError::zone_file(line, format!("the owner name: {reason}"))
            })?;
            index = 1;
        }

        // WP13.4: the aging mark and the WINS records of a Windows file.
        let aged = match self.windows_prefix(src, tokens, &mut index, line)? {
            Ok(aged) => aged,
            Err(loss) => return Ok(Item::Loss(loss)),
        };
        let (ttl, class, rtype) = ttl_class_type(src, tokens, &mut index, last_line)?;
        let ttl = match ttl {
            Some(ttl) => {
                self.last_ttl = ttl;
                ttl
            }
            None => self.dollar_ttl.unwrap_or(self.last_ttl),
        };

        // The data; a syntax error in it stops the read before any loss is reported.
        let data = &tokens[index..];
        let mut fields = Fields::new(src, data, last_line, &self.origin);
        self.data.clear();
        let parsed = if parse::is_generic(src, data) {
            Some(parse::generic(&mut fields, &mut self.data))
        } else {
            parse::data(rtype, &mut fields, &mut self.data)
        };
        let known = match parsed {
            Some(Ok(())) => true,
            Some(Err((line, reason))) => return Err(ZoneError::zone_file(line, reason)),
            None => false,
        };

        let loss = |code: &'static str, detail: String| Ok(Item::Loss(Loss { line, code, detail }));
        let class = class.unwrap_or(types::IN);
        if class != types::IN {
            return loss(
                LOSS_CLASS,
                format!(
                    "a record of class {} is not served",
                    types::class_name(class)
                ),
            );
        }
        let name = match DnsName::from_wire(&self.owner) {
            Ok((name, _)) => name,
            Err(error) => return loss(LOSS_DATA, format!("owner name refused: {}", error.reason)),
        };
        if !name.is_subdomain_of(&self.apex) {
            return loss(
                LOSS_OUTSIDE,
                format!("{name} is outside the zone {}", self.apex),
            );
        }
        if !known {
            return loss(
                LOSS_DATA,
                format!(
                    "{name} {}: the data of this type is read only in the generic form \\# (RFC 3597)",
                    types::name(rtype)
                ),
            );
        }
        let rdata = match Rdata::from_wire(rtype, &self.data) {
            Ok(rdata) => rdata,
            Err(error) => return loss(LOSS_DATA, format!("{name} {rtype}: {}", error.reason)),
        };
        Ok(Item::Record(FileRecord {
            line,
            name,
            rtype,
            ttl,
            rdata,
            aged,
        }))
    }
}

// ----- writing --------------------------------------------------------------------------

/// The `$ORIGIN` and `$TTL` lines.
pub fn header(apex: &DnsName, ttl: u32) -> String {
    format!("$ORIGIN {}\n$TTL {ttl}\n", absolute(apex))
}

/// A name with its trailing dot.
pub fn absolute(name: &DnsName) -> String {
    if name.is_root() {
        ".".to_owned()
    } else {
        format!("{name}.")
    }
}

/// The record data in presentation format.
///
/// # Errors
///
/// `dns.record.invalid` when stored data does not parse.
pub fn presentation(rtype: Rtype, rdata: &Rdata) -> ZoneResult<String> {
    let data = rdata.decode(rtype).map_err(|_| {
        ZoneError::new(
            tenko_core::dns::codes::RECORD_INVALID,
            400,
            format!("stored {rtype} data does not parse"),
        )
    })?;
    Ok(present::typed(&data).unwrap_or_else(|| present::generic(rdata.as_bytes())))
}

/// The type as the zone file names it.
pub fn type_name(rtype: Rtype) -> String {
    types::name(rtype)
}

/// Writes the lines of one RRset.
///
/// # Errors
///
/// `dns.record.invalid` when stored data does not parse.
pub fn write_rrset(out: &mut String, apex: &DnsName, rrset: &RrSet) -> ZoneResult<()> {
    let owner = relative_name(&rrset.name, apex);
    let type_name = type_name(rrset.rtype);
    let mut records: Vec<&Rdata> = rrset.rdata.iter().collect();
    records.sort();
    for rdata in records {
        let data = presentation(rrset.rtype, rdata)?;
        let _ = writeln!(out, "{owner} {} IN {type_name} {data}", rrset.ttl);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
