//! Kea's classification expressions (the `test` of a client class) built from Tenko's
//! matches, classes and policy conditions.
//!
//! | Tenko match | Kea expression |
//! |---|---|
//! | vendor class, exact | `option[60].hex == 'PXEClient'` |
//! | vendor class, prefix | `substring(option[60].hex,0,9) == 'PXEClient'` |
//! | user class | `option[77].hex == 'iPXE' or substring(option[77].hex,0,5) == 0x0469505845` (the whole value, or the first RFC 3004 instance) |
//! | MAC pattern | `pkt4.mac == 0x00005e005301`, or `substring(pkt4.mac,i,n) == 0x..` per run of fixed octets |
//! | client identifier | `option[61].hex == 0x01..` |
//! | circuit-id, remote-id | `relay4[1].hex == ..`, `relay4[2].hex == ..` |
//! | architecture | `substring(option[93].hex,0,2) == 0x0007 or ..` over the first four entries |
//! | host name | `lcase(option[12].text) == 'name'` or its `substring` for a prefix |
//!
//! A class is OR over its matches; a policy joins its terms with `and` or `or`, a negated
//! term is `not (..)`. A literal is a quoted string when every octet is printable ASCII
//! other than a quote or a backslash, else a hexadecimal literal. Every operand of `not`,
//! `and` and `or` that is not a `member(..)` is put in parentheses, so the precedence of
//! Kea's grammar never decides.

use std::fmt::Write as _;

use tenko_core::dhcp::{MacPattern, Match};

/// The name of Kea's built-in class every packet belongs to.
pub const ALL: &str = "ALL";

/// A boolean expression of Kea's classification language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// Always true (`member('ALL')`).
    True,
    /// Always false (`not member('ALL')`).
    False,
    /// A comparison, rendered.
    Test(String),
    /// Membership of a class defined earlier.
    Member(String),
    /// Negation.
    Not(Box<Expr>),
    /// Every operand holds.
    And(Vec<Expr>),
    /// At least one operand holds.
    Or(Vec<Expr>),
}

impl Expr {
    /// The negation, simplified.
    #[must_use]
    pub fn negate(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Not(inner) => *inner,
            other => Self::Not(Box::new(other)),
        }
    }

    /// The conjunction, simplified: true operands go, a false one makes it false.
    pub fn and(items: impl IntoIterator<Item = Expr>) -> Self {
        let mut out = Vec::new();
        for item in items {
            match item {
                Self::True => {}
                Self::False => return Self::False,
                Self::And(inner) => out.extend(inner),
                other => out.push(other),
            }
        }
        match out.len() {
            0 => Self::True,
            1 => out.pop().unwrap_or(Self::True),
            _ => Self::And(out),
        }
    }

    /// The disjunction, simplified: false operands go, a true one makes it true.
    pub fn or(items: impl IntoIterator<Item = Expr>) -> Self {
        let mut out = Vec::new();
        for item in items {
            match item {
                Self::False => {}
                Self::True => return Self::True,
                Self::Or(inner) => out.extend(inner),
                other => out.push(other),
            }
        }
        match out.len() {
            0 => Self::False,
            1 => out.pop().unwrap_or(Self::False),
            _ => Self::Or(out),
        }
    }

    /// Membership of `class`.
    pub fn member(class: &str) -> Self {
        Self::Member(class.to_owned())
    }

    fn is_atomic(&self) -> bool {
        matches!(self, Self::True | Self::False | Self::Member(_))
    }

    fn operand(&self, out: &mut String) {
        if self.is_atomic() {
            self.write(out);
        } else {
            out.push('(');
            self.write(out);
            out.push(')');
        }
    }

    fn write(&self, out: &mut String) {
        match self {
            Self::True => {
                let _ = write!(out, "member('{ALL}')");
            }
            Self::False => {
                let _ = write!(out, "not member('{ALL}')");
            }
            Self::Test(text) => out.push_str(text),
            Self::Member(name) => {
                out.push_str("member(");
                out.push_str(&literal(name.as_bytes()));
                out.push(')');
            }
            Self::Not(inner) => {
                out.push_str("not ");
                inner.operand(out);
            }
            Self::And(items) | Self::Or(items) => {
                let join = if matches!(self, Self::And(_)) {
                    " and "
                } else {
                    " or "
                };
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push_str(join);
                    }
                    item.operand(out);
                }
            }
        }
    }

    /// The expression as Kea reads it.
    pub fn render(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }
}

/// Whether the octets can be written as a quoted Kea string.
fn printable(octets: &[u8]) -> bool {
    !octets.is_empty()
        && octets
            .iter()
            .all(|&b| (0x20..0x7f).contains(&b) && b != b'\'' && b != b'\\')
}

/// A Kea literal of the octets: `'text'` when printable, else `0x..`.
pub fn literal(octets: &[u8]) -> String {
    if printable(octets) {
        let mut out = String::with_capacity(octets.len() + 2);
        out.push('\'');
        out.extend(octets.iter().map(|&b| char::from(b)));
        out.push('\'');
        out
    } else {
        hex_literal(octets)
    }
}

/// A hexadecimal Kea literal (`0x..`).
pub fn hex_literal(octets: &[u8]) -> String {
    let mut out = String::with_capacity(2 + 2 * octets.len());
    out.push_str("0x");
    for b in octets {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn equals(left: &str, right: &[u8]) -> Expr {
    Expr::Test(format!("{left} == {}", literal(right)))
}

fn starts_with(field: &str, prefix: &[u8]) -> Expr {
    Expr::Test(format!(
        "substring({field},0,{}) == {}",
        prefix.len(),
        literal(prefix)
    ))
}

/// The six positions of a MAC pattern, `None` for a wildcard.
fn positions(pattern: &MacPattern) -> [Option<u8>; 6] {
    let text = pattern.to_string();
    let mut out = [None; 6];
    for (index, part) in text.split(':').take(6).enumerate() {
        out[index] = u8::from_str_radix(part, 16).ok();
    }
    out
}

fn mac(pattern: &MacPattern) -> Expr {
    let positions = positions(pattern);
    if positions.iter().all(Option::is_some) {
        let octets: Vec<u8> = positions.iter().filter_map(|b| *b).collect();
        return Expr::Test(format!("pkt4.mac == {}", hex_literal(&octets)));
    }
    mac_at("pkt4.mac", 0, pattern)
}

/// The tests of a MAC pattern against the six octets of `field` from `offset` on: one
/// `substring` per run of fixed octets.
fn mac_at(field: &str, offset: usize, pattern: &MacPattern) -> Expr {
    let positions = positions(pattern);
    let mut tests = Vec::new();
    let mut at = 0;
    while at < 6 {
        if positions[at].is_none() {
            at += 1;
            continue;
        }
        let start = at;
        let mut run = Vec::new();
        while at < 6 {
            match positions[at] {
                Some(b) => run.push(b),
                None => break,
            }
            at += 1;
        }
        tests.push(Expr::Test(format!(
            "substring({field},{},{}) == {}",
            offset + start,
            run.len(),
            hex_literal(&run)
        )));
    }
    Expr::and(tests)
}

// WP9.3, the DHCPv6 half: the MAC filters of a DHCPv6 client.
/// Option 79 (RFC 6939) of the relay nearest the server, as Kea reads it.
const RELAY_LINK_LAYER: &str = "relay6[0].option[79].hex";
/// The client's DUID (option 1).
const CLIENT_DUID: &str = "option[1].hex";

/// A MAC pattern against a DHCPv6 client's link-layer address as the engine takes it: the
/// Client Link-Layer Address option a relay added (RFC 6939, hardware type 1), else the
/// address of a DUID-LLT or DUID-LL of hardware type 1. Kea reads option 79 of the relay
/// nearest the server (`relay6[0]`), which is the relay on the client's link when one
/// relay forwards; the engine reads it from the relay on the client's link.
pub fn mac6(pattern: &MacPattern) -> Expr {
    let has_option = Expr::Test(String::from("relay6[0].option[79].exists"));
    let from_option = Expr::and([
        Expr::Test(format!("substring({RELAY_LINK_LAYER},0,2) == 0x0001")),
        mac_at(RELAY_LINK_LAYER, 2, pattern),
    ]);
    let llt = Expr::and([
        Expr::Test(format!("substring({CLIENT_DUID},0,4) == 0x00010001")),
        mac_at(CLIENT_DUID, 8, pattern),
    ]);
    let ll = Expr::and([
        Expr::Test(format!("substring({CLIENT_DUID},0,4) == 0x00030001")),
        mac_at(CLIENT_DUID, 4, pattern),
    ]);
    Expr::or([
        Expr::and([has_option.clone(), from_option]),
        Expr::and([has_option.negate(), Expr::or([llt, ll])]),
    ])
}

/// The expression of one match, and whether it is exact (false for the user class, of
/// which Kea's expressions read only the first RFC 3004 instance).
pub fn of_match(item: &Match) -> (Expr, bool) {
    match item {
        Match::VendorClass { value, prefix } => (
            if *prefix {
                starts_with("option[60].hex", value.as_bytes())
            } else {
                equals("option[60].hex", value.as_bytes())
            },
            true,
        ),
        Match::UserClass { value } => {
            let bytes = value.as_bytes();
            let whole = equals("option[77].hex", bytes);
            let Ok(len) = u8::try_from(bytes.len()) else {
                return (whole, false);
            };
            let mut instance = Vec::with_capacity(bytes.len() + 1);
            instance.push(len);
            instance.extend_from_slice(bytes);
            (
                Expr::or([whole, starts_with("option[77].hex", &instance)]),
                false,
            )
        }
        Match::Mac { pattern } => (mac(pattern), true),
        Match::ClientId { value } => (
            Expr::Test(format!("option[61].hex == {}", hex_literal(&value.0))),
            true,
        ),
        Match::CircuitId { value } => (equals("relay4[1].hex", &value.0), true),
        Match::RemoteId { value } => (equals("relay4[2].hex", &value.0), true),
        Match::Architecture { code } => {
            let code = hex_literal(&code.to_be_bytes());
            (
                Expr::or((0..4).map(|entry| {
                    Expr::Test(format!(
                        "substring(option[93].hex,{},2) == {code}",
                        entry * 2
                    ))
                })),
                true,
            )
        }
        Match::HostName { value, prefix } => {
            let lower = value.to_ascii_lowercase();
            (
                if *prefix {
                    starts_with("lcase(option[12].text)", lower.as_bytes())
                } else {
                    equals("lcase(option[12].text)", lower.as_bytes())
                },
                true,
            )
        }
    }
}

/// The OR of a class's matches, and whether every match is exact.
pub fn of_matches(matches: &[Match]) -> (Expr, bool) {
    let mut exact = true;
    let expr = Expr::or(matches.iter().map(|item| {
        let (expr, is_exact) = of_match(item);
        exact &= is_exact;
        expr
    }));
    (expr, exact)
}

#[cfg(test)]
mod tests {
    use tenko_core::serde_util::HexBytes;

    use super::*;

    fn render(item: &Match) -> String {
        of_match(item).0.render()
    }

    #[test]
    fn matches_render_as_kea_reads_them() {
        assert_eq!(
            render(&Match::VendorClass {
                value: "PXEClient".into(),
                prefix: true
            }),
            "substring(option[60].hex,0,9) == 'PXEClient'"
        );
        assert_eq!(
            render(&Match::VendorClass {
                value: "MSFT 5.0".into(),
                prefix: false
            }),
            "option[60].hex == 'MSFT 5.0'"
        );
        assert_eq!(
            render(&Match::UserClass {
                value: "iPXE".into()
            }),
            "(option[77].hex == 'iPXE') or (substring(option[77].hex,0,5) == 0x0469505845)"
        );
        assert_eq!(
            render(&Match::Mac {
                pattern: MacPattern::new("00:00:5e:00:53:01").expect("pattern")
            }),
            "pkt4.mac == 0x00005e005301"
        );
        assert_eq!(
            render(&Match::Mac {
                pattern: MacPattern::new("00:00:5e:00:*:85").expect("pattern")
            }),
            "(substring(pkt4.mac,0,4) == 0x00005e00) and (substring(pkt4.mac,5,1) == 0x85)"
        );
        assert_eq!(
            render(&Match::Mac {
                pattern: MacPattern::new("00-00-5E-*").expect("pattern")
            }),
            "substring(pkt4.mac,0,3) == 0x00005e"
        );
        assert_eq!(
            render(&Match::ClientId {
                value: HexBytes(vec![1, 0, 0, 0x5e, 0, 0x53, 1])
            }),
            "option[61].hex == 0x0100005e005301"
        );
        assert_eq!(
            render(&Match::CircuitId {
                value: HexBytes(b"lan".to_vec())
            }),
            "relay4[1].hex == 'lan'"
        );
        assert_eq!(
            render(&Match::RemoteId {
                value: HexBytes(vec![0, 1])
            }),
            "relay4[2].hex == 0x0001"
        );
        assert!(render(&Match::Architecture { code: 7 }).starts_with(
            "(substring(option[93].hex,0,2) == 0x0007) or (substring(option[93].hex,2,2) == 0x0007)"
        ));
        assert_eq!(
            render(&Match::HostName {
                value: "Printer".into(),
                prefix: true
            }),
            "substring(lcase(option[12].text),0,7) == 'printer'"
        );
    }

    #[test]
    fn literals_quote_only_safe_text() {
        assert_eq!(literal(b"lab-ops"), "'lab-ops'");
        assert_eq!(literal(b"it's"), "0x69742773");
        assert_eq!(literal(b"a\\b"), "0x615c62");
        assert_eq!(literal(&[0, 1]), "0x0001");
    }

    #[test]
    fn operators_simplify_and_parenthesise() {
        assert_eq!(
            Expr::and([Expr::True, Expr::member("a")]).render(),
            "member('a')"
        );
        assert_eq!(Expr::or([Expr::False, Expr::False]), Expr::False);
        assert_eq!(Expr::and([Expr::False, Expr::member("a")]), Expr::False);
        assert_eq!(Expr::member("a").negate().negate(), Expr::member("a"));
        assert_eq!(
            Expr::and([
                Expr::member("a"),
                Expr::or([Expr::member("b"), Expr::member("c")]).negate()
            ])
            .render(),
            "member('a') and (not (member('b') or member('c')))"
        );
        assert_eq!(Expr::True.render(), "member('ALL')");
        assert_eq!(Expr::False.render(), "not member('ALL')");
    }
}
