//! The `.rdp` file and the `ssh://` URI of the remote access hand-off (API-11). Pure
//! functions, written to match `ui/src/hosts/handoff.ts` byte for byte.
//!
//! Everything here is text in, text out: no I/O and no percent-encoding crate. The cleaning
//! rules are those of the UI. A value loses every control character (category Cc) and the
//! Unicode line and paragraph separators (Zl, Zp), so it can never end its line in an `.rdp`
//! file and start another setting. Surrounding whitespace is trimmed the way JavaScript's
//! `String.prototype.trim` does it.
//!
//! One difference from the UI cannot occur here: JavaScript strings may hold lone
//! surrogates, which the UI turns into U+FFFD before it percent-encodes; a Rust `str` is
//! always valid Unicode, so there is nothing to replace.

/// The default port of Remote Desktop.
pub(crate) const DEFAULT_RDP_PORT: u16 = 3389;

/// The default port of SSH, which an `ssh://` URI leaves out.
pub(crate) const DEFAULT_SSH_PORT: u16 = 22;

/// The media type of an `.rdp` file.
pub(crate) const RDP_MIME: &str = "application/x-rdp";

/// The longest base of an `.rdp` file name, in characters before the extension.
const MAX_FILE_NAME_BASE: usize = 64;

/// The file name base used when nothing is left of the host name.
const FALLBACK_FILE_NAME_BASE: &str = "host";

/// Why a hand-off cannot be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HandoffError {
    /// The host or address is empty after cleaning.
    EmptyHost,
    /// Port 0.
    InvalidPort,
}

/// Whether `c` is removed from every value: a control character (category Cc), the line
/// separator U+2028 (Zl) or the paragraph separator U+2029 (Zp).
fn is_line_breaking(c: char) -> bool {
    c.is_control() || c == '\u{2028}' || c == '\u{2029}'
}

/// Whether JavaScript's `trim` strips `c`: the ECMAScript white space (the space separators
/// of category Zs, tab, vertical tab, form feed and the byte order mark) and the line
/// terminators. It differs from [`char::is_whitespace`] for U+0085 (not stripped by
/// JavaScript) and U+FEFF (stripped by JavaScript only).
fn is_js_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{9}'..='\u{d}'
            | ' '
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
            | '\u{feff}'
    )
}

/// `value` without leading and trailing white space, as JavaScript's `trim` sees it.
fn js_trim(value: &str) -> &str {
    value.trim_matches(is_js_whitespace)
}

/// Removes control characters (CR and LF among them) and the Unicode line and paragraph
/// separators, so a value can never end its line in an `.rdp` file and start another
/// setting.
fn single_line(value: &str) -> String {
    value.chars().filter(|&c| !is_line_breaking(c)).collect()
}

/// The host without surrounding brackets and white space, as a single line.
fn bare_host(host: &str) -> String {
    let line = single_line(host);
    let text = js_trim(&line);
    match text
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
    {
        Some(inner) => js_trim(inner).to_owned(),
        None => text.to_owned(),
    }
}

/// A user name as a trimmed single line; empty when there is none.
fn clean_user(user: Option<&str>) -> String {
    js_trim(&single_line(user.unwrap_or(""))).to_owned()
}

/// A valid IPv6 literal has at least two colons; "host:port" has one.
fn is_ipv6_literal(host: &str) -> bool {
    host.matches(':').count() >= 2
}

/// The part of a host that goes before ":port" in an `.rdp` file: an IPv6 literal in
/// brackets.
fn rdp_host(host: &str) -> String {
    if is_ipv6_literal(host) {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

/// Whether `byte` stays as it is in JavaScript's `encodeURIComponent`: `A-Z a-z 0-9` and
/// `- _ . ! ~ * ' ( )`.
fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
        )
}

/// JavaScript's `encodeURIComponent`: every byte of the UTF-8 form that is not unreserved
/// becomes `%XX` with upper-case hexadecimal digits.
fn encode_component(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        if is_unreserved(byte) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    out
}

/// Splits an IPv6 literal with an optional zone, the match of
/// `^([0-9A-Fa-f:.]+)(?:%(.+))?$`: the longest run of hexadecimal digits, colons and dots,
/// then either the end or a `%` followed by at least one character. The host is a single
/// line already, so the `.` of the expression (no line terminators) accepts every zone
/// character.
fn split_ipv6_zone(host: &str) -> Option<(&str, Option<&str>)> {
    let end = host
        .find(|c: char| !(c.is_ascii_hexdigit() || c == ':' || c == '.'))
        .unwrap_or(host.len());
    if end == 0 {
        return None;
    }
    let (address, rest) = host.split_at(end);
    if rest.is_empty() {
        return Some((address, None));
    }
    match rest.strip_prefix('%') {
        Some(zone) if !zone.is_empty() => Some((address, Some(zone))),
        _ => None,
    }
}

/// The host of an `ssh://` URI: an IPv6 literal in brackets (RFC 6874 zone), else a
/// registered name encoded as a URI component.
fn uri_host(host: &str) -> String {
    if is_ipv6_literal(host)
        && let Some((address, zone)) = split_ipv6_zone(host)
    {
        return match zone {
            Some(zone) => format!("[{address}%25{}]", encode_component(zone)),
            None => format!("[{address}]"),
        };
    }
    encode_component(host)
}

/// The text of a `.rdp` file: CRLF line ends, ending with CRLF. The address always carries
/// the port and an IPv6 literal is bracketed (`[2001:db8::10]:3389`); an address given in
/// brackets is not bracketed twice. The user name is written only when it is not empty after
/// cleaning. Control characters are removed from the values, so a value cannot inject another
/// setting.
///
/// # Errors
///
/// [`HandoffError::InvalidPort`] for port 0 (checked first) and [`HandoffError::EmptyHost`]
/// when the address is empty after cleaning.
pub(crate) fn rdp_file(
    address: &str,
    port: u16,
    username: Option<&str>,
) -> Result<String, HandoffError> {
    if port == 0 {
        return Err(HandoffError::InvalidPort);
    }
    let host = bare_host(address);
    if host.is_empty() {
        return Err(HandoffError::EmptyHost);
    }
    let username = clean_user(username);

    let mut lines = vec![format!("full address:s:{}:{port}", rdp_host(&host))];
    if !username.is_empty() {
        lines.push(format!("username:s:{username}"));
    }
    lines.extend(
        [
            "prompt for credentials:i:1",
            "administrative session:i:0",
            "screen mode id:i:2",
            "authentication level:i:2",
        ]
        .map(str::to_owned),
    );
    Ok(format!("{}\r\n", lines.join("\r\n")))
}

/// A safe file name for the `.rdp` file of a host: every character outside `[A-Za-z0-9._-]`
/// becomes "_", at most 64 characters, plus ".rdp"; "host.rdp" when nothing is left.
///
/// The replacement is made per UTF-16 code unit, as JavaScript does it, so a character
/// outside the Basic Multilingual Plane (a surrogate pair in UTF-16) becomes two underscores
/// and counts as two of the 64 characters; the name is the same as the UI makes.
pub(crate) fn rdp_file_name(host_name: &str) -> String {
    let base: String = host_name
        .encode_utf16()
        .map(|unit| match u8::try_from(unit) {
            Ok(byte) if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') => {
                char::from(byte)
            }
            _ => '_',
        })
        .take(MAX_FILE_NAME_BASE)
        .collect();
    let base = if base.is_empty() {
        FALLBACK_FILE_NAME_BASE
    } else {
        &base
    };
    format!("{base}.rdp")
}

/// `ssh://[user@]host[:port]`: the user percent-encoded as RFC 3986 userinfo (as
/// `encodeURIComponent` does), an IPv6 literal in brackets with its zone encoded as RFC 6874
/// asks, any other host encoded as a URI component, and the port only when it is not 22.
///
/// # Errors
///
/// [`HandoffError::InvalidPort`] for port 0 (checked first) and [`HandoffError::EmptyHost`]
/// when the host is empty after cleaning.
pub(crate) fn ssh_uri(host: &str, port: u16, user: Option<&str>) -> Result<String, HandoffError> {
    if port == 0 {
        return Err(HandoffError::InvalidPort);
    }
    let host = bare_host(host);
    if host.is_empty() {
        return Err(HandoffError::EmptyHost);
    }
    let user = clean_user(user);

    let userinfo = if user.is_empty() {
        String::new()
    } else {
        format!("{}@", encode_component(&user))
    };
    let suffix = if port == DEFAULT_SSH_PORT {
        String::new()
    } else {
        format!(":{port}")
    };
    Ok(format!("ssh://{userinfo}{}{suffix}", uri_host(&host)))
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_RDP_PORT, DEFAULT_SSH_PORT, HandoffError, RDP_MIME, is_line_breaking, rdp_file,
        rdp_file_name, ssh_uri,
    };

    /// NUL, NEL, line separator and paragraph separator.
    const CONTROLS: &str = "\u{0}\u{85}\u{2028}\u{2029}";

    /// A pair of surrogates in UTF-16, one scalar value in UTF-8.
    const ASTRAL: &str = "\u{1f600}";

    const TRAILER: [&str; 4] = [
        "prompt for credentials:i:1",
        "administrative session:i:0",
        "screen mode id:i:2",
        "authentication level:i:2",
    ];

    /// Every way a text can end a line, or that a reader might take for it.
    const LINE_BREAKS: [&str; 8] = [
        "\r",
        "\n",
        "\r\n",
        "\n\r",
        "\u{85}",
        "\u{2028}",
        "\u{2029}",
        "\u{b}\u{c}",
    ];

    fn rdp_text(address: &str, port: u16, username: Option<&str>) -> String {
        rdp_file(address, port, username).expect("the .rdp file can be built")
    }

    /// The lines of an `.rdp` text, without the terminator of the last one.
    fn rdp_lines(text: &str) -> Vec<&str> {
        assert!(text.ends_with("\r\n"), "the text ends with CRLF: {text:?}");
        text[..text.len() - 2].split("\r\n").collect()
    }

    fn first_rdp_line(address: &str, port: u16) -> String {
        let text = rdp_text(address, port, None);
        rdp_lines(&text)[0].to_owned()
    }

    fn uri(host: &str, port: u16, user: Option<&str>) -> String {
        ssh_uri(host, port, user).expect("the ssh URI can be built")
    }

    /// Decodes `%XX` sequences; the input is the output of the encoder.
    fn percent_decode(text: &str) -> String {
        let bytes = text.as_bytes();
        let mut out = Vec::new();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%' {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).expect("hex digits");
                out.push(u8::from_str_radix(hex, 16).expect("two hex digits"));
                index += 3;
            } else {
                out.push(bytes[index]);
                index += 1;
            }
        }
        String::from_utf8(out).expect("UTF-8")
    }

    /// The parts of an `ssh://` URI as a URI parser sees them: the text before the one `@`,
    /// the host (a bracketed IPv6 literal stays whole) and the port after the host.
    struct Parts {
        userinfo: Option<String>,
        host: String,
        port: Option<String>,
    }

    fn parse_ssh(uri: &str) -> Parts {
        let authority = uri.strip_prefix("ssh://").expect("the scheme");
        assert!(
            !authority.contains(['/', '?', '#']),
            "no path, query or fragment: {uri}"
        );
        assert!(
            authority.matches('@').count() <= 1,
            "at most one userinfo separator: {uri}"
        );
        let (userinfo, host_port) = match authority.split_once('@') {
            Some((userinfo, rest)) => (Some(userinfo.to_owned()), rest),
            None => (None, authority),
        };
        let (host, port) = if host_port.starts_with('[') {
            let close = host_port.find(']').expect("a closing bracket");
            let (host, rest) = host_port.split_at(close + 1);
            (host, rest.strip_prefix(':'))
        } else {
            match host_port.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (host_port, None),
            }
        };
        Parts {
            userinfo,
            host: host.to_owned(),
            port: port.map(str::to_owned),
        }
    }

    #[test]
    fn the_default_ports_and_the_media_type_are_those_of_the_ui() {
        assert_eq!(DEFAULT_RDP_PORT, 3389);
        assert_eq!(DEFAULT_SSH_PORT, 22);
        assert_eq!(RDP_MIME, "application/x-rdp");
    }

    #[test]
    fn ports_from_one_to_65535_are_accepted_by_both_builders() {
        for port in [1, 22, 3389, 8080, 65535] {
            assert!(rdp_file("192.0.2.10", port, None).is_ok(), "rdp {port}");
            assert!(ssh_uri("192.0.2.10", port, None).is_ok(), "ssh {port}");
        }
    }

    #[test]
    fn port_zero_is_refused_by_both_builders() {
        assert_eq!(
            rdp_file("192.0.2.10", 0, None),
            Err(HandoffError::InvalidPort)
        );
        assert_eq!(
            ssh_uri("192.0.2.10", 0, None),
            Err(HandoffError::InvalidPort)
        );
    }

    #[test]
    fn the_port_is_checked_before_the_host() {
        assert_eq!(rdp_file("", 0, None), Err(HandoffError::InvalidPort));
        assert_eq!(ssh_uri("", 0, None), Err(HandoffError::InvalidPort));
    }

    #[test]
    fn rdp_file_writes_an_ipv4_address_with_the_default_port_and_the_fixed_settings() {
        let text = rdp_text("192.0.2.10", DEFAULT_RDP_PORT, None);
        let expected = format!(
            "full address:s:192.0.2.10:3389\r\n{}\r\n",
            TRAILER.join("\r\n")
        );
        assert_eq!(text, expected);
    }

    #[test]
    fn rdp_file_joins_the_lines_with_crlf_and_ends_with_crlf_never_a_bare_lf() {
        let text = rdp_text("192.0.2.10", DEFAULT_RDP_PORT, Some("admin"));
        assert!(text.ends_with("\r\n"));
        assert!(!text.replace("\r\n", "").contains(['\r', '\n']));
        assert_eq!(text.split("\r\n").count(), 7);
    }

    #[test]
    fn rdp_file_brackets_an_ipv6_literal() {
        assert_eq!(
            first_rdp_line("2001:db8::10", 3389),
            "full address:s:[2001:db8::10]:3389"
        );
    }

    #[test]
    fn rdp_file_does_not_bracket_an_ipv6_literal_twice() {
        assert_eq!(
            first_rdp_line("[2001:db8::10]", 3390),
            "full address:s:[2001:db8::10]:3390"
        );
    }

    #[test]
    fn rdp_file_trims_white_space_inside_the_brackets_and_around_them() {
        assert_eq!(
            first_rdp_line("  [ 2001:db8::10 ] ", 3389),
            "full address:s:[2001:db8::10]:3389"
        );
        assert_eq!(
            first_rdp_line("[\r2001:db8::10\n]", 3389),
            "full address:s:[2001:db8::10]:3389"
        );
    }

    #[test]
    fn rdp_file_strips_brackets_only_when_both_are_present() {
        assert_eq!(
            first_rdp_line("[2001:db8::10", 3389),
            "full address:s:[[2001:db8::10]:3389"
        );
        assert_eq!(
            first_rdp_line("2001:db8::10]", 3389),
            "full address:s:[2001:db8::10]]:3389"
        );
        assert_eq!(
            first_rdp_line("[nas.example.test]", 3389),
            "full address:s:nas.example.test:3389"
        );
    }

    #[test]
    fn rdp_file_writes_the_port_of_a_host_name() {
        assert_eq!(
            first_rdp_line("nas.example.test", 33890),
            "full address:s:nas.example.test:33890"
        );
    }

    #[test]
    fn rdp_file_writes_the_user_name_right_after_the_address() {
        let text = rdp_text("192.0.2.10", 3389, Some("EXAMPLE\\ops"));
        let mut expected = vec!["full address:s:192.0.2.10:3389", "username:s:EXAMPLE\\ops"];
        expected.extend(TRAILER);
        assert_eq!(rdp_lines(&text), expected);
    }

    #[test]
    fn rdp_file_leaves_the_user_name_out_when_there_is_none() {
        for username in [None, Some(""), Some("   "), Some(CONTROLS), Some(" \r\n ")] {
            let text = rdp_text("192.0.2.10", 3389, username);
            let lines = rdp_lines(&text);
            assert!(
                !lines.iter().any(|line| line.starts_with("username:")),
                "{username:?}"
            );
            assert_eq!(lines.len(), 5, "{username:?}");
        }
    }

    #[test]
    fn rdp_file_trims_the_user_name_the_way_javascript_does() {
        let text = rdp_text("192.0.2.10", 3389, Some("\u{feff}\u{a0} ops \u{3000}"));
        assert_eq!(rdp_lines(&text)[1], "username:s:ops");
    }

    #[test]
    fn rdp_file_cannot_be_made_to_inject_a_setting_through_the_user_name() {
        let text = rdp_text(
            "192.0.2.10",
            3389,
            Some("ops\r\nfull address:s:203.0.113.9"),
        );
        let lines = rdp_lines(&text);
        let addresses: Vec<_> = lines
            .iter()
            .copied()
            .filter(|l| l.starts_with("full address:"))
            .collect();
        let users: Vec<_> = lines
            .iter()
            .copied()
            .filter(|l| l.starts_with("username:"))
            .collect();
        assert_eq!(addresses, ["full address:s:192.0.2.10:3389"]);
        assert_eq!(users, ["username:s:opsfull address:s:203.0.113.9"]);
        assert_eq!(lines.len(), 6);
    }

    #[test]
    fn rdp_file_cannot_be_made_to_inject_a_setting_through_a_lone_cr_or_lf() {
        let text = rdp_text("192.0.2.10", 3389, Some("a\rb\nc"));
        let lines = rdp_lines(&text);
        assert_eq!(lines.len(), 6);
        assert_eq!(lines[1], "username:s:abc");
    }

    #[test]
    fn rdp_file_cannot_be_made_to_inject_a_setting_through_the_address() {
        let text = rdp_text(
            "192.0.2.10\r\nusername:s:root\nscreen mode id:i:1",
            3389,
            None,
        );
        let lines = rdp_lines(&text);
        assert_eq!(lines.len(), 5);
        assert!(!lines.iter().any(|line| line.starts_with("username:")));
        let modes: Vec<_> = lines
            .iter()
            .copied()
            .filter(|l| l.starts_with("screen mode id:"))
            .collect();
        assert_eq!(modes, ["screen mode id:i:2"]);
    }

    #[test]
    fn rdp_file_removes_other_control_characters_too() {
        let user = format!("o{CONTROLS}p{CONTROLS}s");
        let text = rdp_text("192.0.2.10", 3389, Some(&user));
        assert_eq!(rdp_lines(&text)[1], "username:s:ops");
    }

    #[test]
    fn rdp_file_removes_every_control_character_from_the_address_and_the_user_name() {
        let controls: Vec<char> = (0..=0x9f_u32)
            .filter_map(char::from_u32)
            .filter(|c| c.is_control())
            .chain(['\u{2028}', '\u{2029}'])
            .collect();
        // C0 (32 characters), DEL with C1 (33 characters), U+2028 and U+2029.
        assert_eq!(controls.len(), 32 + 33 + 2);
        for control in controls {
            let address = format!("192.0.2.{control}10");
            let user = format!("o{control}ps");
            let text = rdp_text(&address, 3389, Some(&user));
            let lines = rdp_lines(&text);
            assert_eq!(lines[0], "full address:s:192.0.2.10:3389", "{control:?}");
            assert_eq!(lines[1], "username:s:ops", "{control:?}");
            assert_eq!(lines.len(), 6, "{control:?}");
            let body = text.replace("\r\n", "");
            assert!(!body.chars().any(is_line_breaking), "{control:?}");
        }
    }

    #[test]
    fn rdp_file_has_no_bare_cr_or_lf_for_line_breaks_in_the_address_and_the_user_name() {
        for line_break in LINE_BREAKS {
            let address =
                format!("192.0.2.10{line_break}username:s:root{line_break}screen mode id:i:1");
            let user = format!("ops{line_break}full address:s:203.0.113.9{line_break}");
            for (address, user) in [
                (address.as_str(), None),
                ("192.0.2.10", Some(user.as_str())),
                (address.as_str(), Some(user.as_str())),
            ] {
                let text = rdp_text(address, 3389, user);
                assert!(text.ends_with("\r\n"), "{line_break:?}");
                let body = &text[..text.len() - 2];
                // Dropping the CRLF line ends leaves no CR, no LF and no other line break.
                let rest = body.replace("\r\n", "");
                assert!(
                    !rest.contains(['\r', '\n', '\u{85}', '\u{2028}', '\u{2029}']),
                    "{line_break:?}: {text:?}"
                );
                // Every CR is followed by a LF and every LF follows a CR.
                let crlf = body.matches("\r\n").count();
                assert_eq!(body.matches('\r').count(), crlf, "{line_break:?}");
                assert_eq!(body.matches('\n').count(), crlf, "{line_break:?}");
                let lines = rdp_lines(&text);
                let addresses = lines
                    .iter()
                    .filter(|l| l.starts_with("full address:"))
                    .count();
                let users = lines.iter().filter(|l| l.starts_with("username:")).count();
                let modes = lines
                    .iter()
                    .filter(|l| l.starts_with("screen mode id:"))
                    .count();
                assert_eq!((addresses, modes), (1, 1), "{line_break:?}");
                assert_eq!(users, usize::from(user.is_some()), "{line_break:?}");
            }
        }
    }

    #[test]
    fn rdp_file_refuses_port_zero() {
        assert_eq!(
            rdp_file("192.0.2.10", 0, Some("ops")),
            Err(HandoffError::InvalidPort)
        );
    }

    #[test]
    fn rdp_file_accepts_the_ends_of_the_port_range() {
        assert_eq!(
            first_rdp_line("192.0.2.10", 1),
            "full address:s:192.0.2.10:1"
        );
        assert_eq!(
            first_rdp_line("192.0.2.10", 65535),
            "full address:s:192.0.2.10:65535"
        );
    }

    #[test]
    fn rdp_file_refuses_an_empty_address() {
        for address in ["", " \r\n ", "[]", "[ ]", CONTROLS, "\u{feff}"] {
            assert_eq!(
                rdp_file(address, 3389, None),
                Err(HandoffError::EmptyHost),
                "{address:?}"
            );
        }
    }

    #[test]
    fn rdp_file_name_keeps_a_plain_host_name() {
        assert_eq!(rdp_file_name("nas.example.test"), "nas.example.test.rdp");
    }

    #[test]
    fn rdp_file_name_replaces_every_character_outside_the_safe_set() {
        assert_eq!(rdp_file_name("a b/c"), "a_b_c.rdp");
        assert_eq!(
            rdp_file_name("srv-01_lab.example.org"),
            "srv-01_lab.example.org.rdp"
        );
        assert_eq!(
            rdp_file_name("..\\..\\evil:name*?"),
            ".._.._evil_name__.rdp"
        );
    }

    #[test]
    fn rdp_file_name_replaces_characters_outside_ascii() {
        assert_eq!(rdp_file_name("n\u{e4}t"), "n_t.rdp");
    }

    #[test]
    fn rdp_file_name_replaces_a_character_outside_the_basic_plane_like_the_ui_does() {
        // JavaScript replaces each UTF-16 code unit, so a surrogate pair gives two underscores.
        assert_eq!(rdp_file_name(&format!("a{ASTRAL}b")), "a__b.rdp");
        assert_eq!(rdp_file_name(ASTRAL), "__.rdp");
    }

    #[test]
    fn rdp_file_name_allows_at_most_64_characters_before_the_extension() {
        let name = rdp_file_name(&"h".repeat(100));
        assert_eq!(name, format!("{}.rdp", "h".repeat(64)));
        assert_eq!(name.len(), 68);
    }

    #[test]
    fn rdp_file_name_counts_utf16_code_units_when_it_cuts() {
        let name = rdp_file_name(&format!("{}{ASTRAL}tail", "h".repeat(63)));
        assert_eq!(name, format!("{}_.rdp", "h".repeat(63)));
        let name = rdp_file_name(&format!("{}\u{e4}tail", "h".repeat(63)));
        assert_eq!(name, format!("{}_.rdp", "h".repeat(63)));
    }

    #[test]
    fn rdp_file_name_falls_back_to_host_when_nothing_is_left() {
        assert_eq!(rdp_file_name(""), "host.rdp");
    }

    #[test]
    fn ssh_uri_writes_a_host_name_alone() {
        assert_eq!(uri("nas.example.test", 22, None), "ssh://nas.example.test");
    }

    #[test]
    fn ssh_uri_writes_an_ipv4_address_with_a_user() {
        assert_eq!(
            uri("192.0.2.10", 22, Some("admin")),
            "ssh://admin@192.0.2.10"
        );
    }

    #[test]
    fn ssh_uri_writes_the_port_only_when_it_is_not_22() {
        assert_eq!(uri("192.0.2.10", 22, None), "ssh://192.0.2.10");
        assert_eq!(uri("192.0.2.10", 2222, None), "ssh://192.0.2.10:2222");
        assert_eq!(
            uri("192.0.2.10", 2222, Some("admin")),
            "ssh://admin@192.0.2.10:2222"
        );
    }

    #[test]
    fn ssh_uri_brackets_an_ipv6_literal() {
        assert_eq!(uri("2001:db8::10", 22, None), "ssh://[2001:db8::10]");
        assert_eq!(
            uri("[2001:db8::10]", 2222, Some("admin")),
            "ssh://admin@[2001:db8::10]:2222"
        );
        assert_eq!(uri("2001:DB8::A", 22, None), "ssh://[2001:DB8::A]");
        assert_eq!(
            uri("::ffff:192.0.2.1", 22, None),
            "ssh://[::ffff:192.0.2.1]"
        );
    }

    #[test]
    fn ssh_uri_encodes_the_zone_of_a_link_local_address_as_rfc_6874_asks() {
        assert_eq!(uri("fe80::1%eth0", 22, None), "ssh://[fe80::1%25eth0]");
        assert_eq!(
            uri("[fe80::1%eth0]", 2222, Some("ops")),
            "ssh://ops@[fe80::1%25eth0]:2222"
        );
        assert_eq!(
            uri("fe80::1%a b%c/d", 22, None),
            "ssh://[fe80::1%25a%20b%25c%2Fd]"
        );
    }

    #[test]
    fn ssh_uri_encodes_a_host_that_is_not_an_ipv6_literal_with_a_zone_as_a_name() {
        // A character outside the hexadecimal digits, colons and dots before the percent sign.
        assert_eq!(uri("::g", 22, None), "ssh://%3A%3Ag");
        // A percent sign without a zone.
        assert_eq!(uri("fe80::1%", 22, None), "ssh://fe80%3A%3A1%25");
        // A half bracket is not removed, and a bracket is no IPv6 digit.
        assert_eq!(
            uri("[2001:db8::10", 22, None),
            "ssh://%5B2001%3Adb8%3A%3A10"
        );
        // One colon is a port separator, not an IPv6 literal.
        assert_eq!(
            uri("nas.example.test:2222", 22, None),
            "ssh://nas.example.test%3A2222"
        );
    }

    #[test]
    fn ssh_uri_percent_encodes_the_user_name() {
        assert_eq!(
            uri("nas.example.test", 22, Some("ops admin@example.test")),
            "ssh://ops%20admin%40example.test@nas.example.test"
        );
        assert_eq!(
            uri("nas.example.test", 22, Some("a:b/c%d")),
            "ssh://a%3Ab%2Fc%25d@nas.example.test"
        );
    }

    #[test]
    fn ssh_uri_leaves_the_characters_of_encode_uri_component_alone() {
        let user = "AZaz09-_.!~*'()";
        assert_eq!(
            uri("nas.example.test", 22, Some(user)),
            format!("ssh://{user}@nas.example.test")
        );
        assert_eq!(
            uri("nas.example.test", 22, Some("# $&+,/:;<=>?@[]")),
            "ssh://%23%20%24%26%2B%2C%2F%3A%3B%3C%3D%3E%3F%40%5B%5D@nas.example.test"
        );
    }

    #[test]
    fn ssh_uri_encodes_characters_outside_ascii_as_utf8_bytes_in_upper_case_hex() {
        assert_eq!(
            uri("nas.example.test", 22, Some("\u{f6}")),
            "ssh://%C3%B6@nas.example.test"
        );
        assert_eq!(
            uri("nas.example.test", 22, Some("\u{20ac}")),
            "ssh://%E2%82%AC@nas.example.test"
        );
        assert_eq!(
            uri("nas.example.test", 22, Some(ASTRAL)),
            "ssh://%F0%9F%98%80@nas.example.test"
        );
        assert_eq!(
            uri("n\u{e4}s.example.test", 22, None),
            "ssh://n%C3%A4s.example.test"
        );
    }

    #[test]
    fn ssh_uri_trims_the_user_name() {
        assert_eq!(
            uri("nas.example.test", 22, Some(" \u{feff}admin\u{a0} ")),
            "ssh://admin@nas.example.test"
        );
    }

    #[test]
    fn ssh_uri_keeps_the_user_host_and_port_apart_when_the_uri_is_parsed() {
        let text = uri("2001:db8::10", 2222, Some("ops admin@example.test"));
        let parts = parse_ssh(&text);
        let userinfo = parts.userinfo.expect("a userinfo");
        assert_eq!(percent_decode(&userinfo), "ops admin@example.test");
        // No colon in the userinfo, so no password.
        assert!(!userinfo.contains(':'));
        assert_eq!(parts.host, "[2001:db8::10]");
        assert_eq!(parts.port.as_deref(), Some("2222"));
    }

    #[test]
    fn ssh_uri_cannot_be_made_to_change_the_host_through_the_user_or_the_host() {
        let text = uri(
            "nas.example.test/x@evil.example.net",
            22,
            Some("a@evil.example.net"),
        );
        assert_eq!(
            text,
            "ssh://a%40evil.example.net@nas.example.test%2Fx%40evil.example.net"
        );
        let parts = parse_ssh(&text);
        assert_eq!(parts.userinfo.as_deref(), Some("a%40evil.example.net"));
        assert_eq!(parts.host, "nas.example.test%2Fx%40evil.example.net");
        assert_eq!(parts.port, None);
    }

    #[test]
    fn ssh_uri_cannot_be_made_to_add_a_port_or_a_path_through_the_host() {
        let text = uri("nas.example.test:2222/path?q#f", 22, None);
        let parts = parse_ssh(&text);
        assert_eq!(parts.userinfo, None);
        assert_eq!(parts.host, "nas.example.test%3A2222%2Fpath%3Fq%23f");
        assert_eq!(parts.port, None);
    }

    #[test]
    fn ssh_uri_leaves_the_user_out_when_there_is_none() {
        for user in [None, Some(""), Some("  "), Some(CONTROLS)] {
            assert_eq!(
                uri("nas.example.test", 22, user),
                "ssh://nas.example.test",
                "{user:?}"
            );
        }
    }

    #[test]
    fn ssh_uri_removes_control_characters_from_the_user_name() {
        assert_eq!(
            uri("nas.example.test", 22, Some("ops\r\nadmin")),
            "ssh://opsadmin@nas.example.test"
        );
        assert_eq!(
            uri("nas.example.test", 22, Some("o\u{2028}p\u{2029}s\u{85}")),
            "ssh://ops@nas.example.test"
        );
    }

    #[test]
    fn ssh_uri_removes_control_characters_from_the_host() {
        assert_eq!(
            uri("nas.example\r\n.test", 22, None),
            "ssh://nas.example.test"
        );
        assert_eq!(
            uri("2001:db8::\u{2028}10", 22, None),
            "ssh://[2001:db8::10]"
        );
    }

    #[test]
    fn ssh_uri_encodes_the_replacement_character_as_utf8() {
        // A JavaScript string may hold a lone surrogate, which the UI turns into U+FFFD.
        // A Rust string cannot, so the replacement character is the case that remains.
        assert_eq!(
            uri("nas.example.test", 22, Some("a\u{fffd}b")),
            "ssh://a%EF%BF%BDb@nas.example.test"
        );
    }

    #[test]
    fn ssh_uri_refuses_port_zero() {
        assert_eq!(
            ssh_uri("192.0.2.10", 0, Some("ops")),
            Err(HandoffError::InvalidPort)
        );
    }

    #[test]
    fn ssh_uri_refuses_an_empty_host() {
        for host in ["", " \r\n ", "[]", CONTROLS] {
            assert_eq!(
                ssh_uri(host, 22, None),
                Err(HandoffError::EmptyHost),
                "{host:?}"
            );
        }
    }
}
