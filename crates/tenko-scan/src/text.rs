//! Text from the network: the one cleaning every parser of the crate applies to a string a
//! peer sent (DNS names and TXT strings, LLDP and CDP TLVs, DHCP options, SNMP octet strings).
//!
//! A peer chooses these bytes, and they reach the status file, the API, the web interface and
//! an administrator's terminal. [`clean_text`] reads them as lossy UTF-8 and removes what a
//! display would act on or hide instead of showing: control characters (C0, DEL and C1, so
//! terminal escape sequences, bells and line breaks) and the invisible direction and format
//! marks of [`is_unsafe_char`].

/// The longest text kept, in characters.
pub const MAX_TEXT_CHARS: usize = 255;

/// True for a character that is not shown as itself: a control character (C0, DEL, C1) or an
/// invisible direction or format mark (zero-width space, the bidirectional marks, embeddings,
/// overrides and isolates, the line and paragraph separators, the word joiner and the
/// invisible operators, the byte order mark, the interlinear annotation marks).
pub fn is_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061c}'
                | '\u{200b}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
        )
}

/// Bytes as text: lossy UTF-8, every [`is_unsafe_char`] removed, trimmed, cut to
/// [`MAX_TEXT_CHARS`] characters; `None` when nothing is left.
pub fn clean_text(bytes: &[u8]) -> Option<String> {
    let text: String = String::from_utf8_lossy(bytes)
        .chars()
        .filter(|c| !is_unsafe_char(*c))
        .collect();
    let cut: String = text.trim().chars().take(MAX_TEXT_CHARS).collect();
    (!cut.is_empty()).then_some(cut)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_are_removed() {
        assert_eq!(clean_text(b"a\x1b[31mb"), Some("a[31mb".to_owned()), "ESC");
        assert_eq!(clean_text(b"ring\x07"), Some("ring".to_owned()), "BEL");
        assert_eq!(clean_text(b"de\x7fl"), Some("del".to_owned()), "DEL");
        assert_eq!(clean_text(b"a\x00b"), Some("ab".to_owned()), "NUL");
        assert_eq!(
            clean_text("tab\tnew\nline\rend".as_bytes()),
            Some("tabnewlineend".to_owned())
        );
        assert_eq!(
            clean_text("c1\u{9b}31m".as_bytes()),
            Some("c131m".to_owned()),
            "C1 CSI"
        );
    }

    #[test]
    fn direction_and_format_marks_are_removed() {
        assert_eq!(
            clean_text("\u{202e}name".as_bytes()),
            Some("name".to_owned()),
            "U+202E"
        );
        for mark in [
            '\u{061c}', '\u{200b}', '\u{200e}', '\u{200f}', '\u{2028}', '\u{2029}', '\u{202a}',
            '\u{2060}', '\u{2066}', '\u{2069}', '\u{feff}', '\u{fffb}',
        ] {
            let text = format!("a{mark}b");
            assert_eq!(
                clean_text(text.as_bytes()),
                Some("ab".to_owned()),
                "{mark:?}"
            );
        }
    }

    #[test]
    fn a_mixed_string_keeps_only_what_is_shown() {
        let mixed = "\u{feff} sw\x1b]0;x\x07itch\u{202e}-a\r\n\x7f ";
        assert_eq!(
            clean_text(mixed.as_bytes()),
            Some("sw]0;xitch-a".to_owned())
        );
        assert_eq!(
            clean_text(&[b'o', 0xff, b'k']),
            Some("o\u{fffd}k".to_owned())
        );
    }

    #[test]
    fn clean_text_is_unchanged() {
        for clean in [
            "switch-a.example.test",
            "GigabitEthernet0/2",
            "Café Printer",
            "Göteborg",
            "laptop",
        ] {
            assert_eq!(clean_text(clean.as_bytes()).as_deref(), Some(clean));
        }
    }

    #[test]
    fn text_is_trimmed_cut_and_none_when_empty() {
        assert_eq!(
            clean_text(b"  switch-a.example.net \r\n"),
            Some("switch-a.example.net".to_owned())
        );
        assert_eq!(clean_text(b""), None);
        assert_eq!(clean_text(b" \t\n\x00"), None);
        assert_eq!(clean_text("\u{202e}\u{200b}".as_bytes()), None);
        assert_eq!(
            clean_text(&[b'x'; 300]).map(|text| text.chars().count()),
            Some(MAX_TEXT_CHARS)
        );
        let long = "\u{f6}".repeat(300);
        assert_eq!(
            clean_text(long.as_bytes()).map(|text| text.chars().count()),
            Some(MAX_TEXT_CHARS)
        );
    }
}
