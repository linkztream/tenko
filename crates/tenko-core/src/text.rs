//! The characters a text from outside Tenko may not carry to where an operator reads it.
//!
//! [`is_hidden`] holds for the control characters (Unicode category Cc: C0, DEL and C1),
//! which can break a line or start a terminal sequence, and for the format characters that
//! reorder or hide text without being seen: the bidirectional marks, embeddings, overrides
//! and isolates (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069), the zero-width
//! characters (U+200B to U+200D, U+2060 to U+2064, U+FEFF), the interlinear annotation
//! characters (U+FFF9 to U+FFFB) and the tag characters (U+E0001, U+E0020 to U+E007F). Text
//! in Arabic or Hebrew needs none of them to read right; the bidirectional algorithm orders
//! it from its letters.
//!
//! Not covered: the other format characters (the soft hyphen, the number signs of Arabic
//! script, the Mongolian vowel separator and a few of historic scripts), which some writing
//! needs and none of which moves text; combining marks; and letters of one script that look
//! like letters of another. The Windows DHCP exporter strips the same list from its log
//! (`ConvertTo-LogText` in `deploy/windows/mirror/Tenko-DhcpMirror.ps1`).

/// The format characters [`is_hidden`] holds for besides category Cc.
const HIDDEN_FORMAT: [(char, char); 9] = [
    ('\u{061C}', '\u{061C}'),
    ('\u{200B}', '\u{200F}'),
    ('\u{202A}', '\u{202E}'),
    ('\u{2060}', '\u{2064}'),
    ('\u{2066}', '\u{2069}'),
    ('\u{FEFF}', '\u{FEFF}'),
    ('\u{FFF9}', '\u{FFFB}'),
    ('\u{E0001}', '\u{E0001}'),
    ('\u{E0020}', '\u{E007F}'),
];

/// Whether `c` is a control character or a format character that reorders or hides text.
pub fn is_hidden(c: char) -> bool {
    c.is_control()
        || HIDDEN_FORMAT
            .iter()
            .any(|(first, last)| (*first..=*last).contains(&c))
}

/// The first such character of `text`.
pub fn first_hidden(text: &str) -> Option<char> {
    text.chars().find(|c| is_hidden(*c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_listed_characters_and_no_letter_are_hidden() {
        for c in [
            '\0',
            '\u{1b}',
            '\u{7f}',
            '\u{9b}',
            '\u{061C}',
            '\u{200B}',
            '\u{200F}',
            '\u{202A}',
            '\u{202E}',
            '\u{2060}',
            '\u{2064}',
            '\u{2066}',
            '\u{2069}',
            '\u{FEFF}',
            '\u{FFF9}',
            '\u{FFFB}',
            '\u{E0001}',
            '\u{E0020}',
            '\u{E007F}',
        ] {
            assert!(is_hidden(c), "U+{:04X}", u32::from(c));
        }
        for c in [
            'a',
            ' ',
            '\u{00AD}',
            '\u{0627}',
            '\u{05D0}',
            '\u{200A}',
            '\u{2010}',
            '\u{2065}',
            '\u{FFFC}',
            '\u{E0000}',
            '\u{E0080}',
        ] {
            assert!(!is_hidden(c), "U+{:04X}", u32::from(c));
        }
        assert_eq!(first_hidden("192.0.2.\u{202E}01"), Some('\u{202E}'));
        assert_eq!(first_hidden("שרת مكتب"), None);
    }
}
