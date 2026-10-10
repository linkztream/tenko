//! Protocol versions of the node transport and their negotiation (OPS-08).
//!
//! Data-plane nodes talk to controllers over gRPC (package `tenko.cluster.v1`). A node offers
//! every protocol major it implements in the handshake; the controller answers with the highest
//! major that both sides implement ([`negotiate`]). When the two sides share none, the call is
//! refused with a [`VersionMismatch`] (code `cluster.protocol.unsupported`) and the controller
//! records a health notice.
//!
//! # The rolling upgrade rule
//!
//! Controllers are upgraded first and keep serving the previous major until every node is
//! upgraded, so a newer side always still speaks the older side's major for one release. When a
//! build introduces major 2, its [`SUPPORTED_MAJORS`] is `[1, 2]`; only the release after that
//! one drops major 1. Today only major 1 exists.
//!
//! | Controller majors | Node majors | Outcome |
//! |---|---|---|
//! | 1 | 1 | major 1 |
//! | 1, 2 | 1 | major 1: the controller was upgraded first and still speaks the old major |
//! | 1, 2 | 1, 2 | major 2 |
//! | 2, 3 | 1, 2, 3 | major 3 |
//! | 2 | 1 | refused: the node must be upgraded |
//! | 1 | 2 | refused: the controller must be upgraded |
//! | none | 1 | refused: the two sides share no protocol major |
//!
//! Major 0 is never valid and never negotiated; an offer that contains it is treated as if the
//! 0 were absent, but the error still reports the offer as it was received.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use tenko_core::Coded;
use utoipa::ToSchema;

/// The newest protocol major this build implements.
pub const CURRENT_MAJOR: u32 = 1;

/// Every protocol major this build implements, in ascending order. The last entry is
/// [`CURRENT_MAJOR`]. By the rolling upgrade rule, the previous major stays in this list for one
/// release after a new one is introduced.
pub const SUPPORTED_MAJORS: &[u32] = &[1];

/// Returns the highest protocol major that both lists contain.
///
/// The order of the lists and duplicates in them do not matter. Major 0 is never valid and is
/// ignored.
///
/// # Errors
///
/// Returns a [`VersionMismatch`] carrying both offers when the two lists share no valid major.
pub fn negotiate(ours: &[u32], theirs: &[u32]) -> Result<u32, VersionMismatch> {
    ours.iter()
        .copied()
        .filter(|major| *major != 0 && theirs.contains(major))
        .max()
        .ok_or_else(|| VersionMismatch::new(ours, theirs))
}

/// Which side of a failed negotiation implements the newer protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Newer {
    /// This side has the higher highest major, so the other side must be upgraded.
    Ours,
    /// The other side has the higher highest major, so this side must be upgraded.
    Theirs,
    /// The highest majors are equal, or a side offered no major at all: neither side is ahead.
    Neither,
}

/// The two sides share no protocol major (`cluster.protocol.unsupported`, HTTP 409).
///
/// Both lists are kept as they were offered, sorted ascending and without duplicates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct VersionMismatch {
    /// The majors this side implements, sorted ascending and deduplicated.
    pub ours: Vec<u32>,
    /// The majors the other side offered, sorted ascending and deduplicated.
    pub theirs: Vec<u32>,
}

impl VersionMismatch {
    /// Builds a mismatch from the two offers. Both lists are sorted and deduplicated.
    pub fn new(ours: &[u32], theirs: &[u32]) -> Self {
        Self {
            ours: sorted_unique(ours),
            theirs: sorted_unique(theirs),
        }
    }

    /// Compares the highest major of each side. The result is [`Newer::Neither`] when they are
    /// equal or when a side offered no major.
    pub fn newer(&self) -> Newer {
        match (self.ours.iter().max(), self.theirs.iter().max()) {
            (Some(ours), Some(theirs)) if ours > theirs => Newer::Ours,
            (Some(ours), Some(theirs)) if ours < theirs => Newer::Theirs,
            _ => Newer::Neither,
        }
    }

    /// Describes the mismatch in one English sentence and says which side to upgrade.
    ///
    /// `our_side` and `their_side` are complete noun phrases that are used as they are, for
    /// example `"the controller"` and `"the node"`. The advice names the side with the lower
    /// highest major. When neither side is ahead (see [`Newer::Neither`]) the sentence ends with
    /// `; the two sides share no protocol major` instead.
    ///
    /// ```text
    /// the controller implements protocol major 1 and the node offers 0; upgrade the node
    /// ```
    pub fn detail(&self, our_side: &str, their_side: &str) -> String {
        let advice = match self.newer() {
            Newer::Ours => format!("upgrade {their_side}"),
            Newer::Theirs => format!("upgrade {our_side}"),
            Newer::Neither => "the two sides share no protocol major".to_owned(),
        };
        format!(
            "{our_side} implements {} and {their_side} offers {}; {advice}",
            implemented(&self.ours),
            offered(&self.theirs),
        )
    }
}

impl fmt::Display for VersionMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail("this side", "the other side"))
    }
}

impl std::error::Error for VersionMismatch {}

impl Coded for VersionMismatch {
    fn code(&self) -> &'static str {
        "cluster.protocol.unsupported"
    }

    fn http_status(&self) -> u16 {
        409
    }

    fn params(&self) -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            ("ours", format_majors(&self.ours)),
            ("theirs", format_majors(&self.theirs)),
        ])
    }
}

/// Formats a list of majors as comma-separated text, for example `1, 2`. An empty list is
/// `none`.
pub fn format_majors(majors: &[u32]) -> String {
    if majors.is_empty() {
        return "none".to_owned();
    }
    majors
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Parses a list of majors as written by [`format_majors`].
///
/// Entries are separated by commas and may be surrounded by spaces, for example `1,2` or
/// ` 1 , 2 `. The order is kept as written. An empty text and `none` give an empty list.
///
/// # Errors
///
/// Returns a [`ParseMajorsError`] for anything else: an empty entry (`1,,2`), a sign (`-1`),
/// a word, or a number that does not fit in a `u32`.
pub fn parse_majors(text: &str) -> Result<Vec<u32>, ParseMajorsError> {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed == "none" {
        return Ok(Vec::new());
    }
    trimmed
        .split(',')
        .map(|entry| {
            let entry = entry.trim();
            if entry.is_empty() || !entry.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            entry.parse::<u32>().ok()
        })
        .collect::<Option<Vec<u32>>>()
        .ok_or_else(|| ParseMajorsError {
            text: text.to_owned(),
        })
}

/// The text given to [`parse_majors`] is not a list of protocol majors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a list of protocol majors: {text}")]
pub struct ParseMajorsError {
    /// The text that was rejected, as it was given.
    pub text: String,
}

fn sorted_unique(majors: &[u32]) -> Vec<u32> {
    let mut sorted = majors.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    sorted
}

/// What a side implements: `protocol major 1`, `protocol majors 1, 2` or `no protocol major`.
fn implemented(majors: &[u32]) -> String {
    match majors {
        [] => "no protocol major".to_owned(),
        [one] => format!("protocol major {one}"),
        several => format!("protocol majors {}", format_majors(several)),
    }
}

/// What a side offers: `0`, `0, 1` or `no protocol major`.
fn offered(majors: &[u32]) -> String {
    if majors.is_empty() {
        "no protocol major".to_owned()
    } else {
        format_majors(majors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTROLLER: &str = "the controller";
    const NODE: &str = "the node";

    /// The expected result of one negotiation.
    #[derive(Debug, Clone, Copy)]
    enum Expect {
        Major(u32),
        Mismatch(Newer),
    }

    #[test]
    fn negotiate_table() {
        use Expect::{Major, Mismatch};
        let rows: &[(&[u32], &[u32], Expect)] = &[
            (&[1], &[1], Major(1)),
            (&[1, 2], &[1], Major(1)),
            (&[1], &[1, 2], Major(1)),
            (&[1, 2], &[1, 2], Major(2)),
            (&[2, 3], &[1, 2, 3], Major(3)),
            (&[3, 1, 2], &[2, 3, 1], Major(3)),
            (&[2, 1, 2], &[1], Major(1)),
            (&[1], &[0], Mismatch(Newer::Ours)),
            (&[2], &[1], Mismatch(Newer::Ours)),
            (&[1], &[2], Mismatch(Newer::Theirs)),
            (&[], &[], Mismatch(Newer::Neither)),
            (&[0, 1], &[0], Mismatch(Newer::Ours)),
            (&[0], &[0], Mismatch(Newer::Neither)),
            (&[1], &[], Mismatch(Newer::Neither)),
            (&[], &[1], Mismatch(Newer::Neither)),
            (&[1, 3], &[2, 4], Mismatch(Newer::Theirs)),
        ];
        for (ours, theirs, expect) in rows {
            let result = negotiate(ours, theirs);
            match (expect, &result) {
                (Major(want), Ok(got)) => {
                    assert_eq!(got, want, "ours {ours:?}, theirs {theirs:?}");
                }
                (Mismatch(want), Err(error)) => {
                    assert_eq!(error.newer(), *want, "ours {ours:?}, theirs {theirs:?}");
                    assert_eq!(error.ours, sorted_unique(ours));
                    assert_eq!(error.theirs, sorted_unique(theirs));
                }
                _ => {
                    panic!("ours {ours:?}, theirs {theirs:?}: expected {expect:?}, got {result:?}")
                }
            }
        }
    }

    #[test]
    fn negotiate_is_symmetric_in_the_major_and_mirrors_the_mismatch() {
        assert_eq!(negotiate(&[1, 2], &[2, 3]), negotiate(&[2, 3], &[1, 2]));
        let forward = negotiate(&[2], &[1]).unwrap_err();
        let backward = negotiate(&[1], &[2]).unwrap_err();
        assert_eq!(forward.newer(), Newer::Ours);
        assert_eq!(backward.newer(), Newer::Theirs);
        assert_eq!(forward.ours, backward.theirs);
        assert_eq!(forward.theirs, backward.ours);
    }

    #[test]
    fn mismatch_keeps_the_offers_sorted_and_without_duplicates() {
        let error = negotiate(&[4, 2, 4], &[3, 3, 1]).unwrap_err();
        assert_eq!(error.ours, [2, 4]);
        assert_eq!(error.theirs, [1, 3]);
        let error = negotiate(&[1], &[]).unwrap_err();
        assert_eq!(error.ours, [1]);
        assert_eq!(error.theirs, Vec::<u32>::new());
    }

    #[test]
    fn supported_majors_are_ascending_and_end_with_the_current_major() {
        assert_eq!(SUPPORTED_MAJORS.last(), Some(&CURRENT_MAJOR));
        assert!(SUPPORTED_MAJORS.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(!SUPPORTED_MAJORS.contains(&0));
    }

    #[test]
    fn this_build_negotiates_with_itself() {
        assert_eq!(
            negotiate(SUPPORTED_MAJORS, SUPPORTED_MAJORS),
            Ok(CURRENT_MAJOR)
        );
    }

    #[test]
    fn detail_for_a_node_that_offers_only_an_older_major() {
        let error = negotiate(&[1], &[0]).unwrap_err();
        assert_eq!(
            error.detail(CONTROLLER, NODE),
            "the controller implements protocol major 1 and the node offers 0; upgrade the node"
        );
    }

    #[test]
    fn detail_for_a_node_that_offers_only_a_newer_major() {
        let error = negotiate(&[1], &[2, 3]).unwrap_err();
        assert_eq!(
            error.detail(CONTROLLER, NODE),
            "the controller implements protocol major 1 and the node offers 2, 3; \
             upgrade the controller"
        );
    }

    #[test]
    fn detail_for_a_controller_with_several_majors() {
        let error = negotiate(&[3, 2], &[1]).unwrap_err();
        assert_eq!(
            error.detail(CONTROLLER, NODE),
            "the controller implements protocol majors 2, 3 and the node offers 1; \
             upgrade the node"
        );
    }

    #[test]
    fn detail_for_an_empty_offer() {
        let error = negotiate(&[1], &[]).unwrap_err();
        assert_eq!(
            error.detail(CONTROLLER, NODE),
            "the controller implements protocol major 1 and the node offers no protocol major; \
             the two sides share no protocol major"
        );
        let error = negotiate(&[], &[1]).unwrap_err();
        assert_eq!(
            error.detail(CONTROLLER, NODE),
            "the controller implements no protocol major and the node offers 1; \
             the two sides share no protocol major"
        );
    }

    #[test]
    fn detail_for_equal_highest_majors() {
        let error = negotiate(&[0], &[0]).unwrap_err();
        assert_eq!(
            error.detail(CONTROLLER, NODE),
            "the controller implements protocol major 0 and the node offers 0; \
             the two sides share no protocol major"
        );
    }

    #[test]
    fn detail_uses_the_side_names_it_is_given() {
        let error = negotiate(&[1], &[2]).unwrap_err();
        assert_eq!(
            error.detail("the probe", "the hub"),
            "the probe implements protocol major 1 and the hub offers 2; upgrade the probe"
        );
    }

    #[test]
    fn display_uses_neutral_side_names() {
        let error = negotiate(&[1], &[0]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "this side implements protocol major 1 and the other side offers 0; \
             upgrade the other side"
        );
        let error = negotiate(&[1], &[2]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "this side implements protocol major 1 and the other side offers 2; \
             upgrade this side"
        );
    }

    #[test]
    fn mismatch_is_a_coded_error() {
        let error = negotiate(&[1, 2], &[3]).unwrap_err();
        assert_eq!(error.code(), "cluster.protocol.unsupported");
        assert_eq!(error.http_status(), 409);
        assert_eq!(
            error.params(),
            BTreeMap::from([("ours", "1, 2".to_owned()), ("theirs", "3".to_owned())])
        );
        let empty = negotiate(&[1], &[]).unwrap_err();
        assert_eq!(empty.params()["theirs"], "none");
        let coded = error.to_coded_error();
        assert_eq!(coded.code, "cluster.protocol.unsupported");
        assert_eq!(coded.status, 409);
        assert_eq!(coded.detail, error.to_string());
    }

    #[test]
    fn mismatch_is_a_std_error() {
        fn takes_error(_: &dyn std::error::Error) {}
        takes_error(&VersionMismatch::new(&[1], &[2]));
    }

    #[test]
    fn format_majors_text() {
        assert_eq!(format_majors(&[]), "none");
        assert_eq!(format_majors(&[1]), "1");
        assert_eq!(format_majors(&[1, 2]), "1, 2");
        assert_eq!(format_majors(&[3, 1]), "3, 1");
    }

    #[test]
    fn parse_majors_accepts_lists_and_the_empty_list() {
        assert_eq!(parse_majors("1"), Ok(vec![1]));
        assert_eq!(parse_majors("1,2"), Ok(vec![1, 2]));
        assert_eq!(parse_majors(" 1 , 2 "), Ok(vec![1, 2]));
        assert_eq!(parse_majors("0"), Ok(vec![0]));
        assert_eq!(parse_majors(""), Ok(Vec::new()));
        assert_eq!(parse_majors("  "), Ok(Vec::new()));
        assert_eq!(parse_majors("none"), Ok(Vec::new()));
        assert_eq!(parse_majors(" none "), Ok(Vec::new()));
    }

    #[test]
    fn parse_majors_round_trips_format_majors() {
        for majors in [&[][..], &[1], &[1, 2], &[2, 3, 7], &[0, u32::MAX]] {
            assert_eq!(parse_majors(&format_majors(majors)).as_deref(), Ok(majors));
        }
    }

    #[test]
    fn parse_majors_rejects_everything_else() {
        for text in [
            "1,x",
            "-1",
            "+1",
            "1,,2",
            "1,",
            ",1",
            "x",
            "1 2",
            "1;2",
            "none,1",
            "1,none",
            "None",
            "4294967296",
            "1.5",
        ] {
            let error = parse_majors(text).unwrap_err();
            assert_eq!(error.text, text);
            assert_eq!(
                error.to_string(),
                format!("not a list of protocol majors: {text}")
            );
        }
    }

    #[test]
    fn mismatch_json_round_trip() {
        let error = negotiate(&[1], &[0]).unwrap_err();
        let json = serde_json::to_string(&error).unwrap();
        assert_eq!(json, r#"{"ours":[1],"theirs":[0]}"#);
        let back: VersionMismatch = serde_json::from_str(&json).unwrap();
        assert_eq!(back, error);
        let parsed: VersionMismatch =
            serde_json::from_str(r#"{"ours":[1,2],"theirs":[]}"#).unwrap();
        assert_eq!(parsed, VersionMismatch::new(&[2, 1], &[]));
    }
}
