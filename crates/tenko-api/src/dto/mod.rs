//! Data transfer objects of the platform endpoints, shared by the server and the client
//! (feature `client`).
//!
//! Domain DTOs live with their areas (the IPAM model in `tenko_core::ipam`, for example);
//! this module holds the shapes every area shares, [`Page`] above all, and the bodies of the
//! audit, events and system endpoints.

use serde::{Deserialize, Serialize};
use tenko_core::Revision;
use utoipa::ToSchema;

pub mod audit;
pub mod events;
pub mod release;
pub mod system;
pub mod updates;

/// One page of a list (plan section 4): the items, the opaque cursor of the next page and
/// the store revision the page was read at.
///
/// A client that wants live updates subscribes to `GET /events` from `revision`; a client
/// that wants the next page passes `next_cursor` back as `cursor`. The cursor is opaque and
/// bound to the query that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Page<T> {
    /// The items of this page, at most `limit` of them.
    pub items: Vec<T>,
    /// Cursor of the next page; `null` on the last page.
    pub next_cursor: Option<String>,
    /// Store revision the page was read at.
    pub revision: Revision,
}

impl<T> Page<T> {
    /// A page from its parts.
    pub fn new(items: Vec<T>, next_cursor: Option<String>, revision: Revision) -> Self {
        Self {
            items,
            next_cursor,
            revision,
        }
    }

    /// Maps the items, keeping the cursor and the revision.
    #[must_use]
    pub fn map<U>(self, f: impl FnMut(T) -> U) -> Page<U> {
        Page {
            items: self.items.into_iter().map(f).collect(),
            next_cursor: self.next_cursor,
            revision: self.revision,
        }
    }
}

/// Sort direction of lists that only sort by their natural key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SortOrder {
    /// Oldest or lowest first.
    Asc,
    /// Newest or highest first.
    #[default]
    Desc,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_shape_matches_the_plan() {
        let page = Page::new(vec![1, 2], Some("abc".to_owned()), Revision(7));
        assert_eq!(
            serde_json::to_value(&page).expect("json"),
            serde_json::json!({ "items": [1, 2], "next_cursor": "abc", "revision": 7 })
        );
        let last: Page<u8> = Page::new(vec![], None, Revision(7));
        assert_eq!(
            serde_json::to_value(&last).expect("json")["next_cursor"],
            serde_json::Value::Null
        );
        assert_eq!(page.map(|n| n * 10).items, vec![10, 20]);
    }
}
