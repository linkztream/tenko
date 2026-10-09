//! Field-level differences between two versions of an object, rendered as text for the
//! audit log (`AuditDetails::changes`), the history and plan previews.

use serde_json::{Map, Value};
use tenko_core::audit::FieldChange;

use crate::object::IpamObject;

/// Fields that change on every write and carry no information for a reviewer.
const IGNORED: [&str; 2] = ["meta.revision", "meta.updated"];

/// The changed fields between `before` and `after` (either may be absent), sorted by
/// field path. Nested objects are flattened one level for `meta` (`meta.tags`).
pub fn diff(before: Option<&IpamObject>, after: Option<&IpamObject>) -> Vec<FieldChange> {
    let before = before.map(fields).unwrap_or_default();
    let after = after.map(fields).unwrap_or_default();
    let mut keys: Vec<&String> = before.keys().chain(after.keys()).collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .filter(|key| !IGNORED.contains(&key.as_str()))
        .filter_map(|key| {
            let old = before.get(key).and_then(render);
            let new = after.get(key).and_then(render);
            (old != new).then(|| FieldChange {
                object: None,
                field: key.clone(),
                old,
                new,
            })
        })
        .collect()
}

/// Whether two versions differ in anything a reviewer sees.
pub fn same(before: &IpamObject, after: &IpamObject) -> bool {
    diff(Some(before), Some(after)).is_empty()
}

fn fields(object: &IpamObject) -> Map<String, Value> {
    let mut out = Map::new();
    let Ok(Value::Object(mut tagged)) = serde_json::to_value(object) else {
        return out;
    };
    let Some(Value::Object(data)) = tagged.remove("data") else {
        return out;
    };
    for (key, value) in data {
        match (key.as_str(), value) {
            ("meta", Value::Object(meta)) => {
                for (inner, value) in meta {
                    out.insert(format!("meta.{inner}"), value);
                }
            }
            (_, value) => {
                out.insert(key, value);
            }
        }
    }
    out
}

fn render(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(text) => Some(text.clone()),
        Value::Array(items) if items.is_empty() => None,
        Value::Object(map) if map.is_empty() => None,
        other => Some(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::prefix;

    #[test]
    fn diff_lists_changed_fields_only() {
        let before = prefix("192.0.2.0/24");
        let mut after = before.clone();
        after.cidr = "192.0.2.0/23".parse().expect("cidr");
        after.meta.description = Some("lab".to_owned());
        after.meta.revision = tenko_core::Revision(9);
        let changes = diff(
            Some(&IpamObject::Prefix(before.clone())),
            Some(&IpamObject::Prefix(after)),
        );
        let fields: Vec<&str> = changes.iter().map(|c| c.field.as_str()).collect();
        assert_eq!(fields, ["cidr", "meta.description"]);
        assert_eq!(changes[0].old.as_deref(), Some("192.0.2.0/24"));
        assert_eq!(changes[0].new.as_deref(), Some("192.0.2.0/23"));
        assert_eq!(changes[1].old, None);

        let created = diff(None, Some(&IpamObject::Prefix(before.clone())));
        assert!(created.iter().any(|c| c.field == "cidr" && c.old.is_none()));
        assert!(same(
            &IpamObject::Prefix(before.clone()),
            &IpamObject::Prefix(before)
        ));
    }
}
