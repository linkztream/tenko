//! Free-space search for next free (IPAM-07), shared by the planner (over a read view)
//! and the prefix tree (over its in-memory image), so both pick the same candidate.
//!
//! Blocked space is a list of inclusive intervals of numbers within one address family;
//! the functions sort and merge it themselves.

use tenko_core::ipam::AllocPolicy;

use crate::net::{Family, align_down, align_up, host_mask};

/// Sorts and merges inclusive intervals, joining adjacent ones.
pub fn merge(mut blocked: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    blocked.retain(|(first, last)| first <= last);
    blocked.sort_unstable();
    let mut merged: Vec<(u128, u128)> = Vec::with_capacity(blocked.len());
    for (first, last) in blocked {
        match merged.last_mut() {
            Some((_, end)) if end.checked_add(1).is_none_or(|next| first <= next) => {
                *end = (*end).max(last);
            }
            _ => merged.push((first, last)),
        }
    }
    merged
}

/// The free number in `[lo, hi]` closest to the policy's end, outside every blocked
/// interval, or `None` when everything is blocked.
pub fn first_free(
    lo: u128,
    hi: u128,
    blocked: Vec<(u128, u128)>,
    policy: AllocPolicy,
) -> Option<u128> {
    if lo > hi {
        return None;
    }
    let blocked = merge(blocked);
    match policy {
        AllocPolicy::Lowest => {
            let mut candidate = lo;
            for (first, last) in &blocked {
                if *last < candidate {
                    continue;
                }
                if *first > candidate {
                    break;
                }
                candidate = last.checked_add(1)?;
            }
            (candidate <= hi).then_some(candidate)
        }
        AllocPolicy::Highest => {
            let mut candidate = hi;
            for (first, last) in blocked.iter().rev() {
                if *first > candidate {
                    continue;
                }
                if *last < candidate {
                    break;
                }
                candidate = first.checked_sub(1)?;
            }
            (candidate >= lo).then_some(candidate)
        }
    }
}

/// Like [`first_free`], but walks a sorted set of used numbers lazily, so the cost is the
/// number of used addresses before the first gap rather than all of them.
pub fn first_free_lazy<V>(
    lo: u128,
    hi: u128,
    blocked: Vec<(u128, u128)>,
    used: &std::collections::BTreeMap<u128, V>,
    policy: AllocPolicy,
) -> Option<u128> {
    if lo > hi {
        return None;
    }
    let blocked = merge(blocked);
    match policy {
        AllocPolicy::Lowest => {
            let mut candidate = lo;
            let mut index = 0;
            let mut addresses = used.range(lo..=hi).map(|(key, _)| key).peekable();
            loop {
                if candidate > hi {
                    return None;
                }
                while index < blocked.len() && blocked[index].1 < candidate {
                    index += 1;
                }
                if let Some((first, last)) = blocked.get(index)
                    && *first <= candidate
                {
                    candidate = last.checked_add(1)?;
                    continue;
                }
                while addresses.peek().is_some_and(|a| **a < candidate) {
                    addresses.next();
                }
                if addresses.peek() == Some(&&candidate) {
                    candidate = candidate.checked_add(1)?;
                    continue;
                }
                return Some(candidate);
            }
        }
        AllocPolicy::Highest => {
            let mut candidate = hi;
            let mut index = blocked.len();
            let mut addresses = used.range(lo..=hi).rev().map(|(key, _)| key).peekable();
            loop {
                if candidate < lo {
                    return None;
                }
                while index > 0 && blocked[index - 1].0 > candidate {
                    index -= 1;
                }
                if let Some((first, last)) = index.checked_sub(1).and_then(|i| blocked.get(i))
                    && *last >= candidate
                {
                    candidate = first.checked_sub(1)?;
                    continue;
                }
                while addresses.peek().is_some_and(|a| **a > candidate) {
                    addresses.next();
                }
                if addresses.peek() == Some(&&candidate) {
                    candidate = candidate.checked_sub(1)?;
                    continue;
                }
                return Some(candidate);
            }
        }
    }
}

/// The start of the free aligned block of prefix length `len` inside `[lo, hi]` closest
/// to the policy's end that overlaps no blocked interval, or `None`.
pub fn first_free_block(
    family: Family,
    lo: u128,
    hi: u128,
    len: u8,
    blocked: Vec<(u128, u128)>,
    policy: AllocPolicy,
) -> Option<u128> {
    let size_minus_one = host_mask(family, len);
    let blocked = merge(blocked);
    match policy {
        AllocPolicy::Lowest => {
            let mut candidate = align_up(family, lo, len)?;
            let mut index = 0;
            loop {
                let end = candidate.checked_add(size_minus_one)?;
                if end > hi {
                    return None;
                }
                while index < blocked.len() && blocked[index].1 < candidate {
                    index += 1;
                }
                match blocked.get(index) {
                    Some((first, last)) if *first <= end => {
                        candidate = align_up(family, last.checked_add(1)?, len)?;
                    }
                    _ => return Some(candidate),
                }
            }
        }
        AllocPolicy::Highest => {
            let top = hi.checked_sub(size_minus_one)?;
            let mut candidate = align_down(family, top, len);
            let mut index = blocked.len();
            loop {
                if candidate < lo {
                    return None;
                }
                let end = candidate + size_minus_one;
                while index > 0 && blocked[index - 1].0 > end {
                    index -= 1;
                }
                match index.checked_sub(1).and_then(|i| blocked.get(i)) {
                    Some((first, last)) if *last >= candidate => {
                        let below = first.checked_sub(1)?;
                        let top = below.checked_sub(size_minus_one)?;
                        candidate = align_down(family, top, len);
                    }
                    _ => return Some(candidate),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_joins_overlapping_and_adjacent() {
        assert_eq!(
            merge(vec![(5, 6), (1, 2), (3, 3), (10, 12), (11, 20)]),
            vec![(1, 3), (5, 6), (10, 20)]
        );
        assert_eq!(merge(vec![(u128::MAX, u128::MAX), (0, 0)]).len(), 2);
    }

    #[test]
    fn first_free_from_both_ends() {
        let blocked = vec![(1, 3), (5, 5), (9, 10)];
        assert_eq!(
            first_free(1, 10, blocked.clone(), AllocPolicy::Lowest),
            Some(4)
        );
        assert_eq!(
            first_free(1, 10, blocked.clone(), AllocPolicy::Highest),
            Some(8)
        );
        assert_eq!(first_free(1, 3, blocked.clone(), AllocPolicy::Lowest), None);
        assert_eq!(first_free(9, 10, blocked, AllocPolicy::Highest), None);
        assert_eq!(first_free(0, 0, vec![], AllocPolicy::Highest), Some(0));
    }

    #[test]
    fn lazy_search_matches_the_eager_one() {
        let used: std::collections::BTreeMap<u128, u8> =
            [1, 2, 3, 6, 7, 20].into_iter().map(|u| (u, 0)).collect();
        let blocked = vec![(4, 5), (15, 18)];
        for policy in [AllocPolicy::Lowest, AllocPolicy::Highest] {
            for (lo, hi) in [(1, 20), (1, 7), (6, 7), (2, 19), (0, 0)] {
                let mut eager = blocked.clone();
                eager.extend(used.keys().map(|u| (*u, *u)));
                assert_eq!(
                    first_free_lazy(lo, hi, blocked.clone(), &used, policy),
                    first_free(lo, hi, eager, policy),
                    "{lo}..={hi} {policy:?}"
                );
            }
        }
    }

    #[test]
    fn first_free_block_aligns() {
        // A /24 as numbers 0..=255; /26 blocks; 0..=63 used and an address at 70.
        let blocked = vec![(0, 63), (70, 70)];
        assert_eq!(
            first_free_block(Family::V4, 0, 255, 26, blocked.clone(), AllocPolicy::Lowest),
            Some(128)
        );
        assert_eq!(
            first_free_block(
                Family::V4,
                0,
                255,
                26,
                blocked.clone(),
                AllocPolicy::Highest
            ),
            Some(192)
        );
        let full = vec![(0, 255)];
        assert_eq!(
            first_free_block(Family::V4, 0, 255, 26, full, AllocPolicy::Lowest),
            None
        );
        let top_used = vec![(128, 255)];
        assert_eq!(
            first_free_block(Family::V4, 0, 255, 25, top_used, AllocPolicy::Highest),
            Some(0)
        );
    }
}
