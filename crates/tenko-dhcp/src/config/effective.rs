//! The options a client gets in a scope, and why (plan section 2.4).
//!
//! The levels merge from the least to the most specific, the later level winning per space
//! and code, in the order of [`tenko_core::dhcp::merge`]: the server, the scope's shared
//! network, the scope, the policies that match the client, and the client's reservation
//! (the option set of its IPAM interface). Among matching policies the first in order wins
//! per code, as the first matching policy wins per action. Pool options depend on the
//! address the allocator picks and are shown on the pool, not here.
//!
//! Which classes and policies match a client is WP8.4's compiled matcher; the route asks a
//! [`PolicyMatcher`], and until WP8.4 the matcher is [`NoMatcher`], under which no policy
//! matches.

use tenko_core::{
    InterfaceId, PrefixId,
    dhcp::{ClassId, OptionOwner, OptionValue, PolicyId, write_identity},
};
use tenko_store::ReadView;

use super::{ConfigResult, ConfigService, image::build, load::scope_data, scopes::scope_not_found};
use crate::image::ConfigImage;

/// What a request tells about the client, as far as the effective view asks for it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientFacts {
    /// The hardware address.
    pub mac: Option<[u8; 6]>,
    /// The client identifier (option 61).
    pub client_id: Option<Vec<u8>>,
    /// The vendor class (option 60).
    pub vendor_class: Option<String>,
    /// The user class (option 77).
    pub user_class: Option<String>,
}

impl ClientFacts {
    /// The client identities to look a reservation up by: the client identifier's, then the
    /// hardware address's.
    pub fn identities(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut buffer = [0u8; tenko_core::dhcp::lease::MAX_IDENTITY];
        if let Some(client_id) = &self.client_id {
            let len = write_identity(1, &[], Some(client_id), &mut buffer);
            out.push(buffer[..len].to_vec());
        }
        if let Some(mac) = &self.mac {
            let len = write_identity(1, mac, None, &mut buffer);
            out.push(buffer[..len].to_vec());
        }
        out
    }
}

/// The classes a client is in and the policies that match it, in order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Matched {
    /// The classes.
    pub classes: Vec<ClassId>,
    /// The matching enabled policies of the scope, then of the server, each in order.
    pub policies: Vec<PolicyId>,
}

/// Matches a client against the classes and policies of an image (the hook of WP8.4).
pub trait PolicyMatcher: Send + Sync {
    /// The classes and policies that match `client` in `scope`.
    fn matches(&self, image: &ConfigImage, scope: PrefixId, client: &ClientFacts) -> Matched;
}

/// The matcher until WP8.4: no class and no policy matches.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoMatcher;

impl PolicyMatcher for NoMatcher {
    fn matches(&self, _image: &ConfigImage, _scope: PrefixId, _client: &ClientFacts) -> Matched {
        Matched::default()
    }
}

/// One option of the effective set with the owner of the set it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveEntry {
    /// The value.
    pub value: OptionValue,
    /// The owner of the set that set it.
    pub owner: OptionOwner,
}

/// The effective options of a client in a scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    /// The scope.
    pub prefix: PrefixId,
    /// The interface of the client's reservation, if it has one.
    pub reservation: Option<InterfaceId>,
    /// The classes the client is in.
    pub classes: Vec<ClassId>,
    /// The policies that matched, in order.
    pub policies: Vec<PolicyId>,
    /// The options, in reply order.
    pub options: Vec<EffectiveEntry>,
}

/// Merges the levels with their owners, as [`tenko_core::dhcp::merge`] merges the values.
pub fn merge_levels<'a>(
    levels: impl IntoIterator<Item = (OptionOwner, &'a [OptionValue])>,
) -> Vec<EffectiveEntry> {
    let mut merged: Vec<EffectiveEntry> = Vec::new();
    for (owner, values) in levels {
        for value in values {
            match merged
                .iter_mut()
                .find(|held| held.value.space == value.space && held.value.code == value.code)
            {
                Some(held) => {
                    held.value.clone_from(value);
                    held.owner = owner;
                }
                None => merged.push(EffectiveEntry {
                    value: value.clone(),
                    owner,
                }),
            }
        }
    }
    merged
}

impl ConfigService {
    /// The effective options of `client` in the scope of `prefix` (built as if the scope
    /// were enabled).
    ///
    /// # Errors
    ///
    /// `dhcp.scope.not_found`, or the store's error.
    pub fn effective_options(
        view: &dyn ReadView,
        prefix: PrefixId,
        client: &ClientFacts,
        matcher: &dyn PolicyMatcher,
    ) -> ConfigResult<Effective> {
        let mut data = scope_data(view, prefix)?;
        let Some(scope) = data.scopes.get_mut(&prefix) else {
            return Err(scope_not_found(prefix));
        };
        scope.enabled = true;
        let shared_network = scope.shared_network;
        let built = build(&data);
        let reservation = client
            .identities()
            .iter()
            .find_map(|identity| built.image.reservation(prefix, identity))
            .map(|reservation| reservation.interface);
        let found = matcher.matches(&built.image, prefix, client);
        let set = |owner: OptionOwner| {
            data.option_sets
                .get(&owner)
                .map_or(&[][..], |set| set.values.as_slice())
        };
        let mut levels: Vec<(OptionOwner, &[OptionValue])> =
            vec![(OptionOwner::Server, set(OptionOwner::Server))];
        if let Some(network) = shared_network {
            let owner = OptionOwner::SharedNetwork(network);
            levels.push((owner, set(owner)));
        }
        levels.push((OptionOwner::Scope(prefix), set(OptionOwner::Scope(prefix))));
        // The first matching policy wins per code: merge them last to first.
        for policy in found.policies.iter().rev() {
            let owner = OptionOwner::Policy(*policy);
            levels.push((owner, set(owner)));
        }
        if let Some(interface) = reservation {
            let owner = OptionOwner::Host(interface);
            levels.push((owner, set(owner)));
        }
        Ok(Effective {
            prefix,
            reservation,
            classes: found.classes,
            policies: found.policies,
            options: merge_levels(levels),
        })
    }
}
