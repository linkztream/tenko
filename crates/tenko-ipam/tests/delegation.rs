//! DHCPv6 delegation pools (WP9.2): ranges of role `dhcp_pd_pool` with a delegated length.
//! The rules: the network is IPv6, the length lies between the network's and 64, the range
//! starts and ends on a block of that length, only delegation pools have a length, and the
//! overlap rules of ranges apply.

mod common;

use common::*;
use tenko_core::{
    PrefixId, RangeId,
    ipam::{Range, RangeRole},
};
use tenko_ipam::{
    IpamCommand, IpamError, IpamService, codes,
    command::{RangeInput, RangePatch, UpdateRange},
};

/// The last address of the /56 block that ends most ranges of these tests.
const BLOCK_END: &str = "2001:db8:1:1ff:ffff:ffff:ffff:ffff";

/// A delegation pool command with the length `delegated_len`.
fn delegation_range(
    prefix: PrefixId,
    first: &str,
    last: &str,
    delegated_len: Option<u8>,
) -> RangeInput {
    RangeInput {
        delegated_len,
        ..range(prefix, first, last, RangeRole::DhcpPdPool)
    }
}

fn update_range(id: RangeId, patch: RangePatch) -> IpamCommand {
    IpamCommand::UpdateRange(UpdateRange {
        id,
        expected: None,
        patch,
    })
}

/// Whether the error names `field` among its field errors.
fn names_field(error: &IpamError, field: &str) -> bool {
    error.coded().errors.iter().any(|item| item.field == field)
}

/// A service with the IPv6 network `2001:db8:1::/48` and its identifier.
async fn service_with_v6_network() -> (std::sync::Arc<IpamService>, PrefixId) {
    let (service, _) = service();
    let network = prefix(None, "2001:db8:1::/48");
    let network_id = network.id.expect("id");
    run(&service, vec![IpamCommand::CreatePrefix(network)]).await;
    (service, network_id)
}

#[tokio::test]
async fn a_delegation_pool_is_created_on_an_ipv6_network() {
    let (service, network) = service_with_v6_network().await;
    // A /56 pool, one /49 block and one /64 block: the shortest and the longest legal lengths.
    let applied = run(
        &service,
        vec![
            IpamCommand::CreateRange(delegation_range(
                network,
                "2001:db8:1:100::",
                BLOCK_END,
                Some(56),
            )),
            IpamCommand::CreateRange(delegation_range(
                network,
                "2001:db8:1:8000::",
                "2001:db8:1:ffff:ffff:ffff:ffff:ffff",
                Some(49),
            )),
            IpamCommand::CreateRange(delegation_range(
                network,
                "2001:db8:1:4000::",
                "2001:db8:1:4000:ffff:ffff:ffff:ffff",
                Some(64),
            )),
            // Several blocks in one range.
            IpamCommand::CreateRange(delegation_range(
                network,
                "2001:db8:1:200::",
                "2001:db8:1:5ff:ffff:ffff:ffff:ffff",
                Some(56),
            )),
        ],
    )
    .await;
    let pool: Range = fetch(&service, id_of::<RangeId>(applied.results[0])).await;
    assert_eq!(pool.role, RangeRole::DhcpPdPool);
    assert_eq!(pool.delegated_len, Some(56));
    assert_eq!(pool.lease_secs, None);
    assert_eq!(pool.first, ip("2001:db8:1:100::"));
    assert_eq!(pool.last, ip(BLOCK_END));
    let wide: Range = fetch(&service, id_of::<RangeId>(applied.results[1])).await;
    assert_eq!(wide.delegated_len, Some(49));
    let narrow: Range = fetch(&service, id_of::<RangeId>(applied.results[2])).await;
    assert_eq!(narrow.delegated_len, Some(64));
    assert_eq!(all_of::<Range>(&service).await.len(), 4);
}

#[tokio::test]
async fn a_delegation_pool_takes_a_lease_time() {
    let (service, network) = service_with_v6_network().await;
    let applied = run(
        &service,
        vec![IpamCommand::CreateRange(RangeInput {
            lease_secs: Some(3_600),
            ..delegation_range(network, "2001:db8:1:100::", BLOCK_END, Some(56))
        })],
    )
    .await;
    let pool: Range = fetch(&service, id_of::<RangeId>(applied.results[0])).await;
    assert_eq!(pool.lease_secs, Some(3_600));
    // The bounds of a lease time apply as for a DHCP pool.
    let error = run_err(
        &service,
        vec![IpamCommand::CreateRange(RangeInput {
            lease_secs: Some(10),
            ..delegation_range(
                network,
                "2001:db8:1:200::",
                "2001:db8:1:2ff:ffff:ffff:ffff:ffff",
                Some(56),
            )
        })],
        codes::VALIDATION,
    )
    .await;
    assert!(names_field(&error, "lease_secs"), "{error:?}");
    // A lease time stays refused on a reserved range.
    let error = run_err(
        &service,
        vec![IpamCommand::CreateRange(RangeInput {
            lease_secs: Some(3_600),
            ..range(
                network,
                "2001:db8:1::10",
                "2001:db8:1::20",
                RangeRole::Reserved,
            )
        })],
        codes::VALIDATION,
    )
    .await;
    assert!(names_field(&error, "lease_secs"), "{error:?}");
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One table of refusals.
async fn a_delegation_pool_is_refused_when_it_is_not_valid() {
    let (service, network) = service_with_v6_network().await;
    let whole = "2001:db8:1:ffff:ffff:ffff:ffff:ffff";
    let refused = [
        (
            "without a length",
            delegation_range(network, "2001:db8:1:100::", BLOCK_END, None),
        ),
        (
            "as long as the network",
            delegation_range(network, "2001:db8:1::", whole, Some(48)),
        ),
        (
            "shorter than the network",
            delegation_range(network, "2001:db8:1::", whole, Some(40)),
        ),
        (
            "longer than 64",
            delegation_range(
                network,
                "2001:db8:1:100::",
                "2001:db8:1:100::ffff:ffff:ffff",
                Some(65),
            ),
        ),
        (
            "zero",
            delegation_range(network, "2001:db8:1:100::", BLOCK_END, Some(0)),
        ),
        (
            "an unaligned first address",
            delegation_range(network, "2001:db8:1:100::1", BLOCK_END, Some(56)),
        ),
        (
            "a first address off the /56 boundary",
            delegation_range(network, "2001:db8:1:80::", BLOCK_END, Some(56)),
        ),
        (
            "a last address inside a block",
            delegation_range(
                network,
                "2001:db8:1:100::",
                "2001:db8:1:1fe:ffff:ffff:ffff:ffff",
                Some(56),
            ),
        ),
        (
            "a last address at the start of a block",
            delegation_range(network, "2001:db8:1:100::", "2001:db8:1:1ff::", Some(56)),
        ),
        (
            "a delegated length on a DHCP pool",
            RangeInput {
                delegated_len: Some(56),
                ..range(
                    network,
                    "2001:db8:1::100",
                    "2001:db8:1::1ff",
                    RangeRole::DhcpPool,
                )
            },
        ),
        (
            "a delegated length on a reserved range",
            RangeInput {
                delegated_len: Some(56),
                ..range(
                    network,
                    "2001:db8:1::100",
                    "2001:db8:1::1ff",
                    RangeRole::Reserved,
                )
            },
        ),
        (
            "a delegated length on an infrastructure range",
            RangeInput {
                delegated_len: Some(56),
                ..range(
                    network,
                    "2001:db8:1::100",
                    "2001:db8:1::1ff",
                    RangeRole::Infrastructure,
                )
            },
        ),
    ];
    for (what, input) in refused {
        let error = run_err(
            &service,
            vec![IpamCommand::CreateRange(input)],
            codes::VALIDATION,
        )
        .await;
        assert_eq!(status_of(&error), 400, "{what}");
        assert!(names_field(&error, "delegated_len"), "{what}: {error:?}");
    }
    // None of them was stored.
    assert_eq!(all_of::<Range>(&service).await.len(), 0);
}

#[tokio::test]
async fn a_delegation_pool_is_refused_on_an_ipv4_network() {
    let (service, _) = service();
    let network = prefix(None, "192.0.2.0/24");
    let network_id = network.id.expect("id");
    run(&service, vec![IpamCommand::CreatePrefix(network)]).await;
    for len in [Some(26), Some(56), None] {
        let error = run_err(
            &service,
            vec![IpamCommand::CreateRange(delegation_range(
                network_id,
                "192.0.2.64",
                "192.0.2.127",
                len,
            ))],
            codes::VALIDATION,
        )
        .await;
        assert_eq!(status_of(&error), 400);
        assert!(names_field(&error, "role"), "{error:?}");
    }
    assert_eq!(all_of::<Range>(&service).await.len(), 0);
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One scenario from creation to the last patch.
async fn patching_a_delegation_pool_validates_it_again() {
    let (service, network) = service_with_v6_network().await;
    let applied = run(
        &service,
        vec![IpamCommand::CreateRange(delegation_range(
            network,
            "2001:db8:1:100::",
            BLOCK_END,
            Some(56),
        ))],
    )
    .await;
    let pool_id: RangeId = id_of(applied.results[0]);
    let patch_len = |len: Option<Option<u8>>| {
        update_range(
            pool_id,
            RangePatch {
                delegated_len: len,
                ..RangePatch::default()
            },
        )
    };
    // Refused: as long as the network, above 64, cleared, a length whose boundary the range
    // does not sit on (a /52 block is 2^76 addresses and the range starts at 2^72), a last
    // address inside a block, and a role that has no delegated length.
    for (what, patch) in [
        ("as long as the network", patch_len(Some(Some(48)))),
        ("above 64", patch_len(Some(Some(65)))),
        ("cleared", patch_len(Some(None))),
        ("an unaligned length", patch_len(Some(Some(52)))),
        (
            "a last address inside a block",
            update_range(
                pool_id,
                RangePatch {
                    last: Some(ip("2001:db8:1:1fe:ffff:ffff:ffff:ffff")),
                    ..RangePatch::default()
                },
            ),
        ),
        (
            "a role that has no delegated length",
            update_range(
                pool_id,
                RangePatch {
                    role: Some(RangeRole::DhcpPool),
                    ..RangePatch::default()
                },
            ),
        ),
    ] {
        let error = run_err(&service, vec![patch], codes::VALIDATION).await;
        assert!(names_field(&error, "delegated_len"), "{what}: {error:?}");
    }
    let unchanged: Range = fetch(&service, pool_id).await;
    assert_eq!(unchanged.delegated_len, Some(56));
    assert_eq!(unchanged.role, RangeRole::DhcpPdPool);
    // A longer length of which the range is still a whole number of blocks.
    run(&service, vec![patch_len(Some(Some(60)))]).await;
    assert_eq!(
        fetch::<Range>(&service, pool_id).await.delegated_len,
        Some(60)
    );
    // A last address at the end of a /60 block is accepted now.
    run(
        &service,
        vec![update_range(
            pool_id,
            RangePatch {
                last: Some(ip("2001:db8:1:1ef:ffff:ffff:ffff:ffff")),
                ..RangePatch::default()
            },
        )],
    )
    .await;
    // Another role together with clearing the length is accepted.
    run(
        &service,
        vec![update_range(
            pool_id,
            RangePatch {
                role: Some(RangeRole::Reserved),
                delegated_len: Some(None),
                ..RangePatch::default()
            },
        )],
    )
    .await;
    let reserved: Range = fetch(&service, pool_id).await;
    assert_eq!(reserved.role, RangeRole::Reserved);
    assert_eq!(reserved.delegated_len, None);
    // A role change to a delegation pool needs a length at once.
    let error = run_err(
        &service,
        vec![update_range(
            pool_id,
            RangePatch {
                role: Some(RangeRole::DhcpPdPool),
                ..RangePatch::default()
            },
        )],
        codes::VALIDATION,
    )
    .await;
    assert!(names_field(&error, "delegated_len"), "{error:?}");
    run(
        &service,
        vec![update_range(
            pool_id,
            RangePatch {
                role: Some(RangeRole::DhcpPdPool),
                delegated_len: Some(Some(60)),
                ..RangePatch::default()
            },
        )],
    )
    .await;
    assert_eq!(
        fetch::<Range>(&service, pool_id).await.role,
        RangeRole::DhcpPdPool
    );
}

#[tokio::test]
async fn a_delegation_pool_overlaps_like_any_other_range() {
    let (service, network) = service_with_v6_network().await;
    let applied = run(
        &service,
        vec![
            IpamCommand::CreateRange(range(
                network,
                "2001:db8:1:100::10",
                "2001:db8:1:100::20",
                RangeRole::DhcpPool,
            )),
            IpamCommand::CreateRange(delegation_range(
                network,
                "2001:db8:1:400::",
                "2001:db8:1:4ff:ffff:ffff:ffff:ffff",
                Some(56),
            )),
            IpamCommand::CreateRange(delegation_range(
                network,
                "2001:db8:1:200::",
                "2001:db8:1:2ff:ffff:ffff:ffff:ffff",
                Some(56),
            )),
        ],
    )
    .await;
    let dhcp_pool: RangeId = id_of(applied.results[0]);
    let movable: RangeId = id_of(applied.results[2]);
    // A delegation pool over an address pool, an address pool inside a delegation pool,
    // a second delegation pool over the first, and a reserved range over it.
    for (what, input) in [
        (
            "a delegation pool over a DHCP pool",
            delegation_range(network, "2001:db8:1:100::", BLOCK_END, Some(56)),
        ),
        (
            "a DHCP pool inside a delegation pool",
            range(
                network,
                "2001:db8:1:400::10",
                "2001:db8:1:400::20",
                RangeRole::DhcpPool,
            ),
        ),
        (
            "a delegation pool over a delegation pool",
            delegation_range(
                network,
                "2001:db8:1:400::",
                "2001:db8:1:5ff:ffff:ffff:ffff:ffff",
                Some(56),
            ),
        ),
        (
            "a reserved range over a delegation pool",
            range(
                network,
                "2001:db8:1:4f0::",
                "2001:db8:1:500::",
                RangeRole::Reserved,
            ),
        ),
    ] {
        let error = run_err(
            &service,
            vec![IpamCommand::CreateRange(input)],
            codes::RANGE_OVERLAP,
        )
        .await;
        assert_eq!(status_of(&error), 409, "{what}");
    }
    // Moving a delegation pool onto the DHCP pool's space is refused as well.
    run_err(
        &service,
        vec![update_range(
            movable,
            RangePatch {
                first: Some(ip("2001:db8:1:100::")),
                ..RangePatch::default()
            },
        )],
        codes::RANGE_OVERLAP,
    )
    .await;
    assert_eq!(
        fetch::<Range>(&service, dhcp_pool).await.role,
        RangeRole::DhcpPool
    );
    assert_eq!(all_of::<Range>(&service).await.len(), 3);
}
