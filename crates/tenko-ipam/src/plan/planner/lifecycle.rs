//! The lifecycle of a host: decommission and reinstate.
//!
//! A decommissioned host keeps its interfaces, so the reconciler still knows its MAC
//! addresses and proposes no new host for them, but it releases its addresses: every live
//! address on its interfaces is unassigned, which ends the DHCP reservation it made, and its
//! DNS name is removed unless the caller keeps it, so the DNS actuator removes the records.
//! The host records what it released ([`Decommission::released`]). While it is
//! decommissioned no address can be assigned to its interfaces (`ipam.host.decommissioned`).
//!
//! A reinstatement clears the state and binds back every released address that is still
//! live and unassigned, on an interface of the host that is still live, with the DNS name
//! it lost (when it has none now). An address that cannot come back is a warning
//! (`ipam.host.reinstate_skipped`), not an error: the host is reinstated either way.
//!
//! The host's change is audited as `ipam.host.decommission` or `ipam.host.reinstate`; the
//! address changes are audited as the address updates they are.

use tenko_core::{
    HostId, ObjectRef, Revision,
    audit::AuditAction,
    ipam::{Address, Decommission, Host, Interface, ReleasedAddress},
};

use super::Planner;
use crate::{
    command::{AddressPatch, DecommissionHost, UpdateAddress},
    error::{IpamError, IpamResult, codes},
    proposals::decide::clean_reason,
};

/// The audit action of a decommission.
pub const DECOMMISSION_ACTION: &str = "ipam.host.decommission";
/// The audit action of a reinstatement.
pub const REINSTATE_ACTION: &str = "ipam.host.reinstate";

impl Planner<'_> {
    pub(super) fn decommission_host(&mut self, input: &DecommissionHost) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Host>(input.host, input.expected, false)?;
        self.check_unlocked(&before)?;
        if before.is_decommissioned() {
            return Err(decommissioned(&before));
        }
        let reason = clean_reason(input.reason.clone())?;
        let mut released = Vec::new();
        for interface in self.interfaces_of(before.id, false)? {
            for address in self.addresses_of(interface.id, false)? {
                let drop_name = !input.keep_dns && address.dns_name.is_some();
                released.push(ReleasedAddress {
                    address: address.id,
                    interface: interface.id,
                    dns_name: if drop_name {
                        address.dns_name.clone()
                    } else {
                        None
                    },
                });
                self.update_address(&UpdateAddress {
                    id: address.id,
                    expected: None,
                    patch: AddressPatch {
                        interface: Some(None),
                        dns_name: drop_name.then_some(None),
                        ..AddressPatch::default()
                    },
                })?;
            }
        }
        let mut after = before.clone();
        after.decommissioned = Some(Decommission {
            at: self.cx.now,
            by: self.cx.principal.clone(),
            reason,
            kept_dns: input.keep_dns,
            released,
        });
        after.meta.updated = self.stamp();
        self.reservation_checks.remove(&before.id);
        let reference = self.finish_update(&before, &after, |_, _| Ok(()))?;
        self.rename_last_audit(DECOMMISSION_ACTION);
        Ok(reference)
    }

    pub(super) fn reinstate_host(
        &mut self,
        id: HostId,
        expected: Option<Revision>,
    ) -> IpamResult<ObjectRef> {
        let before = self.load_for_change::<Host>(id, expected, false)?;
        self.check_unlocked(&before)?;
        let Some(record) = before.decommissioned.clone() else {
            return Err(IpamError::new(
                codes::HOST_NOT_DECOMMISSIONED,
                409,
                format!("host {} is not decommissioned", before.name),
            )
            .titled("The host is not decommissioned")
            .param("host", &before.name));
        };
        let mut after = before.clone();
        after.decommissioned = None;
        after.meta.updated = self.stamp();
        // The host is active again first, so that its interfaces take addresses.
        let reference = self.finish_update(&before, &after, |_, _| Ok(()))?;
        self.rename_last_audit(REINSTATE_ACTION);
        for released in &record.released {
            let Some((address, _)) = self.try_load::<Address>(released.address)? else {
                self.skipped(released, None, "deleted");
                continue;
            };
            if address.meta.is_deleted() {
                self.skipped(released, Some(&address), "deleted");
                continue;
            }
            if address.interface.is_some() {
                self.skipped(released, Some(&address), "assigned");
                continue;
            }
            let interface_live = self
                .try_load::<Interface>(released.interface)?
                .is_some_and(|(interface, _)| !interface.meta.is_deleted() && interface.host == id);
            if !interface_live {
                self.skipped(released, Some(&address), "interface_gone");
                continue;
            }
            let dns_name = released
                .dns_name
                .clone()
                .filter(|_| address.dns_name.is_none());
            self.update_address(&UpdateAddress {
                id: address.id,
                expected: None,
                patch: AddressPatch {
                    interface: Some(Some(released.interface)),
                    dns_name: dns_name.map(Some),
                    ..AddressPatch::default()
                },
            })?;
        }
        self.reservation_checks.insert(id);
        Ok(reference)
    }

    /// Fails with `ipam.host.decommissioned` when the host of an interface that is to take
    /// an address is decommissioned.
    pub(super) fn check_not_decommissioned(host: &Host) -> IpamResult<()> {
        if host.is_decommissioned() {
            return Err(decommissioned(host));
        }
        Ok(())
    }

    /// Gives the audit draft of the change just recorded the lifecycle action.
    fn rename_last_audit(&mut self, action: &'static str) {
        if let Some(draft) = self.audit.last_mut() {
            draft.action = AuditAction::from_static(action);
        }
    }

    fn skipped(&mut self, released: &ReleasedAddress, address: Option<&Address>, cause: &str) {
        let object: ObjectRef = released.address.into();
        let ip = address
            .map(|address| address.ip.to_string())
            .unwrap_or_default();
        self.warn(
            codes::WARN_REINSTATE_SKIPPED,
            format!("{object} {ip} was not bound again: {cause}"),
            Some(object),
            &[
                ("address", released.address.to_string()),
                ("ip", ip.clone()),
                ("cause", cause.to_owned()),
            ],
            false,
        );
    }
}

fn decommissioned(host: &Host) -> IpamError {
    IpamError::new(
        codes::HOST_DECOMMISSIONED,
        409,
        format!("host {} is decommissioned", host.name),
    )
    .titled("The host is decommissioned")
    .param("host", &host.name)
}
