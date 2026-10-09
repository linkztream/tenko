//! The index of steps waiting for an observation, so that
//! [`JobEngine::on_observation`](crate::JobEngine::on_observation) finds the jobs an
//! observation may wake without scanning every waiting job.
//!
//! Waiters are keyed by the address and the MAC address their predicates name. The index
//! only narrows the candidates: every candidate is checked with
//! [`ObservationCondition::matches`] and then against the stored job before it resumes,
//! so a stale entry costs a lookup and nothing else.

use std::{
    collections::{BTreeSet, HashMap},
    net::IpAddr,
};

use ipnet::IpNet;
use tenko_core::{
    JobId, MacAddr, PrefixId, Timestamp,
    observe::{Observation, Observed},
};

use crate::model::{ObservationCondition, ObservedPredicate};

/// Resolves a prefix to its network, for [`ObservedPredicate::LeaseInPrefix`]. The IPAM
/// domain provides it from its prefix tree; without one, lease predicates never match.
pub trait PrefixResolver: Send + Sync + 'static {
    /// The network of the prefix, if it exists.
    fn cidr(&self, prefix: PrefixId) -> Option<IpNet>;
}

impl<F> PrefixResolver for F
where
    F: Fn(PrefixId) -> Option<IpNet> + Send + Sync + 'static,
{
    fn cidr(&self, prefix: PrefixId) -> Option<IpNet> {
        self(prefix)
    }
}

/// One waiting step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Waiter {
    /// The step.
    pub step: u16,
    /// What it waits for.
    pub condition: ObservationCondition,
    /// When the step started; older observations do not count.
    pub since: Timestamp,
}

/// Waiting steps by the keys their predicates name.
#[derive(Debug, Default)]
pub(crate) struct WaiterIndex {
    waiters: HashMap<JobId, Waiter>,
    by_ip: HashMap<IpAddr, BTreeSet<JobId>>,
    by_mac: HashMap<MacAddr, BTreeSet<JobId>>,
}

impl WaiterIndex {
    /// Adds or replaces the waiter of a job.
    pub fn insert(&mut self, job: JobId, waiter: Waiter) {
        self.remove(job);
        for predicate in &waiter.condition.any_of {
            match predicate {
                ObservedPredicate::AddressSeen { ip, .. } => {
                    self.by_ip.entry(*ip).or_default().insert(job);
                }
                ObservedPredicate::LeaseInPrefix { mac, .. } => {
                    self.by_mac.entry(*mac).or_default().insert(job);
                }
            }
        }
        self.waiters.insert(job, waiter);
    }

    /// Removes the waiter of a job.
    pub fn remove(&mut self, job: JobId) {
        let Some(waiter) = self.waiters.remove(&job) else {
            return;
        };
        for predicate in &waiter.condition.any_of {
            match predicate {
                ObservedPredicate::AddressSeen { ip, .. } => remove_from(&mut self.by_ip, ip, job),
                ObservedPredicate::LeaseInPrefix { mac, .. } => {
                    remove_from(&mut self.by_mac, mac, job);
                }
            }
        }
    }

    /// Number of waiting steps.
    pub fn len(&self) -> usize {
        self.waiters.len()
    }

    /// Jobs whose predicates name the observation's address or MAC address, in id order.
    pub fn candidates(&self, observation: &Observation) -> Vec<(JobId, Waiter)> {
        let Observed::Address { ip, mac, .. } = &observation.subject else {
            return Vec::new();
        };
        let mut jobs: BTreeSet<JobId> = self.by_ip.get(ip).cloned().unwrap_or_default();
        if let Some(mac) = mac
            && let Some(more) = self.by_mac.get(mac)
        {
            jobs.extend(more);
        }
        jobs.into_iter()
            .filter_map(|job| self.waiters.get(&job).map(|waiter| (job, waiter.clone())))
            .collect()
    }
}

fn remove_from<K: std::hash::Hash + Eq>(
    map: &mut HashMap<K, BTreeSet<JobId>>,
    key: &K,
    job: JobId,
) {
    if let Some(jobs) = map.get_mut(key) {
        jobs.remove(&job);
        if jobs.is_empty() {
            map.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use tenko_core::{
        HostId, NodeId, ObservationId, VrfId,
        observe::{ObservationSource, ProbeMethod},
    };

    use super::*;

    fn observation(ip: &str, mac: Option<&str>) -> Observation {
        Observation {
            id: ObservationId::generate(),
            source: ObservationSource::Probe {
                node: NodeId(1),
                method: ProbeMethod::Arp,
            },
            subject: Observed::Address {
                vrf: VrfId::generate(),
                ip: ip.parse().expect("ip"),
                mac: mac.map(|mac| mac.parse().expect("mac")),
            },
            observed_at: Timestamp::UNIX_EPOCH,
            received_at: Timestamp::UNIX_EPOCH,
            expires_at: None,
        }
    }

    fn waiter(predicates: Vec<ObservedPredicate>) -> Waiter {
        Waiter {
            step: 4,
            condition: ObservationCondition {
                subject: HostId::generate().into(),
                any_of: predicates,
            },
            since: Timestamp::UNIX_EPOCH,
        }
    }

    #[test]
    fn candidates_come_from_addresses_and_macs() {
        let mut index = WaiterIndex::default();
        let by_ip = JobId::generate();
        let by_mac = JobId::generate();
        index.insert(
            by_ip,
            waiter(vec![ObservedPredicate::AddressSeen {
                vrf: VrfId::generate(),
                ip: "192.0.2.20".parse().expect("ip"),
                mac: None,
            }]),
        );
        index.insert(
            by_mac,
            waiter(vec![ObservedPredicate::LeaseInPrefix {
                prefix: PrefixId::generate(),
                mac: "00:00:5e:00:53:21".parse().expect("mac"),
            }]),
        );
        assert_eq!(index.len(), 2);
        let found: Vec<_> = index
            .candidates(&observation("192.0.2.20", Some("00:00:5e:00:53:21")))
            .into_iter()
            .map(|(job, _)| job)
            .collect();
        assert_eq!(found, vec![by_ip, by_mac]);
        assert_eq!(index.candidates(&observation("198.51.100.1", None)), vec![]);
        index.remove(by_ip);
        assert_eq!(index.candidates(&observation("192.0.2.20", None)), vec![]);
        assert_eq!(index.len(), 1);
        index.remove(by_mac);
        assert_eq!(index.len(), 0);
        assert!(index.by_ip.is_empty() && index.by_mac.is_empty());
    }
}
