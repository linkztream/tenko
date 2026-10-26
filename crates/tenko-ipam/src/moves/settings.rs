//! The settings of a move's DHCP timing (`[dhcp.moves]` of `tenko.toml`, `docs/moves.md`
//! section 5): the short lease before the network change, how long the job waits for it,
//! the migration deadline's margin and limit, the extension near the deadline and the
//! verification window after the client reconnects. Nothing of this is a constant of the
//! job.

use serde::{Deserialize, Serialize};

/// `[dhcp.moves]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MoveSettings {
    /// The lease a client a move job moves gets at its next renewal before the network
    /// change, in seconds (default 120, 30 to 3,600).
    pub short_lease_secs: u32,
    /// The longest wait for that renewal: a client whose next DHCP message is expected
    /// later moves without it (default 3,600, 0 to 86,400; 0 never waits).
    pub prepare_limit_secs: u32,
    /// After the client's DHCP exchange on the target network is seen, the window in which
    /// the job verifies its new lease (default 90, 10 to 3,600).
    pub verify_secs: u32,
    /// What the migration deadline adds to the end of the client's lease (default 60, 0 to
    /// 3,600).
    pub margin_secs: u32,
    /// The longest migration deadline computed from a lease, in seconds from the start of
    /// the observation (default 172,800, 300 to 604,800); a request's own timeout is not
    /// bounded by it.
    pub deadline_limit_secs: u32,
    /// The last seconds before the deadline in which a DHCP message of the client extends
    /// it (default 15, 1 to 300).
    pub extend_window_secs: u32,
    /// How far the deadline moves then, once per job (default 60, 1 to 3,600).
    pub extend_secs: u32,
}

impl Default for MoveSettings {
    fn default() -> Self {
        Self {
            short_lease_secs: 120,
            prepare_limit_secs: 3_600,
            verify_secs: 90,
            margin_secs: 60,
            deadline_limit_secs: 172_800,
            extend_window_secs: 15,
            extend_secs: 60,
        }
    }
}

impl MoveSettings {
    /// Checks every value against its bounds.
    ///
    /// # Errors
    ///
    /// The first value out of bounds, as `dhcp.moves.<key> must be between <low> and
    /// <high>`.
    pub fn validate(&self) -> Result<(), String> {
        let check = |value: u32, low: u32, high: u32, key: &str| {
            if (low..=high).contains(&value) {
                Ok(())
            } else {
                Err(format!("dhcp.moves.{key} must be between {low} and {high}"))
            }
        };
        check(self.short_lease_secs, 30, 3_600, "short_lease_secs")?;
        check(self.prepare_limit_secs, 0, 86_400, "prepare_limit_secs")?;
        check(self.verify_secs, 10, 3_600, "verify_secs")?;
        check(self.margin_secs, 0, 3_600, "margin_secs")?;
        check(
            self.deadline_limit_secs,
            300,
            604_800,
            "deadline_limit_secs",
        )?;
        check(self.extend_window_secs, 1, 300, "extend_window_secs")?;
        check(self.extend_secs, 1, 3_600, "extend_secs")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_valid_and_the_bounds_hold() {
        assert_eq!(MoveSettings::default().validate(), Ok(()));
        let short = MoveSettings {
            short_lease_secs: 10,
            ..MoveSettings::default()
        };
        assert_eq!(
            short.validate(),
            Err("dhcp.moves.short_lease_secs must be between 30 and 3600".to_owned())
        );
        let limit = MoveSettings {
            deadline_limit_secs: 604_801,
            ..MoveSettings::default()
        };
        assert!(limit.validate().is_err());
        let never = MoveSettings {
            prepare_limit_secs: 0,
            ..MoveSettings::default()
        };
        assert_eq!(never.validate(), Ok(()));
    }
}
