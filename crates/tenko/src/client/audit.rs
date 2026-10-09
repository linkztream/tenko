//! `tenko audit verify`: asks the controller to check the hash chain of the audit log
//! (IAM-18) and reports the first break.

use clap::{Args, Subcommand};

use super::{ClientOpts, Failure, Output, Target};
use crate::exit;

/// Subcommands of `tenko audit`.
#[derive(Debug, Clone, Subcommand)]
pub enum AuditCommand {
    /// Verify the hash chain of the audit log; exits with status 9 when it is broken.
    Verify(VerifyArgs),
}

/// Arguments of `tenko audit verify`.
#[derive(Debug, Clone, Args)]
pub struct VerifyArgs {
    /// Connection options.
    #[command(flatten)]
    pub client: ClientOpts,
}

/// Runs `tenko audit verify`.
///
/// # Errors
///
/// The [`Failure`] of the request.
pub async fn verify(args: &VerifyArgs) -> Result<Output, Failure> {
    let target = Target::resolve(&args.client, true)?;
    let report = target.client()?.audit_verify().await?;
    let mut output = if target.json {
        Output::json(&report)
    } else if report.intact {
        Output::text(format!(
            "audit chain intact: {} record(s) verified, head {} ({}) at revision {}\n",
            report.checked, report.head.seq, report.head.hash, report.revision
        ))
    } else {
        let text = match &report.first_break {
            Some(broken) => format!(
                "audit chain BROKEN at record {} [{}]: {}; {} record(s) verified before it\n",
                broken.seq, broken.code, broken.detail, report.checked
            ),
            None => format!(
                "audit chain BROKEN: {} record(s) verified, the store reports head {}\n",
                report.checked, report.store_head
            ),
        };
        Output::text(text)
    };
    if !report.intact {
        output.status = exit::INTEGRITY;
    }
    Ok(output)
}
