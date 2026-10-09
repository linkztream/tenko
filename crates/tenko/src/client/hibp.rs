//! `tenko hibp build`: builds the offline breached-password filter (IAM-04, TGL-06) from
//! the downloaded Pwned Passwords corpus (`SHA1:COUNT` lines), without any network access.

use std::{
    fs::File,
    io::{BufReader, BufWriter, Write as _},
    path::PathBuf,
};

use clap::{Args, Subcommand};
use tenko_auth::hibp::{BuildOptions, build_filter};

use super::{Failure, Output};

/// Subcommands of `tenko hibp`.
#[derive(Debug, Clone, Subcommand)]
pub enum HibpCommand {
    /// Build the offline filter that `hibp.offline_filter` of `tenko.toml` names.
    Build(BuildArgs),
}

/// Arguments of `tenko hibp build`.
#[derive(Debug, Clone, Args)]
pub struct BuildArgs {
    /// The corpus: one `SHA1:COUNT` line per password hash (the downloader's output).
    #[arg(value_name = "INPUT")]
    pub input: PathBuf,

    /// The filter file to write.
    #[arg(value_name = "OUTPUT")]
    pub output: PathBuf,

    /// Leave out hashes seen fewer times than this; 1 keeps every line.
    #[arg(long, value_name = "N", default_value_t = 1)]
    pub min_count: u64,
}

/// Runs `tenko hibp build`.
///
/// # Errors
///
/// The input cannot be read, a line is malformed, or the output cannot be written.
pub fn build(args: &BuildArgs) -> Result<Output, Failure> {
    let input = File::open(&args.input).map_err(|error| {
        Failure::other(format!("cannot read {}: {error}", args.input.display()))
    })?;
    let temporary = args.output.with_extension("partial");
    let output = File::create(&temporary).map_err(|error| {
        Failure::other(format!("cannot write {}: {error}", temporary.display()))
    })?;
    let mut writer = BufWriter::new(output);
    let min_count = args.min_count.max(1);
    let result = build_filter(
        BufReader::with_capacity(1 << 20, input),
        &mut writer,
        &BuildOptions { min_count },
    );
    let summary = match result {
        Ok(summary) => summary,
        Err(error) => {
            drop(writer);
            let _ = std::fs::remove_file(&temporary);
            return Err(Failure::other(format!(
                "building the filter from {} failed: {error}",
                args.input.display()
            )));
        }
    };
    writer
        .flush()
        .and_then(|()| writer.get_ref().sync_all())
        .map_err(|error| {
            Failure::other(format!("cannot write {}: {error}", temporary.display()))
        })?;
    drop(writer);
    std::fs::rename(&temporary, &args.output).map_err(|error| {
        Failure::other(format!("cannot write {}: {error}", args.output.display()))
    })?;
    Ok(Output::text(format!(
        "wrote {}: {} hash(es), {} skipped below count {min_count}, {} bytes\n",
        args.output.display(),
        summary.keys,
        summary.skipped,
        summary.bytes
    )))
}
