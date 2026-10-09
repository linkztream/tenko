//! Entry point of the `tenko` command-line client.

use clap::Parser;

fn main() {
    let cli = tenko_cli::Cli::parse();
    print!("{}", tenko_cli::execute(&cli));
}
