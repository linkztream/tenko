//! Entry point of the `ddi` command-line client.

use clap::Parser;

fn main() {
    let cli = ddi_cli::Cli::parse();
    print!("{}", ddi_cli::execute(&cli));
}
