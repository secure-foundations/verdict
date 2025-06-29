#![forbid(unsafe_code)]

mod cmd;
mod ct_logs;
mod error;
mod harness;
mod utils;

use clap::{command, Parser, Subcommand};
use cmd::*;
use error::*;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(long_about = None)]
struct Args {
    #[clap(subcommand)]
    action: Action,
}

#[derive(Debug, Subcommand)]
enum Action {
    /// Parse PEM format X.509 certificates from stdin
    ParseCert(parse_cert::Args),

    /// Validate a single certificate chain in PEM format
    Validate(validate::Args),

    /// Parse a specific format of certificates stored in CSVs
    ParseCTLogs(parse_ct_logs::Args),

    /// Compare the results of two CT logs
    DiffResults(diff_results::Args),

    /// Benchmark CT logs on multiple clients
    BenchCTLogs(bench_ct_logs::Args),

    /// Run differential tests on x509-limbo
    Limbo(limbo::Args),
}

fn main_args(args: Args) -> Result<(), Error> {
    match args.action {
        Action::ParseCert(args) => parse_cert::main(args),
        Action::Validate(args) => validate::main(args),
        Action::ParseCTLogs(args) => parse_ct_logs::main(args),
        Action::DiffResults(args) => diff_results::main(args),
        Action::BenchCTLogs(args) => bench_ct_logs::main(args),
        Action::Limbo(args) => limbo::main(args),
    }
}

fn main() -> ExitCode {
    match main_args(Args::parse()) {
        Ok(..) => ExitCode::from(0),
        Err(err) => {
            eprintln!("{}", err);
            ExitCode::from(1)
        }
    }
}
