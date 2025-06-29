use verdict::Task;
use clap::Parser;

use crate::error::*;
use crate::utils::*;
use crate::harness::*;

#[derive(Parser, Debug)]
pub struct Args {
    /// Policy to use
    pub policy: VerdictPolicyName,

    /// Path to the root certificates
    roots: String,

    /// The certificate chain to verify (in PEM format)
    chain: String,

    /// The (optional) target domain to be validated.
    domain: Option<String>,

    /// Repeat the validation for benchmarking purpose
    #[clap(short = 'n', long)]
    repeat: Option<usize>,

    /// Enable debug mode
    #[arg(long, default_value_t = false)]
    debug: bool,

    /// Override the current time with the given timestamp
    #[clap(short = 't', long)]
    override_time: Option<i64>,
}

pub fn main(args: Args) -> Result<(), Error> {
    let timestamp = args.override_time.unwrap_or(chrono::Utc::now().timestamp()) as u64;

    let harness = VerdictHarness { policy: args.policy, debug: args.debug };
    let mut instance = harness.spawn(&args.roots, timestamp)?;

    let task = if let Some(domain) = &args.domain {
        Task::new_server_auth(Some(domain), timestamp)
    } else {
        Task::new_server_auth(None, timestamp)
    };

    let chain = read_pem_file_as_base64(&args.chain)?;
    let res = instance.validate(&chain, &task, args.repeat.unwrap_or(1))?;

    eprintln!("result: {:?}", res);

    Ok(())
}
