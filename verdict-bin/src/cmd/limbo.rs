use std::fs::File;
use std::io::{self, BufReader, BufWriter, Write};
use std::thread;

use chrono::Utc;
use clap::Parser;
use crossbeam::channel::{self, Receiver, Sender};
use csv::WriterBuilder;
use limbo_harness_support::models::{ExpectedResult, Limbo, PeerKind, Testcase, ValidationKind};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use verdict::Task;

use crate::error::*;
use crate::harness::*;

#[derive(Parser, Debug)]
pub struct Args {
    /// X509 validator used for testing
    #[clap(flatten)]
    harness: HarnessArgs,

    /// Path to the Limbo test cases
    path: String,

    /// Number of parallel threads to run validation
    #[clap(short = 'j', long = "jobs", default_value = "1")]
    num_jobs: usize,

    /// Test a particular test ID
    #[clap(short = 't', long = "test")]
    test_id: Option<String>,

    /// Only validate the first LIMIT certificates, if specified
    #[clap(short = 'l', long)]
    limit: Option<usize>,

    /// Enable debug mode
    #[arg(long, default_value_t = false)]
    debug: bool,

    /// Do chain validation only without domain
    #[arg(long, default_value_t = false)]
    no_domain: bool,

    /// Repeat validation of each certificate for benchmarking
    #[clap(short = 'n', long, default_value = "1")]
    repeat: usize,
}

/// x509-limbo resultsw
#[derive(Debug, Deserialize, Serialize)]
pub struct LimboResult {
    pub id: String,
    pub expected: bool,
    pub valid: bool,
    pub err_msg: String,
}

/// Strip -----BEGIN CERTIFICATE----- and -----END CERTIFICATE-----
/// and remove any whitespaces
fn strip_pem(s: &str) -> Option<String> {
    Some(
        s.trim()
            .strip_prefix("-----BEGIN CERTIFICATE-----")?
            .strip_suffix("-----END CERTIFICATE-----")?
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect(),
    )
}

fn test_limbo(
    args: &Args,
    harness: &Box<dyn Harness>,
    testcase: &Testcase,
) -> Result<LimboResult, Error> {
    let tmp_root_file = NamedTempFile::with_suffix(".pem")?;
    let tmp_root_path = tmp_root_file
        .path()
        .to_str()
        .ok_or(io::Error::other("failed to convert path to str"))?
        .to_string();

    let mut writer = BufWriter::new(&tmp_root_file);
    for cert in &testcase.trusted_certs {
        writeln!(writer, "{}", cert)?;
    }
    writer.flush()?;

    let timestamp = testcase.validation_time.unwrap_or(Utc::now()).timestamp() as u64;

    let mut instance = harness.spawn(&tmp_root_path, timestamp)?;

    let mut bundle = vec![strip_pem(&testcase.peer_certificate)
        .ok_or(Error::LimboError("failed to process PEM".to_string()))?];

    for interm in &testcase.untrusted_intermediates {
        bundle
            .push(strip_pem(interm).ok_or(Error::LimboError("failed to process PEM".to_string()))?);
    }

    let task = if let Some(peer_name) = &testcase.expected_peer_name {
        if args.no_domain {
            Task::new_server_auth(None, timestamp)
        } else {
            Task::new_server_auth(Some(&peer_name.value), timestamp)
        }
    } else {
        Task::new_server_auth(None, timestamp)
    };

    let (valid, err_msg) = match instance.validate(&bundle, &task, args.repeat) {
        Ok(res) => (res.valid, res.err),
        Err(e) => (false, format!("{}", e).replace("\n", "")),
    };

    Ok(LimboResult {
        id: testcase.id.to_string(),
        expected: testcase.expected_result == ExpectedResult::Success,
        valid,
        err_msg,
    })
}

fn worker(
    args: &Args,
    rx_job: Receiver<&Testcase>,
    tx_res: Sender<LimboResult>,
) -> Result<(), Error> {
    let harness = get_harness_from_args(&args.harness, args.debug)?;

    while let Ok(testcase) = rx_job.recv() {
        tx_res.send(test_limbo(args, &harness, testcase)?)?;
    }

    Ok(())
}

/// Collect results and write to stdout
fn reducer(rx_res: Receiver<LimboResult>) -> Result<(), Error> {
    let mut output_writer = WriterBuilder::new()
        .has_headers(false)
        .from_writer(std::io::stdout());

    let mut total = 0;
    let mut conformant = 0;

    while let Ok(res) = rx_res.recv() {
        total += 1;
        if res.expected == res.valid {
            conformant += 1;
        }

        output_writer.serialize(res)?;
        output_writer.flush()?;
    }

    eprintln!(
        "{}/{} conformant ({} errors)",
        conformant,
        total,
        total - conformant
    );

    Ok(())
}

pub fn main(args: Args) -> Result<(), Error> {
    let limbo: Limbo = serde_json::from_reader(BufReader::new(File::open(&args.path)?))?;
    eprintln!("loaded {} testcases", limbo.testcases.len());

    // Only perform server authentication and DNS name validation (if enabled)
    let filter = |t: &&Testcase| {
        t.validation_kind == ValidationKind::Server
            && (t.expected_peer_name.is_some()
                && t.expected_peer_name.as_ref().unwrap().kind == PeerKind::Dns)
            && if let Some(id) = &args.test_id {
                &t.id.to_string() == id
            } else {
                true
            }
    };

    let (tx_job, rx_job) = channel::bounded(args.num_jobs);
    let (tx_res, rx_res) = channel::bounded(args.num_jobs);

    thread::scope(|scope| -> Result<(), Error> {
        for _ in 0..args.num_jobs {
            let tx_res = tx_res.clone();
            let rx_job = rx_job.clone();
            scope.spawn(|| worker(&args, rx_job, tx_res));
        }

        scope.spawn(|| reducer(rx_res));

        for (i, testcase) in limbo.testcases.iter().filter(filter).enumerate() {
            if let Some(limit) = args.limit {
                if i >= limit {
                    break;
                }
            }

            tx_job.send(testcase)?;
        }

        drop(tx_job);
        drop(tx_res);

        Ok(())
    })
}
