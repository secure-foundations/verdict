use std::fs::File;
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use chrono::Utc;
use clap::Parser;
use crossbeam::channel;
use crossbeam::channel::Receiver;
use crossbeam::channel::Sender;
use csv::{ReaderBuilder, WriterBuilder};
use verdict::Task;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::ct_logs::*;
use crate::error::*;
use crate::harness::*;
use crate::utils::*;

#[derive(Parser, Debug)]
pub struct Args {
    /// X509 validator used for benchmarking
    #[clap(flatten)]
    harness: HarnessArgs,

    /// Path to the root certificates
    roots: String,

    /// Directory containing intermediate certificates
    interm_dir: String,

    #[clap(num_args = 1..)]
    csv_files: Vec<String>,

    /// Only test the certificate with the given hash
    #[clap(long)]
    hash: Option<String>,

    /// Store the results in the given CSV file
    #[clap(short = 'o', long)]
    out_csv: Option<String>,

    /// Number of parallel threads to run validation
    #[clap(short = 'j', long = "jobs", default_value = "1")]
    num_jobs: usize,

    /// Only validate the first LIMIT certificates, if specified
    #[clap(long)]
    limit: Option<usize>,

    /// Skip the first SKIP certificates
    #[clap(long)]
    skip: Option<usize>,

    /// Repeat validation of each certificate for benchmarking
    #[clap(short = 'n', long, default_value = "1")]
    repeat: usize,

    /// Override the current time with the given timestamp
    #[clap(short = 't', long)]
    override_time: Option<i64>,

    /// Enable debug mode
    #[arg(long, default_value_t = false)]
    debug: bool,

    /// Do chain validation only without domain
    #[arg(long, default_value_t = false)]
    no_domain: bool,

    /// Each certificate is only chosen for testing with the given probability (Bernoulli sampling)
    #[arg(long)]
    sample: Option<f64>,

    /// Seed for the --sample flag
    #[arg(long, default_value_t = 0)]
    sample_seed: u32,
}

/// Each worker thread waits for CTLogEntry's, does the validation, and then sends back CTLogResult's
fn worker(
    args: &Args,
    timestamp: u64,
    mut instance: Box<dyn Instance>,
    rx_job: Receiver<CTLogEntry>,
    tx_res: Sender<CTLogResult>,
) -> Result<(), Error> {
    // Recv a CTLogEntry
    while let Ok(entry) = rx_job.recv() {
        let mut bundle = vec![entry.cert_base64.to_string()];

        // Look up all intermediate certificates <args.interm_dir>/<entry.interm_certs>.pem
        // `entry.interm_certs` is a comma-separated list
        for interm_cert in entry.interm_certs.split(",") {
            bundle.extend(read_pem_file_as_base64(&format!(
                "{}/{}.pem",
                &args.interm_dir, interm_cert
            ))?);
        }

        let res = if args.no_domain {
            instance.validate(
                &bundle,
                &Task::new_server_auth(None, timestamp),
                args.repeat,
            )?
        } else {
            instance.validate(
                &bundle,
                &Task::new_server_auth(Some(&entry.domain), timestamp),
                args.repeat,
            )?
        };

        // Send back a CTLogResult
        tx_res.send(CTLogResult {
            hash: entry.hash,
            domain: entry.domain,
            valid: res.valid,
            err: res.err,
            stats: res.stats,
        })?;
    }

    Ok(())
}

/// Collect validation results from `rx_res` and write them to a CSV file (or stdout if not specified)
fn reducer(
    mut output_writer: csv::Writer<Box<dyn io::Write + Sync + Send>>,
    rx_res: Receiver<CTLogResult>,
) -> Result<(), Error> {
    // Open the output file if it exists, otherwise use stdout
    // let handle: Box<dyn io::Write> = if let Some(out_path) = out_csv {
    //     Box::new(File::create(out_path)?)
    // } else {
    //     Box::new(std::io::stdout())
    // };
    // let mut output_writer =
    //     WriterBuilder::new().has_headers(false).from_writer(handle);

    let start = Instant::now();

    while let Ok(res) = rx_res.recv() {
        output_writer.serialize(res)?;
        output_writer.flush()?;
    }

    eprintln!(
        "total validation time: {:.3}s",
        start.elapsed().as_secs_f64()
    );

    Ok(())
}

pub fn main(args: Args) -> Result<(), Error> {
    let args = Arc::new(args);

    if args.csv_files.is_empty() {
        eprintln!("no csv files given");
        return Ok(());
    }

    if !Path::new(&args.roots).is_file() {
        return Err(Error::RootsNotFound(args.roots.to_string()));
    }

    let timestamp = args.override_time.unwrap_or(Utc::now().timestamp()) as u64;
    let harness: Box<dyn Harness> = get_harness_from_args(&args.harness, args.debug)?;

    let (tx_job, rx_job) = channel::bounded(args.num_jobs);
    let (tx_res, rx_res) = channel::bounded(args.num_jobs);

    let mut workers = Vec::new();

    let mut seed = [0u8; 32];
    seed[0..4].copy_from_slice(&args.sample_seed.to_le_bytes());
    let mut rng = StdRng::from_seed(seed);

    // Main thread: read the input CSV files and send jobs (CTLogEntry's) to worker threads
    let inner = || {
        let handle: Box<dyn io::Write + Sync + Send> = if let Some(out_path) = &args.out_csv {
            Box::new(File::create(out_path)?)
        } else {
            Box::new(std::io::stdout())
        };
        let output_writer = WriterBuilder::new().has_headers(false).from_writer(handle);

        for _ in 0..args.num_jobs {
            let args = args.clone();
            let instance = harness.spawn(&args.roots, timestamp)?;
            let rx_job = rx_job.clone();
            let tx_res = tx_res.clone();

            workers.push(thread::spawn(move || {
                worker(&args, timestamp, instance, rx_job, tx_res)
            }));
        }

        workers.push(thread::spawn(move || reducer(output_writer, rx_res)));

        let mut found_hash = false;
        let mut i: usize = 0;

        let skip = args.skip.unwrap_or(0);

        'outer: for path in &args.csv_files {
            let file = File::open(path)?;
            let mut reader = ReaderBuilder::new().has_headers(false).from_reader(file);

            for entry in reader.deserialize() {
                let entry: CTLogEntry = entry?;

                // Sampling is applied first, if specified
                if let Some(sample) = args.sample {
                    if rng.gen::<f64>() >= sample {
                        continue;
                    }
                }

                if let Some(limit) = args.limit {
                    if i >= limit + skip {
                        break;
                    }
                }

                // Filter out tasks with empty domain name, IP address, or unicode character that failed to parse
                if entry.domain.is_empty()
                    || entry.domain.parse::<IpAddr>().is_ok()
                    || entry.domain.contains('\u{FFFD}')
                {
                    // eprintln!("Skipping {} due to unsupported domain name \"{}\"", &entry.hash, &entry.domain);
                    continue;
                }

                i += 1;

                if i <= skip {
                    continue;
                }

                // If a specific hash is specified, only check certificate with that hash
                if let Some(hash) = &args.hash {
                    if hash != &entry.hash {
                        continue;
                    } else {
                        found_hash = true;
                    }
                }

                tx_job.send(entry)?;

                if found_hash {
                    break 'outer;
                }
            }
        }

        if let Some(hash) = &args.hash {
            if !found_hash {
                eprintln!("hash {} not found in the given CSV files", hash);
            }
        }

        if args.sample.is_some() {
            eprintln!("sampled {} certificates", i);
        }

        Ok(())
    };

    let res = inner();

    // Signal no more jobs
    drop(tx_job);
    drop(tx_res);

    // Join all workers at the end
    for (i, worker) in workers.into_iter().enumerate() {
        match worker.join() {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                eprintln!("worker {} failed with error: {}", i, err);
            }
            Err(err) => {
                eprintln!("failed to join worker {}: {:?}", i, err);
            }
        }
    }

    res
}
