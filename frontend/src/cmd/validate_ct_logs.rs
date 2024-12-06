use std::io;
use std::fs::File;

use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use chain::policy::ExecTask;
use clap::Parser;
use csv::{ReaderBuilder, WriterBuilder};

use parser::{parse_x509_der, decode_base64, VecDeep};
use chain::validate::Validator;

use crate::ct_logs::*;
use crate::error::*;
use crate::utils::*;
use crate::validator;

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(flatten)]
    validator: validator::Args,

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

    /// Only validate the first <limit> certificates, if specified
    #[clap(short = 'l', long)]
    limit: Option<usize>,
}

struct ValidationResult {
    hash: String,
    domain: String,
    result: Result<bool, Error>,
}

type Timer = Arc<Mutex<Duration>>;

fn validate_ct_logs_job(
    args: &Args,
    validator: &Validator,
    entry: &CTLogEntry,
    timer: &Timer,
) -> Result<bool, Error>
{
    let mut chain_bytes = vec![decode_base64(&entry.cert_base64.as_bytes())?];

    // Look up all intermediate certificates <args.interm_dir>/<entry.interm_certs>.pem
    // `entry.interm_certs` is a comma-separated list
    for interm_cert in entry.interm_certs.split(",") {
        chain_bytes.extend(read_pem_file_as_bytes(&format!("{}/{}.pem", &args.interm_dir, interm_cert))?);
    }

    let begin = Instant::now();

    let chain =
        VecDeep::from_vec(chain_bytes.iter().map(|bytes| parse_x509_der(bytes)).collect::<Result<Vec<_>, _>>()?);

    let task = ExecTask::DomainValidation(entry.domain.to_string());

    if args.validator.debug {
        print_debug_info(&validator.roots, &chain, &task, validator.get_validation_time());
    }

    let res = validator.validate(&chain, &task)?;

    *timer.lock().unwrap() += begin.elapsed();

    Ok(res)
}

pub fn main(args: Args) -> Result<(), Error>
{
    let args = Arc::new(args);
    // let heap_profiler = heappy::HeapProfilerGuard::new(1).unwrap();

    eprintln!("validating {} CT log file(s)", args.csv_files.len());

    let (tx_job, rx_job) = crossbeam::channel::unbounded::<CTLogEntry>();
    let (tx_res, rx_res) = mpsc::channel();

    let timer = Arc::new(Mutex::new(Duration::new(0, 0)));

    // Spawn <num_jobs> many worker threads
    let mut workers = (0..args.num_jobs).map(|_| {
        let rx_job = rx_job.clone();
        let tx_res = tx_res.clone();
        let args = args.clone();
        let timer = timer.clone();

        // Each worker thread waits for jobs, does the validation, and then sends back the result
        thread::spawn(move || -> Result<(), Error> {
            // Each thread has to parse its own copy of the root certs and policy

            // Parse root certificates
            // TODO: move this outside
            let roots_bytes = read_pem_file_as_bytes(&args.roots)?;
            let roots =
                roots_bytes.iter().map(|bytes| parse_x509_der(bytes)).collect::<Result<Vec<_>, _>>()?;

            let validator = validator::new_validator(&args.validator, roots)?;

            while let Ok(entry) = rx_job.recv() {
                tx_res.send(ValidationResult {
                    hash: entry.hash.clone(),
                    domain: entry.domain.clone(),
                    result: validate_ct_logs_job(
                        &args,
                        &validator,
                        &entry,
                        &timer,
                    ),
                })?;
            }

            Ok(())
        })
    }).collect::<Vec<_>>();

    // Spawn another thread to collect results and write to output
    let out_csv = args.out_csv.clone();
    workers.push(thread::spawn(move || -> Result<(), Error> {
        // Open the output file if it exists, otherwise use stdout
        let handle: Box<dyn io::Write> = if let Some(out_path) = out_csv {
            Box::new(File::create(out_path)?)
        } else {
            Box::new(std::io::stdout())
        };
        let mut output_writer =
            WriterBuilder::new().has_headers(false).from_writer(handle);

        let mut num_res = 0;
        let begin = Instant::now();

        while let Ok(res) = rx_res.recv() {
            let result_str = match res.result {
                Ok(res) => res.to_string(),
                Err(err) => format!("fail: {}", err),
            };

            output_writer.serialize(CTLogResultLegacy {
                hash: res.hash,
                domain: res.domain,
                result: result_str,
            })?;
            output_writer.flush()?;

            // if num_res % 50 == 0 {
            //     eprint!("\rvalidation average: {:.2}ms", timer.lock().unwrap().as_micros() as f64 / num_res as f64 / 1000f64);
            // }
            num_res += 1;
        }

        // eprintln!("");
        eprintln!("validated {} certificate(s); validation took {:.3}s (across threads); total: {:.3}s",
            num_res, timer.lock().unwrap().as_secs_f64(), begin.elapsed().as_secs_f64());

        Ok(())
    }));

    let mut found_hash = false;
    for path in &args.csv_files {
        let file = File::open(path)?;
        let mut reader = ReaderBuilder::new()
            .has_headers(false)  // If your CSV has headers
            .from_reader(file);

        for (i, entry) in reader.deserialize().enumerate() {
            let entry: CTLogEntry = entry?;

            if let Some(limit) = args.limit {
                if i >= limit {
                    break;
                }
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
        }
    }

    if let Some(hash) = &args.hash {
        if !found_hash {
            eprintln!("hash {} not found in the given CSV files", hash);
        }
    }

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

    // let report = heap_profiler.report();

    // let mut file = std::fs::File::create("memflame.svg").unwrap();
    // report.flamegraph(&mut file);

    // let mut file = std::fs::File::create("memflame.pb").unwrap();
    // report.write_pprof(&mut file).unwrap();

    Ok(())
}
