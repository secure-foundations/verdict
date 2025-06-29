use std::cell::RefCell;
use std::thread;
use std::thread::JoinHandle;
use std::time::Instant;

use clap::ValueEnum;

use verdict::{ChromePolicy, FirefoxPolicy, OpenSSLPolicy, Policy, RootStore, Task, Validator};

use crossbeam::channel;
use crossbeam::channel::Receiver;
use crossbeam::channel::Sender;

use crate::error::*;
use crate::utils::*;

use super::common::*;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum VerdictPolicyName {
    Chrome,
    Firefox,
    #[clap(name = "openssl")]
    OpenSSL,
}

pub struct VerdictHarness {
    pub policy: VerdictPolicyName,
    pub debug: bool,
}

struct Job {
    bundle: Vec<String>,
    task: Task,
    repeat: usize,
}

pub struct VerdictInstance {
    tx_job: Option<Sender<Job>>,
    rx_res: Option<Receiver<ValidationResult>>,
    handle: Option<JoinHandle<Result<(), Error>>>,
}

impl VerdictInstance {
    fn worker<P: Policy>(
        timestamp: u64,
        roots_base64: Vec<Vec<u8>>,
        policy: P,
        rx_job: Receiver<Job>,
        tx_res: Sender<ValidationResult>,
        debug: bool,
    ) -> Result<(), Error> {
        let store = RootStore::from_base64(roots_base64.iter())?;
        let validator = Validator::from_roots(policy, &store)?;

        while let Ok(Job {
            bundle,
            task,
            repeat,
        }) = rx_job.recv()
        {
            let mut durations = Vec::with_capacity(repeat);
            let mut res: Result<bool, verdict::ValidationError> = Ok(false);
            let bundle_bytes: Vec<_> = bundle
                .into_iter()
                .map(|base64| base64.into_bytes())
                .collect();

            if debug {
                validator.print_debug_info(&bundle_bytes, &task)?;
            }

            if task.timestamp() != timestamp {
                return Err(Error::Inconsistentimestamps);
            }

            for _ in 0..repeat {
                let start = Instant::now();
                res = validator.validate_base64(bundle_bytes.iter(), &task);
                durations.push(
                    start
                        .elapsed()
                        .as_micros()
                        .try_into()
                        .map_err(|_| Error::DurationOverflow)?,
                );
            }

            tx_res.send(ValidationResult {
                valid: match res {
                    Ok(true) => true,
                    _ => false,
                },
                err: match res {
                    Err(e) => Error::from(e).to_string(),
                    _ => "".to_string(),
                },
                stats: durations,
            })?;
        }

        Ok(())
    }
}

impl Harness for VerdictHarness {
    fn spawn(&self, roots_path: &str, timestamp: u64) -> Result<Box<dyn Instance>, Error> {
        let roots_base64 = read_pem_file_as_base64(roots_path)?
            .into_iter()
            .map(|base64| base64.into_bytes())
            .collect();

        let (tx_job, rx_job) = channel::bounded(1);
        let (tx_res, rx_res) = channel::bounded(1);

        let policy_name = self.policy;
        let debug = self.debug;

        Ok(Box::new(VerdictInstance {
            tx_job: Some(tx_job),
            rx_res: Some(rx_res),
            handle: Some(thread::spawn(move || match policy_name {
                VerdictPolicyName::Chrome => VerdictInstance::worker(
                    timestamp,
                    roots_base64,
                    ChromePolicy::default(),
                    rx_job,
                    tx_res,
                    debug,
                ),
                VerdictPolicyName::Firefox => VerdictInstance::worker(
                    timestamp,
                    roots_base64,
                    FirefoxPolicy::default(),
                    rx_job,
                    tx_res,
                    debug,
                ),
                VerdictPolicyName::OpenSSL => VerdictInstance::worker(
                    timestamp,
                    roots_base64,
                    OpenSSLPolicy::default(),
                    rx_job,
                    tx_res,
                    debug,
                ),
            })),
        }))
    }
}

impl Instance for VerdictInstance {
    fn validate(
        &mut self,
        bundle: &Vec<String>,
        task: &Task,
        repeat: usize,
    ) -> Result<ValidationResult, Error> {
        if repeat == 0 {
            return Err(Error::ZeroRepeat);
        }

        self.tx_job
            .as_ref()
            .ok_or(Error::VerdictBenchError(
                "tx_job has already been dropped".to_string(),
            ))?
            .send(Job {
                bundle: bundle.clone(),
                task: task.clone(),
                repeat,
            })?;

        Ok(self
            .rx_res
            .as_ref()
            .ok_or(Error::VerdictBenchError(
                "tx_job has already been dropped".to_string(),
            ))?
            .recv()?)
    }
}

impl Drop for VerdictInstance {
    fn drop(&mut self) {
        drop(self.tx_job.take().unwrap());
        drop(self.rx_res.take().unwrap());

        let Some(handle) = self.handle.take() else {
            eprintln!("verdict impl already joined");
            return;
        };

        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => eprintln!("verdict impl failed with: {:?}", e),
            Err(e) => eprintln!("failed to join verdict impl: {:?}", e),
        }
    }
}
