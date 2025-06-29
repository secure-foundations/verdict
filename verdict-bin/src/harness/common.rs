use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout};

use clap::{Parser, ValueEnum};
use verdict::Task;

use super::armor::*;
use super::ceres::*;
use super::chrome::*;
use super::firefox::*;
use super::hammurabi::*;
use super::openssl::*;
use super::verdict::*;
use super::verdict::*;
use crate::error::*;

#[derive(Debug)]
pub struct ValidationResult {
    pub valid: bool,
    pub err: String,
    pub stats: Vec<u64>, // Durations in microseconds
}

/// NOTE: both `spawn` and `ExecTask` include timestamps
/// this is because for some harnesses, we had to use libfaketime
/// to set the time, which is only doable at the beginning
pub trait Harness {
    fn spawn(&self, roots_path: &str, timestamp: u64) -> Result<Box<dyn Instance>, Error>;
}

pub trait Instance: Send {
    fn validate(
        &mut self,
        bundle: &Vec<String>,
        task: &Task,
        repeat: usize,
    ) -> Result<ValidationResult, Error>;
}

/// A common protocol used by the test harnesses of Chrome, Firefox, etc.
/// Basically the frontend sends benchmarking task (leaf, intermediates, repeat, etc.)
/// and the server implementing the benchmark performs the task in its native language
pub struct CommonBenchInstance {
    timestamp: u64,
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl CommonBenchInstance {
    pub fn new(mut child: Child, timestamp: u64) -> Result<CommonBenchInstance, Error> {
        let stdin = child.stdin.take().ok_or(Error::ChildStdin)?;
        let stdout = child.stdout.take().ok_or(Error::ChildStdout)?;
        Ok(CommonBenchInstance {
            timestamp,
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }
}

impl Instance for CommonBenchInstance {
    fn validate(
        &mut self,
        bundle: &Vec<String>,
        task: &Task,
        repeat: usize,
    ) -> Result<ValidationResult, Error> {
        if bundle.len() == 0 {
            return Err(Error::EmptyBundle);
        }

        if repeat == 0 {
            return Err(Error::ZeroRepeat);
        }

        let task_str = match task.hostname() {
            Some(hostname) => {
                if hostname.trim().is_empty() {
                    // Abort if the domain is empty
                    return Ok(ValidationResult {
                        valid: false,
                        err: "empty domain name".to_string(),
                        stats: vec![0; repeat],
                    });
                }
                format!("domain: {}", hostname)
            }
            None => "validate".to_string(),
        };

        // Check that `task`'s timestamp is consistent with `spawn`
        if task.timestamp() != self.timestamp {
            return Err(Error::Inconsistentimestamps);
        }

        writeln!(self.stdin, "repeat: {}", repeat)?;
        writeln!(self.stdin, "leaf: {}", bundle[0])?;
        for cert in bundle.iter().skip(1) {
            writeln!(self.stdin, "interm: {}", cert)?;
        }
        writeln!(self.stdin, "{}", task_str)?;

        let mut line = String::new();

        if self.stdout.read_line(&mut line)? == 0 {
            return Err(Error::CommonBenchError("failed to read stdout".to_string()));
        }

        // Wait for the bench server to send back the result in the form of
        // `result: <OK or err msg> <sample 1 time> <sample 2 time> ...`
        if line.starts_with("result:") {
            let mut res = line["result:".len()..].trim().split_ascii_whitespace();
            let res_fst = res
                .next()
                .ok_or(Error::CommonBenchError("no results".to_string()))?;

            Ok(ValidationResult {
                valid: res_fst == "OK",
                err: if res_fst == "OK" {
                    "".to_string()
                } else {
                    res_fst.trim().to_string()
                },

                // Parse the rest as a space separated list of integers (time in microseconds)
                stats: res
                    .map(|s| s.parse())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| Error::CommonBenchError("failed to parse results".to_string()))?,
            })
        } else if line.starts_with("error:") {
            Err(Error::CommonBenchError(
                line["error:".len()..].trim().to_string(),
            ))
        } else {
            Err(Error::CommonBenchError(format!(
                "unexpected output: {}",
                line
            )))
        }
    }
}

impl Drop for CommonBenchInstance {
    fn drop(&mut self) {
        if let Some(status) = self.child.try_wait().unwrap() {
            eprintln!("cert bench failed with: {}", status);
        }

        // We expect the process to be still running
        // so no need to consume the status here
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}

#[derive(Debug, Clone, ValueEnum)]
pub enum HarnessName {
    Chrome,
    Firefox,
    #[clap(name = "openssl")]
    OpenSSL,
    Armor,
    HammurabiChrome,
    HammurabiFirefox,
    Ceres,
    VerdictChrome,
    VerdictFirefox,
    #[clap(name = "verdict-openssl")]
    VerdictOpenSSL,
}

/// Arguments to load a harness
#[derive(Parser, Debug)]
pub struct HarnessArgs {
    /// X509 validator used for benchmarking
    name: HarnessName,

    /// For any harness, if the specific `<harness>_repo`
    /// flag is not given, and --bench-repo is specified,
    /// then we will use the path `<bench_repo>/<harness>`
    /// as the harness repo
    #[clap(long)]
    bench_repo: Option<String>,

    /// Path to the Chrome build repo with cert_bench
    #[clap(long)]
    chrome_repo: Option<String>,

    /// Path to the Firefox build repo
    #[clap(long)]
    firefox_repo: Option<String>,

    /// Path to the OpenSSL harness repo
    #[clap(long)]
    openssl_repo: Option<String>,

    /// Path to the ARMOR repo
    #[clap(long)]
    armor_repo: Option<String>,

    /// Path to the Hammurabi repo
    #[clap(long)]
    hammurabi_repo: Option<String>,

    /// Path to the CERES repo
    #[clap(long)]
    ceres_repo: Option<String>,

    /// Path to libfaketime.so
    #[clap(
        long,
        default_value = "/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1"
    )]
    faketime_lib: String,
}

/// Generate a dynamic Harness according the given arguments
pub fn get_harness_from_args(args: &HarnessArgs, debug: bool) -> Result<Box<dyn Harness>, Error> {
    let bench_repo = match args.bench_repo.clone() {
        Some(p) => std::fs::canonicalize(p)
            .ok()
            .map(|p| p.to_string_lossy().to_string()),
        None => None,
    };

    Ok(match args.name {
        HarnessName::Chrome => Box::new(ChromeHarness {
            repo: args
                .chrome_repo
                .clone()
                .or(bench_repo.clone().map(|p| p + "/chromium"))
                .ok_or(Error::CommonBenchError(
                    "chrome repo not specified".to_string(),
                ))?,
            faketime_lib: args.faketime_lib.clone(),
            debug,
        }),

        HarnessName::Firefox => Box::new(FirefoxHarness {
            repo: args
                .firefox_repo
                .clone()
                .or(bench_repo.clone().map(|p| p + "/firefox"))
                .ok_or(Error::CommonBenchError(
                    "firefox repo not specified".to_string(),
                ))?,
            debug,
        }),

        HarnessName::OpenSSL => Box::new(OpenSSLHarness {
            repo: args
                .openssl_repo
                .clone()
                .or(bench_repo.clone().map(|p| p + "/openssl"))
                .ok_or(Error::CommonBenchError(
                    "openssl repo not specified".to_string(),
                ))?,
            debug,
        }),

        HarnessName::Armor => Box::new(ArmorHarness {
            repo: args
                .armor_repo
                .clone()
                .or(bench_repo.clone().map(|p| p + "/armor"))
                .ok_or(Error::CommonBenchError(
                    "armor repo not specified".to_string(),
                ))?,
            faketime_lib: args.faketime_lib.clone(),
            debug,
        }),

        HarnessName::HammurabiChrome => Box::new(HammurabiHarness {
            repo: args
                .hammurabi_repo
                .clone()
                .or(bench_repo.clone().map(|p| p + "/hammurabi"))
                .ok_or(Error::CommonBenchError(
                    "hammurabi repo not specified".to_string(),
                ))?,
            policy: HammurabiPolicy::Chrome,
            debug,
        }),

        HarnessName::HammurabiFirefox => Box::new(HammurabiHarness {
            repo: args
                .hammurabi_repo
                .clone()
                .or(bench_repo.clone().map(|p| p + "/hammurabi"))
                .ok_or(Error::CommonBenchError(
                    "hammurabi repo not specified".to_string(),
                ))?,
            policy: HammurabiPolicy::Firefox,
            debug,
        }),

        HarnessName::Ceres => Box::new(CeresHarness {
            repo: args
                .ceres_repo
                .clone()
                .or(bench_repo.clone().map(|p| p + "/ceres"))
                .ok_or(Error::CommonBenchError(
                    "ceres repo not specified".to_string(),
                ))?,
            faketime_lib: args.faketime_lib.clone(),
            debug,
        }),

        HarnessName::VerdictChrome => Box::new(VerdictHarness {
            policy: VerdictPolicyName::Chrome,
            debug,
        }),

        HarnessName::VerdictFirefox => Box::new(VerdictHarness {
            policy: VerdictPolicyName::Firefox,
            debug,
        }),

        HarnessName::VerdictOpenSSL => Box::new(VerdictHarness {
            policy: VerdictPolicyName::OpenSSL,
            debug,
        }),
    })
}
