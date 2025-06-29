use std::path::PathBuf;
use std::process;

use super::common::*;
use crate::error::*;

pub struct FirefoxHarness {
    pub repo: String,
    pub debug: bool,
}

impl Harness for FirefoxHarness {
    /// Spawns a child process to run cert_bench
    fn spawn(&self, roots_path: &str, timestamp: u64) -> Result<Box<dyn Instance>, Error> {
        let mut bin_path = PathBuf::from(&self.repo);
        bin_path.extend(["cert_bench.sh"]);

        if !bin_path.exists() {
            return Err(Error::FirefoxRepoNotFound(bin_path.display().to_string()));
        }

        let mut cmd = process::Command::new(bin_path.clone());
        cmd.arg(roots_path)
            .arg(timestamp.to_string())
            .stdin(process::Stdio::piped())
            .stdout(process::Stdio::piped());

        if !self.debug {
            cmd.stderr(process::Stdio::null());
        };

        Ok(Box::new(CommonBenchInstance::new(cmd.spawn()?, timestamp)?))
    }
}
