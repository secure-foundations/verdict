use std::path::PathBuf;
use std::process;

use chrono::{TimeZone, Utc};

use super::common::*;
use crate::error::*;

pub enum HammurabiPolicy {
    Chrome,
    Firefox,
}

pub struct HammurabiHarness {
    pub repo: String,
    pub policy: HammurabiPolicy,
    pub debug: bool,
}

impl Harness for HammurabiHarness {
    fn spawn(&self, roots_path: &str, timestamp: u64) -> Result<Box<dyn Instance>, Error> {
        let mut bin_path = PathBuf::from(&self.repo);
        bin_path.extend(["target", "release", "bench"]);

        if !bin_path.exists() {
            return Err(Error::HammurabiRepoNotFound(bin_path.display().to_string()));
        }

        let mut cmd = process::Command::new(bin_path);
        cmd.current_dir(&self.repo)
            .arg(match self.policy {
                HammurabiPolicy::Chrome => "chrome",
                HammurabiPolicy::Firefox => "firefox",
            })
            .arg(std::fs::canonicalize(roots_path)?) // Use libfaketime to change the validation time
            .arg(timestamp.to_string())
            .arg("--ignore-root-parse-error")
            .stdin(process::Stdio::piped())
            .stdout(process::Stdio::piped());

        if !self.debug {
            cmd.stderr(process::Stdio::null());
        };

        Ok(Box::new(CommonBenchInstance::new(cmd.spawn()?, timestamp)?))
    }
}
