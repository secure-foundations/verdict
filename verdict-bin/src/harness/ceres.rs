use std::path::PathBuf;
use std::process;

use chrono::{TimeZone, Utc};

use super::common::*;
use crate::error::*;

pub struct CeresHarness {
    pub repo: String,
    pub faketime_lib: String,
    pub debug: bool,
}

impl Harness for CeresHarness {
    fn spawn(&self, roots_path: &str, timestamp: u64) -> Result<Box<dyn Instance>, Error> {
        let mut driver_path = PathBuf::from(&self.repo);
        driver_path.extend(["src", "driver.py"]);

        let fake_time = Utc
            .timestamp_opt(timestamp as i64, 0)
            .unwrap()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();

        // Check `args.faketime_lib` exists
        if !PathBuf::from(&self.faketime_lib).exists() {
            return Err(Error::LibFakeTimeNotFound(self.faketime_lib.clone()));
        }

        if !driver_path.exists() {
            return Err(Error::CeresRepoNotFound(driver_path.display().to_string()));
        }

        let mut cmd = process::Command::new("python3");
        cmd.current_dir(&self.repo)
            // Use libfaketime to change the validation time
            .env("LD_PRELOAD", &self.faketime_lib)
            .env("FAKETIME", &format!("@{}", fake_time))
            .arg(std::fs::canonicalize(driver_path)?)
            .arg(std::fs::canonicalize(roots_path)?)
            .arg("--check-purpose")
            .arg("serverAuth")
            .stdin(process::Stdio::piped())
            .stdout(process::Stdio::piped());

        if !self.debug {
            cmd.stderr(process::Stdio::null());
        };

        Ok(Box::new(CommonBenchInstance::new(cmd.spawn()?, timestamp)?))
    }
}
