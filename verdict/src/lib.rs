//! Welcome to the documentation for `verdict`, a formally verified
//! X.509 certificate validation library (developed using [Verus](https://verus.rs)).
//! You can also find a CLI tool and more details about Verdict at [our GitHub repo](https://github.com/secure-foundations/verdict).
//!
//! This is still a very experimental tool, so the API here is likely rough around
//! the edges and subject to change.
//!
//! An example usage of `verdict`:
//! ```rust
//! use verdict::{ChromePolicy, RootStore, Task, Validator};
//!
//! const ROOTS: &[u8] = include_bytes!("roots.pem");
//! const CHAIN: &[u8] = include_bytes!("chain.pem");
//!
//! let roots = RootStore::from_pem(ROOTS).unwrap();
//! let validator = Validator::from_roots(ChromePolicy::default(), &roots).unwrap();
//! let task = Task::new_server_auth(Some("<hostname>"), <UNIX timestamp>);
//!
//! let valid = validator.validate_pem(CHAIN, &task).unwrap();
//! ```
//! Here, both the root certificates and certificate chain are
//! loaded in PEM format.
//! The result in `valid` indicates whether Chromium's X.509
//! validation policy that we modeled in Verdict ([`ChromePolicy`])
//! considers the certificate chain valid (agsinst the provided root
//! store, hostname, and timestamp).
//!
//! We have also modeled the X.509 validation policies in
//! Firefox ([`FirefoxPolicy`]) and OpenSSL ([`OpenSSLPolicy`]).

#![deny(unsafe_code)]
#![warn(rust_2018_idioms)]

mod issue;
mod hash;
mod signature;
mod convert;

mod error;
mod policy;
mod validator;
mod utils;
mod api;

pub use api::*;
