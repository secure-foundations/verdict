//! Welcome to the documentation for `verdict`, a formally verified
//! X.509 certificate validation library (developed using [Verus](https://verus.rs)).
//! You can also find a CLI tool and more details about Verdict at [our GitHub repo](https://github.com/secure-foundations/verdict).
//! 
//! This is still a very experimental tool, so the API here is likely rough around
//! the edges and subject to change.
//! 
//! An example usage of `verdict`:
//! ```rust
//! use verdict::{Validator, RootStore, ChromePolicy, ExecTask, ExecPurpose};
//! 
//! let roots = RootStore::from_base64(<root certificates>).unwrap();
//! let validator = Validator::from_root_store(ChromePolicy, &roots).unwrap();
//! let valid = validator.validate_base64(
//!     <certificate chain, with the first element being the leaf>,
//!     &ExecTask {
//!         hostname: Some("<hostname>".to_string()),
//!         purpose: ExecPurpose::ServerAuth,
//!         now: 1751058397,
//!     },
//! ).unwrap();
//! ```
//! Here, both the root certificates and certificate chain are
//! X.509 certificates in ASN.1 DER format, encoded in Base64.
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

pub use error::{
    ValidationError, ParseError,
};

pub use validator::{
    validate_x509_base64, RootStore, Validator,
};

pub use policy::{
    ChromePolicy, FirefoxPolicy, OpenSSLPolicy,
    ExecCertificate, ExecPurpose, ExecTask, Policy,
};

pub use verdict_parser::{
    parse_x509_der, decode_base64,
};
