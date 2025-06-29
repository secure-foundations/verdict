//! Public wrappers for some core constructs.
#![warn(missing_docs)]

use vstd::prelude::*;
use std::io::BufRead;

use crate::error;
use crate::utils::{read_pem_as_base64, PEMParseError};
use crate::validator::{
    RootStore as InternalRootStore,
    Validator as InternalValidator,
};
use crate::policy::{
    Policy as InternalPolicy,
    ExecCertificate as InternalCertificate,
    ExecTask as InternalTask,
    ExecPurpose as InternalPurpose,
    ExecPolicyError as InternalPolicyError,
    ChromePolicy as InternalChromePolicy,
    FirefoxPolicy as InternalFirefoxPolicy,
    OpenSSLPolicy as InternalOpenSSLPolicy,
};
use ref_cast::RefCast;
use thiserror::Error;
use verdict_parser::VecDeep;

pub use verdict_parser::{decode_base64, parse_x509_der, ParseError};

/// Errors in validation, parsing, and policy execution.
#[derive(Debug, Error)]
pub enum ValidationError {
    /// X.509 validation errors (e.g., errors in signature checking).
    #[error("validation error: {0:?}")]
    ValidationError(error::ValidationError),

    /// Errors in parsing X.509/ASN.1 DER.
    #[error("parse error: {0:?}")]
    ParseError(ParseError),

    /// Errors during policy execution.
    #[error("policy error: {0:?}")]
    PolicyError(InternalPolicyError),

    /// Errors in PEM parsing.
    #[error("PEM parse error: {0:?}")]
    PEMParseError(#[from] PEMParseError),
}

/// Common `Result` type for Verdict APIs
pub type Result<T> = std::result::Result<T, ValidationError>;

/// Verus does not support thiserror yet,
/// so we are manually implementing [`From`]
/// traits instead of using `#[from]`
impl From<error::ValidationError> for ValidationError {
    fn from(err: error::ValidationError) -> Self {
        ValidationError::ValidationError(err)
    }
}

impl From<error::ParseError> for ValidationError {
    fn from(err: error::ParseError) -> Self {
        ValidationError::ParseError(err)
    }
}

impl From<InternalPolicyError> for ValidationError {
    fn from(err: InternalPolicyError) -> Self {
        ValidationError::PolicyError(err)
    }
}

/// A collection of trusted root certificates.
pub struct RootStore(InternalRootStore);

impl RootStore {
    /// Creates an empty root store.
    pub fn new() -> Self {
        RootStore(InternalRootStore {
            roots_der: Vec::new(),
        })
    }

    /// Returns the number of root certificates.
    pub fn len(&self) -> usize {
        self.0.roots_der.len()
    }

    /// Adds certificates in DER format.
    /// NOTE: this may not fully parse the certificates until used later.
    pub fn add_der_certs(&mut self, certs: impl Iterator<Item = impl AsRef<[u8]>>) -> Result<()> {
        self.0.roots_der.extend(certs.map(|c| c.as_ref().to_vec()));
        Ok(())
    }

    /// Adds certificates encoded in Base64 format.
    /// NOTE: this may not fully parse the certificates until used later.
    pub fn add_base64_certs(&mut self, certs: impl Iterator<Item = impl AsRef<[u8]>>) -> Result<()> {
        for cert in certs {
            let der = decode_base64(cert.as_ref())?;
            self.0.roots_der.push(der);
        }
        Ok(())
    }

    /// Adds certificates encoded in PEM format.
    /// NOTE: this may not fully parse the certificates until used later.
    pub fn add_pem_certs<R: BufRead>(&mut self, reader: R) -> Result<()> {
        let certs = read_pem_as_base64(reader);
        for cert in certs {
            let der = decode_base64(cert?.as_bytes())?;
            self.0.roots_der.push(der);
        }
        Ok(())
    }

    /// Creates a new [`RootStore`] from certificates encoded in PEM format.
    pub fn from_pem<R: BufRead>(reader: R) -> Result<Self> {
        let mut store = RootStore::new();
        store.add_pem_certs(reader)?;
        Ok(store)
    }

    /// Creates a new [`RootStore`] from certificates encoded in Base64.
    pub fn from_base64(certs: impl Iterator<Item = impl AsRef<[u8]>>) -> Result<Self> {
        let mut store = RootStore::new();
        store.add_base64_certs(certs)?;
        Ok(store)
    }
}

verus! {

/// An intermediate representation of X.509 certificates
/// used in policy execution.
pub type Certificate = InternalCertificate;

/// A task includes auxiliary information
/// needed for policy execution, such as hostname,
/// purpose (e.g., server/client authentication),
/// and current time.
#[derive(RefCast, Debug)]
#[repr(transparent)]
pub struct Task(InternalTask);

/// A wrapper since Verus does not support `dyn`
#[verifier::external_body]
struct BoxDynInternalPolicy<'a>(Box<dyn InternalPolicy + 'a>);

/// `dyn` is currently not supported by Verus, thus putting this here.
impl<'a> InternalPolicy for BoxDynInternalPolicy<'a> {
    uninterp spec fn spec_likely_issued(&self, issuer: crate::policy::Certificate, subject: crate::policy::Certificate) -> bool;
    uninterp spec fn spec_valid_chain(&self, chain: Seq<crate::policy::Certificate>, task: crate::policy::Task) -> bool;

    #[verifier::external_body]
    fn likely_issued(&self, issuer: &InternalCertificate, subject: &InternalCertificate) -> bool {
        self.0.as_ref().likely_issued(issuer, subject)
    }

    #[verifier::external_body]
    fn valid_chain(&self, chain: &Vec<&InternalCertificate>, task: &InternalTask) -> bool {
        self.0.as_ref().valid_chain(chain, task)
    }
}

/// Common trait for all policies (e.g. [`ChromePolicy`]).
pub trait Policy: Send + Sync {
    /// A policy-dependent predicate to check if `subject`
    /// is likely issued by `issuer` prior to signature checking.
    fn likely_issued(&self, issuer: &Certificate, subject: &Certificate) -> bool;

    /// A policy-specific predicate to check if a certificate chain is
    /// considered valid with the provided [`Task`], provided that
    /// for each `i`, `chain[i]` is issued by `chain[i + 1]`,
    /// and `chain.last()` is a trusted root certificate.
    fn valid_chain(&self, chain: &Vec<&Certificate>, task: &Task) -> bool;
}

/// Converts the public version of [`Policy`] into the internal version.
impl<P: Policy> InternalPolicy for P {
    uninterp spec fn spec_likely_issued(&self, issuer: crate::policy::Certificate, subject: crate::policy::Certificate) -> bool;
    uninterp spec fn spec_valid_chain(&self, chain: Seq<crate::policy::Certificate>, task: crate::policy::Task) -> bool;

    #[verifier::external_body]
    fn likely_issued(&self, issuer: &InternalCertificate, subject: &InternalCertificate) -> bool {
        self.likely_issued(issuer, subject)
    }

    #[verifier::external_body]
    fn valid_chain(&self, chain: &Vec<&InternalCertificate>, task: &InternalTask) -> bool {
        self.valid_chain(chain, Task::ref_cast(task))
    }
}

}

impl Clone for Task {
    fn clone(&self) -> Self {
        Task(self.0.clone())
    }
}

impl Task {
    /// Creates a new [`Task`] for server authentication,
    /// specifying the (optional) hostname and UNIX timestamp
    /// as the validation time.
    pub fn new_server_auth(
        hostname: Option<&str>,
        now: u64,
    ) -> Self {
        Task(InternalTask {
            hostname: hostname.map(|s| s.to_string()),
            purpose: InternalPurpose::ServerAuth,
            now,
        })
    }

    /// Creates a new [`Task`] for server authentication,
    /// specifying the (optional) hostname, and using
    /// the current time as the validation time
    pub fn new_server_auth_now(hostname: Option<&str>) -> Self {
        Task(InternalTask {
            hostname: hostname.map(|s| s.to_string()),
            purpose: InternalPurpose::ServerAuth,
            now: chrono::Utc::now().timestamp() as u64,
        })
    }

    /// Returns the optional hostname associated with this task.
    pub fn hostname(&self) -> Option<&str> {
        self.0.hostname.as_deref()
    }

    /// Returns the validation timestamp.
    pub fn timestamp(&self) -> u64 {
        self.0.now
    }
}

impl<'a, P: Policy + 'a> Policy for &'a P {
    fn likely_issued(&self, issuer: &Certificate, subject: &Certificate) -> bool {
        Policy::likely_issued(*self, issuer, subject)
    }

    fn valid_chain(&self, chain: &Vec<&Certificate>, task: &Task) -> bool {
        Policy::valid_chain(*self, chain, task)
    }
}

/// Implements [`Policy`] for an internal policy.
macro_rules! wrap_internal_policy {
    ($new:ident, $internal:ty, $doc:expr $(,)?) => {
        #[doc=$doc]
        #[derive(Debug)]
        pub struct $new($internal);

        impl Policy for $new {
            fn likely_issued(&self, issuer: &Certificate, subject: &Certificate) -> bool {
                self.0.likely_issued(issuer, subject)
            }

            fn valid_chain(&self, chain: &Vec<&Certificate>, task: &Task) -> bool {
                self.0.valid_chain(chain, &task.0)
            }
        }
    };
}

wrap_internal_policy!(
    ChromePolicy,
    InternalChromePolicy,
    "A model of Chromium's X.509 validation policy around Aug, 2020.",
);

wrap_internal_policy!(
    FirefoxPolicy,
    InternalFirefoxPolicy,
    "A model of Firefox's X.509 validation policy around Aug, 2020.",
);

wrap_internal_policy!(
    OpenSSLPolicy,
    InternalOpenSSLPolicy,
    "A model of OpenSSL's X.509 validation policy around Nov, 2024.",
);

impl Default for ChromePolicy {
    fn default() -> Self {
        ChromePolicy(InternalChromePolicy::default())
    }
}

impl Default for FirefoxPolicy {
    fn default() -> Self {
        FirefoxPolicy(InternalFirefoxPolicy::default())
    }
}

impl Default for OpenSSLPolicy {
    fn default() -> Self {
        OpenSSLPolicy(InternalOpenSSLPolicy::default())
    }
}

/// A formally verified X.509 certificate validation engine.
pub struct Validator<'a>(InternalValidator<'a, BoxDynInternalPolicy<'a>>);

impl<'a> Validator<'a> {
    /// Creates a new [`Validator`] with the given custom policy and root store.
    pub fn from_roots<P: Policy + 'a>(policy: P, roots: &'a RootStore) -> Result<Self> {
        let policy: BoxDynInternalPolicy<'a> = BoxDynInternalPolicy(Box::new(policy));
        let validator =
            InternalValidator::from_root_store(policy, &roots.0)?;
        Ok(Validator(validator))
    }

    /// Validates a certificate chain in PEM format,
    /// assuming that the first certificate is the leaf certificate.
    pub fn validate_pem<R: BufRead>(&self, pem: R, task: &Task) -> Result<bool> {
        let chain_base64 = read_pem_as_base64(pem)
            .map(|res| res)
            .collect::<std::result::Result<Vec<_>, PEMParseError>>()?;
        self.validate_base64(
            chain_base64.iter().map(|c| c.as_bytes()),
            task,
        )
    }

    /// Validates a certificate chain in ASN.1 DER format encoded in Base64,
    /// assuming that the first certificate is the leaf certificate.
    pub fn validate_base64(&self, chain_base64: impl Iterator<Item = impl AsRef<[u8]>>, task: &Task) -> Result<bool> {
        let chain_der = chain_base64
            .map(|c| decode_base64(c.as_ref()))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        self.validate_der(chain_der.iter().map(|c| c.as_slice()), task)
    }

    /// Validates a certificate chain in ASN.1 DER format,
    /// assuming that the first certificate is the leaf certificate.
    pub fn validate_der<'b>(&self, chain_der: impl Iterator<Item = &'b [u8]>, task: &Task) -> Result<bool> {
        let chain = chain_der
            .map(|c| parse_x509_der(c))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(self.0.validate(&VecDeep::from_vec(chain), &task.0)?)
    }

    /// Prints some debug information about a certificate chain.
    /// NOTE: this function is subject to change.
    pub fn print_debug_info(&self, chain_base64: &Vec<Vec<u8>>, task: &Task) -> Result<()> {
        self.0.print_debug_info(chain_base64, &task.0)?;
        Ok(())
    }

    /// Returns the number of root certificates.
    pub fn num_roots(&self) -> usize {
        self.0.roots.len()
    }
}
