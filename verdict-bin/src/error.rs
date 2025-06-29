use thiserror::Error;

use std::sync::mpsc::{RecvError, SendError};

use verdict::{ParseError, ValidationError};

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("csv error: {0}")]
    CSVError(#[from] csv::Error),

    #[error("found BEGIN CERTIFICATE without matching END CERTIFICATE")]
    NoMatchingEndCertificate,

    #[error("found END CERTIFICATE without matching BEGIN CERTIFICATE")]
    NoMatchingBeginCertificate,

    #[error("validation error: {0:?}")]
    ChainValidationError(#[from] ValidationError),

    #[error("regex error: {0}")]
    RegexError(#[from] regex::Error),

    #[error("channel send error: {0}")]
    SendError(String),

    #[error("channel receive error: {0}")]
    RecvError(String),

    #[error("repeat number must be positive")]
    ZeroRepeat,

    #[error("different validation time given at spawn and in task")]
    Inconsistentimestamps,

    #[error("libfaketime.so not found at {0}")]
    LibFakeTimeNotFound(String),

    #[error("chrome not found at {0}")]
    ChromeRepoNotFound(String),

    #[error("firefox not found at {0}")]
    FirefoxRepoNotFound(String),

    #[error("openssl cert bench not found at {0}")]
    OpenSSLRepoNotFound(String),

    #[error("armor driver not found at {0}")]
    ArmorRepoNotFound(String),

    #[error("hammurabi bench program not found at {0}")]
    HammurabiRepoNotFound(String),

    #[error("ceres driver not found at {0}")]
    CeresRepoNotFound(String),

    #[error("failed to get child process stdin")]
    ChildStdin,

    #[error("failed to get child process stdout")]
    ChildStdout,

    #[error("empty certificate bundle")]
    EmptyBundle,

    #[error("cert bench error: {0}")]
    CommonBenchError(String),

    #[error("duration overflow")]
    DurationOverflow,

    #[error("verdict bench error: {0}")]
    VerdictBenchError(String),

    #[error("failed to decode UTF-8: {0}")]
    UTF8Error(#[from] std::str::Utf8Error),

    #[error("failed to decode UTF-8: {0}")]
    StringUTF8Error(#[from] std::string::FromUtf8Error),

    #[error("JSON parsing error: {0}")]
    JSONError(#[from] serde_json::Error),

    #[error("Limbo test error: {0}")]
    LimboError(String),

    #[error("root certificates not found at {0}")]
    RootsNotFound(String),

    #[error("parse error: {0:?}")]
    ParseError(ParseError),
}

impl From<ParseError> for Error {
    fn from(err: ParseError) -> Self {
        Error::ParseError(err)
    }
}

impl<T> From<SendError<T>> for Error {
    fn from(err: SendError<T>) -> Self {
        Error::SendError(err.to_string())
    }
}

impl<T> From<crossbeam::channel::SendError<T>> for Error {
    fn from(err: crossbeam::channel::SendError<T>) -> Self {
        Error::SendError(err.to_string())
    }
}

impl From<RecvError> for Error {
    fn from(err: RecvError) -> Self {
        Error::RecvError(err.to_string())
    }
}

impl From<crossbeam::channel::RecvError> for Error {
    fn from(err: crossbeam::channel::RecvError) -> Self {
        Error::RecvError(err.to_string())
    }
}
