use crate::policy::ExecPolicyError;
pub use verdict_parser::ParseError;
use vstd::prelude::*;

verus! {

/// Errors when validating a certificate chain
#[derive(Debug)]
pub enum ValidationError {
    IntegerOverflow,
    EmptyChain,
    ProofFailure,
    TimeParseError,
    RSAPubKeyParseError,
    UnexpectedExtParam,
    PolicyError(ExecPolicyError),
    ParseError(ParseError),
}

impl From<ParseError> for ValidationError {
    fn from(err: ParseError) -> Self {
        ValidationError::ParseError(err)
    }
}

}
