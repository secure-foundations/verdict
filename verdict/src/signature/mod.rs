#![allow(unsafe_code)]

#[cfg(feature = "aws-lc")]
pub mod ecdsa_aws_lc;
#[cfg(feature = "aws-lc")]
pub mod rsa_aws_lc;

#[cfg(feature = "aws-lc")]
pub use ecdsa_aws_lc as ecdsa;

#[cfg(feature = "aws-lc")]
pub use rsa_aws_lc as rsa;

#[cfg(not(feature = "aws-lc"))]
pub mod ecdsa_libcrux;
#[cfg(not(feature = "aws-lc"))]
pub mod rsa_libcrux;

#[cfg(not(feature = "aws-lc"))]
pub use ecdsa_libcrux as ecdsa;

#[cfg(not(feature = "aws-lc"))]
pub use rsa_libcrux as rsa;
