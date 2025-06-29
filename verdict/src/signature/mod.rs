#![allow(unsafe_code)]

#[cfg(not(feature = "verified-crypto"))]
pub mod ecdsa_aws_lc;
#[cfg(not(feature = "verified-crypto"))]
pub mod rsa_aws_lc;

#[cfg(not(feature = "verified-crypto"))]
pub use ecdsa_aws_lc as ecdsa;

#[cfg(not(feature = "verified-crypto"))]
pub use rsa_aws_lc as rsa;

#[cfg(feature = "verified-crypto")]
pub mod ecdsa_libcrux;
#[cfg(feature = "verified-crypto")]
pub mod rsa_libcrux;

#[cfg(feature = "verified-crypto")]
pub use ecdsa_libcrux as ecdsa;

#[cfg(feature = "verified-crypto")]
pub use rsa_libcrux as rsa;
