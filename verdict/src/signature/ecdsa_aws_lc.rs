use aws_lc_rs::signature::VerificationAlgorithm;
use vstd::prelude::*;

use verdict_parser::x509::*;
use verdict_parser::PolyfillEq;

verus! {

pub uninterp spec fn spec_p256_verify(
    alg: SpecAlgorithmIdentifierValue,
    pub_key: Seq<u8>,
    sig: Seq<u8>,
    msg: Seq<u8>,
) -> bool;

pub uninterp spec fn spec_p384_verify(
    alg: SpecAlgorithmIdentifierValue,
    pub_key: Seq<u8>,
    sig: Seq<u8>,
    msg: Seq<u8>,
) -> bool;

pub enum ECDSAError {
    UnsupportedAlgorithm,
    VerificationFailed,
}

/// Verify ECDSA P-256 signature with SHA-256/SHA-384 through AWS-LC
#[verifier::external_body]
pub fn p256_verify(
    alg: &AlgorithmIdentifierValue<'_>,
    pub_key: &[u8],
    sig: &[u8],
    msg: &[u8],
) -> (res: Result<(), ECDSAError>)
    ensures
        res.is_ok() == spec_p256_verify(alg@, pub_key@, sig@, msg@),
{
    let scheme = if alg.id.polyfill_eq(&oid!(ECDSA_SIGNATURE_SHA256)) {
        &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1
    } else if alg.id.polyfill_eq(&oid!(ECDSA_SIGNATURE_SHA384)) {
        &aws_lc_rs::signature::ECDSA_P256_SHA384_ASN1
    } else {
        return Err(ECDSAError::UnsupportedAlgorithm);
    };

    if scheme.verify_sig(pub_key, msg, sig).is_ok() {
        Ok(())
    } else {
        Err(ECDSAError::VerificationFailed)
    }
}

/// Verify ECDSA P-384 signature with SHA-384
/// (currently other SHA-2 hash functions are not supported
/// since only P-384 + SHA-384 is verified in AWS-LC)
#[verifier::external_body]
pub fn p384_verify(
    alg: &AlgorithmIdentifierValue<'_>,
    pub_key: &[u8],
    sig: &[u8],
    msg: &[u8],
) -> (res: Result<(), ECDSAError>)
    ensures
        res.is_ok() == spec_p384_verify(alg@, pub_key@, sig@, msg@),
{
    let scheme = if alg.id.polyfill_eq(&oid!(ECDSA_SIGNATURE_SHA256)) {
        &aws_lc_rs::signature::ECDSA_P384_SHA256_ASN1
    } else if alg.id.polyfill_eq(&oid!(ECDSA_SIGNATURE_SHA384)) {
        &aws_lc_rs::signature::ECDSA_P384_SHA384_ASN1
    } else {
        return Err(ECDSAError::UnsupportedAlgorithm);
    };

    if scheme.verify_sig(pub_key, msg, sig).is_ok() {
        Ok(())
    } else {
        Err(ECDSAError::VerificationFailed)
    }
}

}
