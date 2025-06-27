// RSA PKCS#1 v1.5 signature verification

use vstd::prelude::*;

use verdict_parser::PolyfillEq;
use verdict_parser::x509::*;

use aws_lc_rs::signature::VerificationAlgorithm;

verus! {

#[derive(Debug)]
pub enum RSAError {
    SignatureError,
    UnsupportedAlgorithm,
}

pub struct RSAPublicKeyInternal(Vec<u8>);

pub uninterp spec fn spec_pkcs1_v1_5_load_pub_key(pub_key: Seq<u8>) -> Option<RSAPublicKeyInternal>;
pub uninterp spec fn spec_pkcs1_v1_5_verify(
    alg: SpecAlgorithmIdentifierValue,
    pub_key: RSAPublicKeyInternal,
    sig: Seq<u8>,
    msg: Seq<u8>,
) -> bool;

/// Verify RSA PKCS#1 v1.5 signature
///
/// `alg` specifies the signature + digest combination to be used
/// we check that the signature algorithm should be RSA, and hash
/// the message according to the digest algorithm.
///
/// `pub_key` is an ASN.1 encoded public key:
/// ```text
///     RSAPublicKey ::= SEQUENCE {
///         modulus            INTEGER, -- n
///         publicExponent     INTEGER  -- e --
///     }
/// ```
/// (decoded via `pkcs1_v1_5_load_pub_key`)
///
/// `sig` is the signature encoded in big-endian (expected to be the same length as the modulus)
/// `msg` is the message expected to be signed
#[verifier::external_body]
pub fn pkcs1_v1_5_verify(
    alg: &AlgorithmIdentifierValue<'_>,
    pub_key: &RSAPublicKeyInternal,
    sig: &[u8],
    msg: &[u8],
) -> (res: Result<(), RSAError>)
    ensures
        res.is_ok() == spec_pkcs1_v1_5_verify(alg@, *pub_key, sig@, msg@),
{
    let scheme = if alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA256)) {
        &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256
    } else if alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA384)) {
        &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA384
    } else if alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA512)) {
        &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA512
    } else {
        return Err(RSAError::UnsupportedAlgorithm);
    };

    if scheme.verify_sig(&pub_key.0, msg, sig).is_ok() {
        Ok(())
    } else {
        Err(RSAError::SignatureError)
    }
}

#[verifier::external_body]
pub fn pkcs1_v1_5_load_pub_key(pub_key: &[u8]) -> (res: Result<RSAPublicKeyInternal, RSAError>)
    ensures
        res matches Ok(key) ==> spec_pkcs1_v1_5_load_pub_key(pub_key@) == Some(key),
        res is Err ==> spec_pkcs1_v1_5_load_pub_key(pub_key@) is None,
{
    Ok(RSAPublicKeyInternal(pub_key.to_vec()))
}

}
