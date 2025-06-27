use vstd::prelude::*;

use verdict_polyfill::slice_drop_first;
use libcrux::signature::{Signature, EcDsaP256Signature, Algorithm, DigestAlgorithm, verify};
use aws_lc_rs::signature::VerificationAlgorithm;

use verdict_parser::PolyfillEq;
use verdict_parser::Combinator;
use verdict_parser::asn1::ASN1;
use verdict_parser::x509::*;

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
    InvalidSignature,
    UnsupportedAlgorithm,
    VerificationFailed,
}

#[verifier::external_type_specification]
#[allow(dead_code)]
pub struct ExAlgorithm(Algorithm);

#[verifier::external_type_specification]
#[allow(dead_code)]
pub struct ExDigestAlgorithm(DigestAlgorithm);

#[verifier::external_body]
#[inline(always)]
fn p256_verify_internal(
    alg: Algorithm,
    pub_key: &[u8],
    r: &[u8],
    s: &[u8],
    msg: &[u8],
) -> bool
{
    if r.len() > 32 || s.len() > 32 {
        return false;
    }

    let mut r_copy = [0; 32];
    let mut s_copy = [0; 32];

    (&mut r_copy[32 - r.len()..]).copy_from_slice(r);
    (&mut s_copy[32 - s.len()..]).copy_from_slice(s);

    let sig = Signature::EcDsaP256(EcDsaP256Signature::from_raw(r_copy, s_copy, alg));

    verify(msg, &sig, pub_key).is_ok()
}

/// Verify ECDSA P-256 signature with SHA-256/SHA-384
/// through libcrux/EverCrypt
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
    let (len, parsed_sig) = ASN1(ECDSASigValue).parse(sig)
        .or(Err(ECDSAError::InvalidSignature))?;

    if len != sig.len() {
        return Err(ECDSAError::InvalidSignature);
    }

    let r = parsed_sig.r.bytes();
    let s = parsed_sig.s.bytes();

    // ASN.1 integer may have a leading zero byte
    // to avoid the leading bit to be set for positive integers
    // so we need to remove it
    let r = if r.len() != 0 && r[0] == 0 { slice_drop_first(r) } else { &r };
    let s = if s.len() != 0 && s[0] == 0 { slice_drop_first(s) } else { &s };

    // libcrux doesn't seem to have SHA224 support yet
    let internal_alg = if alg.id.polyfill_eq(&oid!(ECDSA_SIGNATURE_SHA256)) {
        Algorithm::EcDsaP256(DigestAlgorithm::Sha256)
    } else if alg.id.polyfill_eq(&oid!(ECDSA_SIGNATURE_SHA384)) {
        Algorithm::EcDsaP256(DigestAlgorithm::Sha384)
    } else if alg.id.polyfill_eq(&oid!(ECDSA_SIGNATURE_SHA512)) {
        Algorithm::EcDsaP256(DigestAlgorithm::Sha512)
    } else {
        return Err(ECDSAError::UnsupportedAlgorithm);
    };

    if p256_verify_internal(
        internal_alg,
        pub_key,
        r,
        s,
        msg,
    ) {
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
