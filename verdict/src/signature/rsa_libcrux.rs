// RSA PKCS#1 v1.5 signature verification

use vstd::prelude::*;

use verdict_polyfill::{slice_eq, slice_drop_first, slice_skip, usize_into_u32};

use verdict_parser::PolyfillEq;
use verdict_parser::Combinator;
use verdict_parser::asn1::ASN1;
use verdict_parser::x509::*;

use crate::hash;

verus! {

#[derive(Debug)]
pub enum RSAError {
    InvalidPublicKey,
    SizeOverflow,
    DecryptError,
    PKCS1PaddingError,
    AlgorithmMismatch,
    UnsupportedAlgorithm,
    HashMismatch,
}

pub struct RSAPublicKeyInternal {
    n_bits: u32,
    e_bits: u32,
    key: *mut u64,
}

pub uninterp spec fn spec_pkcs1_v1_5_load_pub_key(pub_key: Seq<u8>) -> Option<RSAPublicKeyInternal>;
pub uninterp spec fn spec_pkcs1_v1_5_verify(
    alg: SpecAlgorithmIdentifierValue,
    pub_key: RSAPublicKeyInternal,
    sig: Seq<u8>,
    msg: Seq<u8>,
) -> bool;

impl Drop for RSAPublicKeyInternal {
    #[verifier::external_body]
    fn drop(&mut self)
        opens_invariants none
        no_unwind
    {
        hacl_free_pkey(self.key)
    }
}

#[verifier::external_body]
#[inline(always)]
fn hacl_new_rsapss_load_pkey(
    mod_bits: u32,
    e_bits: u32,
    nb: &[u8],
    eb: &[u8],
) -> Option<RSAPublicKeyInternal>
{
    let key = unsafe {
        libcrux_hacl::Hacl_RSAPSS_new_rsapss_load_pkey(
            mod_bits,
            e_bits,
            nb.as_ptr() as _,
            eb.as_ptr() as _,
        )
    };

    if key.is_null() {
        None
    } else {
        Some(RSAPublicKeyInternal {
            n_bits: mod_bits,
            e_bits: e_bits,
            key,
        })
    }
}

#[verifier::external_body]
#[inline(always)]
fn hacl_free_pkey(pkey: *mut u64) {
    unsafe {
        libcrux_hacl::hacl_free(pkey as _);
    }
}

#[verifier::external_body]
#[inline(always)]
fn hacl_rsa_decrypt(
    mod_bits: u32,
    e_bits: u32,
    pkey: *mut u64,
    sig_len: u32,
    sig: &[u8],
) -> Option<Vec<u8>>
{
    // `sig_len` should be equal to `ceil(mod_bits / 2)`
    // (also checked in Hacl_RSAPSS_rsa_decrypt)
    let len = sig_len.try_into().ok()?;
    let mut decoded: Vec<u8> = vec![0; len];

    if unsafe {
        libcrux_hacl::Hacl_RSAPSS_rsa_decrypt(
            mod_bits,
            e_bits,
            pkey,
            sig_len,
            sig.as_ptr() as _,
            decoded.as_mut_ptr() as _,
        )
    } {
        Some(decoded)
    } else {
        None
    }
}

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
    if sig.len() > usize::MAX as usize {
        return Err(RSAError::SizeOverflow);
    }

    // Decrypt the signature using hacl*
    let decoded = match hacl_rsa_decrypt(
            pub_key.n_bits,
            pub_key.e_bits,
            pub_key.key,
            sig.len() as u32,
            sig,
        ) {
            Some(decoded) => decoded,
            None => {
                return Err(RSAError::DecryptError);
            }
        };

    // PKCS#1 v1.5 padding
    //     msg = 0x00 || 0x01 || PS || 0x00 || T
    // where T is a DigestInfo:
    // DigestInfo ::= SEQUENCE {
    //     digestAlgorithm AlgorithmIdentifier,
    //     digest OCTET STRING
    // }
    if decoded.len() < 2 || decoded[0] != 0x00 || decoded[1] != 0x01 {
        return Err(RSAError::PKCS1PaddingError);
    }

    let mut i = 2;
    while i < decoded.len() && decoded[i] == 0xff {
        i += 1;
    }

    if i >= decoded.len() || decoded[i] != 0x00 {
        return Err(RSAError::PKCS1PaddingError);
    }

    let dig_info = slice_skip(decoded.as_slice(), i + 1);

    let (len, digest_info_parsed) = ASN1(DigestInfo).parse(dig_info)
        .or(Err(RSAError::PKCS1PaddingError))?;

    if len != dig_info.len() {
        return Err(RSAError::PKCS1PaddingError);
    }

    // Check that the signature algorithms specified by the digest info
    // and the given `alg` are the same
    if digest_info_parsed.alg.id.polyfill_eq(&alg.id) {
        return Err(RSAError::AlgorithmMismatch);
    }

    // TODO: enforce parameter field to be NULL or empty?

    // TODO: more digest algorithms
    let res = if alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA224)) {
        slice_eq(&digest_info_parsed.digest, &hash::sha224_digest(msg))
    } else if alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA256)) {
        slice_eq(&digest_info_parsed.digest, &hash::sha256_digest(msg))
    } else if alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA384)) {
        slice_eq(&digest_info_parsed.digest, &hash::sha384_digest(msg))
    } else if alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA512)) {
        slice_eq(&digest_info_parsed.digest, &hash::sha512_digest(msg))
    } else {
        return Err(RSAError::UnsupportedAlgorithm);
    };

    if !res {
        return Err(RSAError::HashMismatch);
    }

    Ok(())
}

#[verifier::external_body]
pub fn pkcs1_v1_5_load_pub_key(pub_key: &[u8]) -> (res: Result<RSAPublicKeyInternal, RSAError>)
    ensures
        res matches Ok(key) ==> spec_pkcs1_v1_5_load_pub_key(pub_key@) == Some(key),
        res is Err ==> spec_pkcs1_v1_5_load_pub_key(pub_key@) is None,
{
    let (len, pub_key_parsed) = ASN1(RSAPublicKey).parse(pub_key)
        .or(Err(RSAError::InvalidPublicKey))?;

    if len != pub_key.len() {
        return Err(RSAError::InvalidPublicKey);
    }

    let n = pub_key_parsed.n.bytes();
    let e = pub_key_parsed.e.bytes();

    // ASN.1 integer may have a leading zero byte
    // to avoid the leading bit to be set for positive integers
    // so we need to remove it
    let n = if n.len() != 0 && n[0] == 0 { slice_drop_first(n) } else { &n };
    let e = if e.len() != 0 && e[0] == 0 { slice_drop_first(e) } else { &e };

    // Lengths in bits
    let n_len = n.len().checked_mul(8).ok_or(RSAError::SizeOverflow)?;
    let e_len = e.len().checked_mul(8).ok_or(RSAError::SizeOverflow)?;

    if n_len > u32::MAX as usize || e_len > u32::MAX as usize {
        return Err(RSAError::SizeOverflow);
    }

    // Load the public key into hacl*
    hacl_new_rsapss_load_pkey(
        usize_into_u32(n_len), usize_into_u32(e_len), n, e,
    ).ok_or(RSAError::InvalidPublicKey)
}

}

// No operation can modify the public key pointer except for Drop
unsafe impl Send for RSAPublicKeyInternal {}
unsafe impl Sync for RSAPublicKeyInternal {}
