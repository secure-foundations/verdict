// Specifications for the most basic issuing relation
// i.e. only compares names and checks signature

use vstd::prelude::*;

use verdict_polyfill::*;
use verdict_parser::{*, asn1::*, x509::*};

use crate::signature::*;

verus! {

/// NOTE: RFC 5280, 7.1 requires using RFC 4518's normalization procedure
/// But right now we only support a subset of these normalization rules
///
/// 1. Fold cases by Rust's char::to_lowercase
/// 2. Remove leading/trailing spaces
/// 3. Compress multiple inner spaces into one
///
/// Note that we only consider the ASCII space ' ' instead of all white spaces
pub open spec fn spec_normalize_string(s: Seq<char>) -> Seq<char> {
    spec_normalize_string_helper(s, false, false)
}

/// Helper function for spec_normalize_string
/// `seen_nw` = have seen a non-whitespace since the start of the string
/// `seen_ws` = have seen a whitespace since the last non-whitespace character
pub open spec fn spec_normalize_string_helper(s: Seq<char>, seen_nw: bool, seen_ws: bool) -> Seq<char>
    decreases s.len()
{
    if s.len() == 0 {
        seq![] // Ignores spaces seen so far
    } else if s[0] == ' ' {
        spec_normalize_string_helper(s.drop_first(), seen_nw, true)
    } else {
        let prefix = if seen_nw && seen_ws {
            seq![' '] + spec_char_lower(s[0])
        } else {
            spec_char_lower(s[0])
        };

        prefix + spec_normalize_string_helper(s.drop_first(), true, false)
    }
}

/// Verify the subject cert's signature using issuer's public key
///
/// Currently we support these signature schemes:
/// - RSA PKCS#1 v1.5 with SHA-224, SHA-256, SHA-384, SHA-512 (Evercrypt through libcrux)
/// - P-256 with SHA-256, SHA-384, SHA-512 (Evercrypt through libcrux)
/// - P-384 with SHA-256, SHA-384 (AWS-LC)
///
/// NOTE: P-384 + SHA-256 is not yet verified in AWS-LC
/// Also P-384 + SHA-384 is only verified for Intel CPUs (SandyBridge+)
/// See https://github.com/awslabs/aws-lc-verification
///
/// NOTE: Comparison of subject.sig_alg == subject.cert.signature is done in the policy
pub open spec fn spec_verify_signature(issuer: SpecCertificateValue, subject: SpecCertificateValue) -> bool
{
    &&& ASN1(TBSCertificate)@.spec_serialize(subject.cert) matches Ok(tbs_cert)
    &&& {
        // RSA
        ||| {
            &&& issuer.cert.subject_key.alg.param is RSAEncryption
            &&& {
                ||| subject.sig_alg.id == spec_oid!(RSA_SIGNATURE_SHA224)
                ||| subject.sig_alg.id == spec_oid!(RSA_SIGNATURE_SHA256)
                ||| subject.sig_alg.id == spec_oid!(RSA_SIGNATURE_SHA384)
                ||| subject.sig_alg.id == spec_oid!(RSA_SIGNATURE_SHA512)
            }
            &&& rsa::spec_pkcs1_v1_5_load_pub_key(BitStringValue::spec_bytes(issuer.cert.subject_key.pub_key)) matches Some(pub_key)
            &&& rsa::spec_pkcs1_v1_5_verify(
                subject.sig_alg,
                pub_key,
                BitStringValue::spec_bytes(subject.sig),
                tbs_cert,
            )
        }

        // ECDSA P-256
        ||| {
            &&& issuer.cert.subject_key.alg.param matches SpecAlgorithmParamValue::ECPublicKey(curve)
            &&& curve == spec_oid!(EC_P_256)
            &&& {
                ||| subject.sig_alg.id == spec_oid!(ECDSA_SIGNATURE_SHA256)
                ||| subject.sig_alg.id == spec_oid!(ECDSA_SIGNATURE_SHA384)
                ||| subject.sig_alg.id == spec_oid!(ECDSA_SIGNATURE_SHA512)
            }
            &&& ecdsa::spec_p256_verify(
                subject.sig_alg,
                BitStringValue::spec_bytes(issuer.cert.subject_key.pub_key),
                BitStringValue::spec_bytes(subject.sig),
                tbs_cert,
            )
        }

        // ECDSA P-384
        ||| {
            &&& issuer.cert.subject_key.alg.param matches SpecAlgorithmParamValue::ECPublicKey(curve)
            &&& curve == spec_oid!(EC_P_384)
            &&& {
                ||| subject.sig_alg.id == spec_oid!(ECDSA_SIGNATURE_SHA256)
                ||| subject.sig_alg.id == spec_oid!(ECDSA_SIGNATURE_SHA384)
            }
            &&& ecdsa::spec_p384_verify(
                subject.sig_alg,
                BitStringValue::spec_bytes(issuer.cert.subject_key.pub_key),
                BitStringValue::spec_bytes(subject.sig),
                tbs_cert,
            )
        }
    }
}

/// Exec version of spec_normalize_string
pub fn normalize_string(s: &str) -> (res: String)
    ensures res@ =~= spec_normalize_string(s@)
{
    let mut seen_nw = false;
    let mut seen_ws = false;

    let mut res = string_new_with_cap(str_byte_len(s));
    let mut iter = str_chars(s);

    #[allow(unused_variables)]
    let mut i: usize = 0;

    assert(s@.skip(0) == s@);

    // Using a custom chars iterator wrapper in polyfill
    loop
        invariant
            spec_chars_iter_str(iter) == s@,
            s@.len() <= usize::MAX,

            i == spec_chars_iter_index(iter),
            spec_normalize_string(s@) =~= res@ + spec_normalize_string_helper(s@.skip(i as int), seen_nw, seen_ws),
        ensures i == s@.len()
        decreases s@.len() - i
    {
        if let Some(c) = chars_iter_next(&mut iter) {
            if c == ' ' {
                seen_ws = true;
            } else {
                if seen_nw && seen_ws {
                    res.append(" ");
                }
                res.append(char_lower(c).as_str());

                seen_nw = true;
                seen_ws = false;
            }

            proof { reveal_strlit(" "); }
            assert(s@.skip(i as int).drop_first() == s@.skip(i + 1));

            i += 1;
        } else {
            break;
        }
    }

    res
}

/// NOTE: For lower case folding, we trust Rust's built-in definition
pub uninterp spec fn spec_char_lower(c: char) -> Seq<char>;

#[verifier::external_body]
#[inline(always)]
fn char_lower(c: char) -> (res: String)
    ensures res@ == spec_char_lower(c)
{
    c.to_lowercase().to_string()
}

pub fn verify_signature(issuer: &CertificateValue<'_>, subject: &CertificateValue<'_>) -> (res: bool)
    ensures res == spec_verify_signature(issuer@, subject@)
{
    let tbs_cert = subject.get().cert.serialize();

    let sig_alg = &subject.get().sig_alg.get();
    let pub_key = issuer.get().cert.get().subject_key.pub_key.bytes();
    let sig = subject.get().sig.bytes();

    match &issuer.get().cert.get().subject_key.alg.param {
        // RSA PKCS#1 v1.5
        AlgorithmParamValue::RSAEncryption(..) => {
            if sig_alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA224)) ||
               sig_alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA256)) ||
               sig_alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA384)) ||
               sig_alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA512)) {
                return match rsa::pkcs1_v1_5_load_pub_key(pub_key) {
                    Ok(pub_key) => rsa::pkcs1_v1_5_verify(sig_alg, &pub_key, sig, tbs_cert).is_ok(),
                    Err(..) => false,
                }
            }
        }

        // ECDSA P-256 and P-384
        AlgorithmParamValue::ECPublicKey(curve) => {
            if curve.polyfill_eq(&oid!(EC_P_256)) && (
                sig_alg.id.polyfill_eq(&oid!(ECDSA_SIGNATURE_SHA256)) ||
                sig_alg.id.polyfill_eq(&oid!(ECDSA_SIGNATURE_SHA384)) ||
                sig_alg.id.polyfill_eq(&oid!(ECDSA_SIGNATURE_SHA512))
            ) {
                return ecdsa::p256_verify(sig_alg, pub_key, sig, tbs_cert).is_ok();
            }

            if curve.polyfill_eq(&oid!(EC_P_384)) && (
                sig_alg.id.polyfill_eq(&oid!(ECDSA_SIGNATURE_SHA256)) ||
                sig_alg.id.polyfill_eq(&oid!(ECDSA_SIGNATURE_SHA384))
            ) {
                return ecdsa::p384_verify(sig_alg, pub_key, sig, tbs_cert).is_ok();
            }
        }

        _ => {}
    }

    false
}

}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn sanity() {
        assert_eq!(normalize_string(""), "");
        assert_eq!(normalize_string("  "), "");
        assert_eq!(normalize_string("  a  "), "a");
        assert_eq!(normalize_string("   aa b   C  "), "aa b c");
        assert_eq!(normalize_string("  a  b  c  "), "a b c");
    }
}
