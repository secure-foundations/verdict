#![forbid(unsafe_code)]

mod common;
pub mod asn1;
pub mod x509;

pub use common::*;

use vstd::prelude::*;

verus! {
    /// Top-level specification for x509 parsing from DER
    pub closed spec fn spec_parse_x509_der(der: Seq<u8>) -> Option<x509::SpecCertificateValue> {
        match x509::Certificate.spec_parse(der) {
            Ok((n, cert)) if n == der.len() => Some(cert),
            _ => None,
        }
    }

    /// Spec for Base64 decoding
    pub closed spec fn spec_decode_base64(base64: Seq<u8>) -> Option<Seq<u8>> {
        match Base64.spec_parse(base64) {
            Ok((n, bytes)) if n == base64.len() => Some(bytes),
            _ => None,
        }
    }

    /// Composition of `spec_parse_x509_der` and `spec_decode_base64`
    pub open spec fn spec_parse_x509_base64(base64: Seq<u8>) -> Option<x509::SpecCertificateValue> {
        match spec_decode_base64(base64) {
            Some(der) => spec_parse_x509_der(der),
            None => None,
        }
    }

    /// Parses the given bytes in ASN.1 DER format
    /// to a [`x509::CertificateValue`].
    ///
    /// This function has been formally verified for parsing soundness,
    /// completeness, and non-malleability.
    ///
    /// NOTE: This is an internal function that is subject to change.
    pub fn parse_x509_der<'a>(bytes: &'a [u8]) -> (res: Result<x509::CertificateValue<'a>, ParseError>)
        ensures
            res matches Ok(res) ==> {
                // Soundness
                &&& spec_parse_x509_der(bytes@) == Some(res@)

                // Non-malleability
                &&& forall |other: Seq<u8>| {
                    &&& other.len() <= usize::MAX
                    &&& #[trigger] spec_parse_x509_der(other) == Some(res@)
                } ==> other == bytes@

                // Prefix-security
                &&& forall |suffix: Seq<u8>| {
                    &&& suffix.len() != 0
                    &&& bytes@.len() + suffix.len() <= usize::MAX
                } ==> #[trigger] spec_parse_x509_der(bytes@ + suffix) is None
            },

            // Completeness
            res is Err ==> spec_parse_x509_der(bytes@) is None,
    {
        let (n, cert) = x509::Certificate.parse(bytes)?;
        if n != bytes.len() {
            return Err(ParseError::Other("trailing bytes in certificate".to_string()));
        }

        proof {
            let (n, spec_res) = x509::Certificate.spec_parse(bytes@).unwrap();

            assert forall |other: Seq<u8>| {
                &&& other.len() <= usize::MAX
                &&& #[trigger] spec_parse_x509_der(other) == Some(cert@)
            } implies other == bytes@ by {
                let (m, other_res) = x509::Certificate.spec_parse(other).unwrap();
                let other_ser = x509::Certificate.spec_serialize(other_res).unwrap();
                let spec_ser = x509::Certificate.spec_serialize(spec_res).unwrap();

                x509::Certificate.theorem_parse_serialize_roundtrip(other);
                x509::Certificate.theorem_parse_serialize_roundtrip(bytes@);

                assert(other_ser == other);
                assert(other == spec_ser);
                assert(spec_ser == bytes@);
            }

            assert forall |suffix: Seq<u8>|{
                &&& suffix.len() != 0
                &&& bytes@.len() + suffix.len() <= usize::MAX
            } implies #[trigger] spec_parse_x509_der(bytes@ + suffix) is None by {
                x509::Certificate.lemma_prefix_secure(bytes@, suffix);
            }
        }

        Ok(cert)
    }

    /// Decodes a Base64-encoded sequence of bytes.
    ///
    /// This function has been formally verified for its
    /// parsing soundness, completeness, and non-malleability.
    ///
    /// NOTE: This is an internal function that is subject to change.
    pub fn decode_base64(encoded: &[u8]) -> (res: Result<Vec<u8>, ParseError>)
        ensures
            res matches Ok(res) ==> {
                // Soundness
                &&& spec_decode_base64(encoded@) == Some(res@)

                // Non-malleability
                &&& forall |other: Seq<u8>| {
                    &&& other.len() <= usize::MAX
                    &&& #[trigger] spec_decode_base64(other) == Some(res@)
                } ==> other == encoded@
            },

            // Completeness
            res is Err ==> spec_decode_base64(encoded@) is None,
    {
        let (n, bytes) = Base64.parse(encoded)?;

        if n != encoded.len() {
            return Err(ParseError::Other("trailing bytes in base64".to_string()));
        }

        assert(encoded.len() <= usize::MAX);
        proof {
            let (n, spec_res) = Base64.spec_parse(encoded@).unwrap();

            assert forall |other: Seq<u8>| {
                &&& other.len() <= usize::MAX
                &&& #[trigger] spec_decode_base64(other) == Some(bytes@)
            } implies other == encoded@ by {
                let (_, other_res) = Base64.spec_parse(other).unwrap();
                let other_ser = Base64.spec_serialize(other_res).unwrap();
                let spec_ser = Base64.spec_serialize(spec_res).unwrap();

                Base64.theorem_parse_serialize_roundtrip(other);
                Base64.theorem_parse_serialize_roundtrip(encoded@);

                assert(other_ser == other);
                assert(other == spec_ser);
                assert(spec_ser == encoded@);
            }
        }

        Ok(bytes)
    }
}
