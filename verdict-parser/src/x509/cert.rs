use super::*;
use vstd::prelude::*;

verus! {

// Certificate  ::=  SEQUENCE  {
//     tbsCertificate       TBSCertificate,
//     signatureAlgorithm   AlgorithmIdentifier,
//     signatureValue       BIT STRING
// }
asn1! {
    seq CertificateInner {
        cert: Cached<ASN1<TBSCertificate>> = Cached(ASN1(TBSCertificate)),
        sig_alg: Cached<ASN1<AlgorithmIdentifier>> = Cached(ASN1(AlgorithmIdentifier)),
        sig: ASN1<BitString> = ASN1(BitString),
    }
}

wrap_combinator! {
    pub struct Certificate: Cached<ASN1<CertificateInner>> = Cached(ASN1(CertificateInner));
}

pub type SpecCertificateValue = SpecCertificateInnerValue;
pub type CertificateValue<'a> = CachedValue<'a, ASN1<CertificateInner>>;

}

#[cfg(test)]
mod test {
    #![allow(unused_variables)]

    use super::*;
    use base64::Engine;

    verus! {
        /// Check that all trait bounds and preconditions are satisfied
        #[test]
        fn is_combinator() {
            let _ = Certificate.parse(&[]);
        }

        /// Check if the serialization cache is correct
        #[test]
        fn cached() {
            if let Ok((_, res)) = Certificate.parse(&[]) {
                let ser = res.serialize();
                assert(ASN1(CertificateInner)@.spec_serialize(res@).is_ok());
                assert(ser@ == ASN1(CertificateInner)@.spec_serialize(res@).unwrap());

                let tbs: &CachedValue<ASN1<TBSCertificate>> = &res.get().cert;
                let tbs_ser = tbs.serialize();
                assert(ASN1(TBSCertificate)@.spec_serialize(tbs@).is_ok());
                assert(tbs_ser@ == ASN1(TBSCertificate)@.spec_serialize(tbs@).unwrap());
            }
        }
    }

    fn parse_cert(src: &str) -> Result<(), String> {
        let cert_base64 = src.split_whitespace().collect::<String>();
        let cert_bytes = base64::prelude::BASE64_STANDARD
            .decode(cert_base64)
            .map_err(|e| format!("Failed to decode Base64: {}", e))?;

        let (n, cert) = Certificate
            .parse(&cert_bytes)
            .map_err(|e| format!("Failed to parse certificate"))?;

        // Check that the caching is correct
        assert_eq!(n, cert_bytes.len());
        assert_eq!(&cert_bytes, cert.serialize());

        Ok(())
    }

    /// Test the final combinator on some root certificates
    #[test]
    fn roots_pem() {
        let roots = include_str!("../../tests/data/roots.pem");
        const PREFIX: &'static str = "-----BEGIN CERTIFICATE-----";
        const SUFFIX: &'static str = "-----END CERTIFICATE-----";

        // Parse all certificates provided
        roots
            .split(PREFIX)
            .skip(1)
            .enumerate()
            .for_each(|(i, cert_enc)| match cert_enc.split(SUFFIX).next() {
                Some(cert_enc) => {
                    eprintln!("Parsing certificate {}", i);
                    assert!(parse_cert(cert_enc).is_ok());
                }
                None => {}
            });
    }
}
