use super::*;
use vstd::prelude::*;

verus! {

asn1! {
    // Dss-Parms  ::=  SEQUENCE  {
    //     p             INTEGER,
    //     q             INTEGER,
    //     g             INTEGER
    // }
    seq DSAParam {
        p: ASN1<BigInt> = ASN1(BigInt),
        q: ASN1<BigInt> = ASN1(BigInt),
        g: ASN1<BigInt> = ASN1(BigInt),
    }

    // NOTE: This is the format of the public key field of subject public key info
    // not the format of AlgorithmIdentifier.param
    //
    // RSAPublicKey ::= SEQUENCE {
    //     modulus            INTEGER, -- n
    //     publicExponent     INTEGER  -- e --
    // }
    seq RSAParam {
        modulus: ASN1<BigInt> = ASN1(BigInt),
        exponent: ASN1<BigInt> = ASN1(BigInt),
    }
}

// TODO: DSA, ECDSA, etc.
oid_match_continuation! {
    continuation AlgorithmParam {
        // Signature algorithms
        // NOTE: for some of these, technically the param field should
        // be NULL (or for some should be empty), but some certificates
        // do not comply with this
        // oid(RSA_SIGNATURE_MD2) => RSASignatureWithMD2(OrdChoice(ASN1(Null), End)): OrdChoice<ASN1<Null>, End>,
        // oid(RSA_SIGNATURE_MD5) => RSASignatureWithMD5(OrdChoice(ASN1(Null), End)): OrdChoice<ASN1<Null>, End>,
        // oid(RSA_SIGNATURE_SHA1) => RSASignatureWithSHA1(OrdChoice(ASN1(Null), End)): OrdChoice<ASN1<Null>, End>,

        oid(RSA_SIGNATURE_SHA256) => RSASignatureWithSHA256(OrdChoice(ASN1(Null), End)): OrdChoice<ASN1<Null>, End>,
        oid(RSA_SIGNATURE_SHA384) => RSASignatureWithSHA384(OrdChoice(ASN1(Null), End)): OrdChoice<ASN1<Null>, End>,
        oid(RSA_SIGNATURE_SHA512) => RSASignatureWithSHA512(OrdChoice(ASN1(Null), End)): OrdChoice<ASN1<Null>, End>,
        oid(RSA_SIGNATURE_SHA224) => RSASignatureWithSHA224(OrdChoice(ASN1(Null), End)): OrdChoice<ASN1<Null>, End>,

        oid(DSA_SIGNATURE) => DSASignature(OrdChoice(ASN1(DSAParam), End)): OrdChoice<ASN1<DSAParam>, End>,

        oid(ECDSA_SIGNATURE_SHA224) => ECDSASignatureWithSHA224(End): End,
        oid(ECDSA_SIGNATURE_SHA256) => ECDSASignatureWithSHA256(End): End,
        oid(ECDSA_SIGNATURE_SHA384) => ECDSASignatureWithSHA384(End): End,
        oid(ECDSA_SIGNATURE_SHA512) => ECDSASignatureWithSHA512(End): End,

        // Subject public key algorithms
        oid(RSA_ENCRYPTION) => RSAEncryption(OrdChoice(ASN1(Null), End)): OrdChoice<ASN1<Null>, End>,
        oid(EC_PUBLIC_KEY) => ECPublicKey(ASN1(ObjectIdentifier)): ASN1<ObjectIdentifier>, // Currently only support named curves

        _ => Other(Tail): Tail,
    }
}

impl<'a> PolyfillEq for DSAParamValue<'a> {
    fn polyfill_eq(&self, other: &Self) -> bool {
        self.p.polyfill_eq(&other.p) && self.q.polyfill_eq(&other.q) && self.g.polyfill_eq(&other.g)
    }
}

impl<'a> PolyfillEq for AlgorithmParamValue<'a> {
    fn polyfill_eq(&self, other: &Self) -> bool {
        match (self, other) {
            // (AlgorithmParamValue::RSASignatureWithMD2(a), AlgorithmParamValue::RSASignatureWithMD2(b)) => a.polyfill_eq(b),
            // (AlgorithmParamValue::RSASignatureWithMD5(a), AlgorithmParamValue::RSASignatureWithMD5(b)) => a.polyfill_eq(b),
            // (AlgorithmParamValue::RSASignatureWithSHA1(a), AlgorithmParamValue::RSASignatureWithSHA1(b)) => a.polyfill_eq(b),
            (AlgorithmParamValue::RSASignatureWithSHA256(a), AlgorithmParamValue::RSASignatureWithSHA256(b)) => a.polyfill_eq(b),
            (AlgorithmParamValue::RSASignatureWithSHA384(a), AlgorithmParamValue::RSASignatureWithSHA384(b)) => a.polyfill_eq(b),
            (AlgorithmParamValue::RSASignatureWithSHA512(a), AlgorithmParamValue::RSASignatureWithSHA512(b)) => a.polyfill_eq(b),
            (AlgorithmParamValue::RSASignatureWithSHA224(a), AlgorithmParamValue::RSASignatureWithSHA224(b)) => a.polyfill_eq(b),
            (AlgorithmParamValue::DSASignature(a), AlgorithmParamValue::DSASignature(b)) => a.polyfill_eq(b),
            (AlgorithmParamValue::ECDSASignatureWithSHA224(a), AlgorithmParamValue::ECDSASignatureWithSHA224(b)) => a.polyfill_eq(b),
            (AlgorithmParamValue::ECDSASignatureWithSHA256(a), AlgorithmParamValue::ECDSASignatureWithSHA256(b)) => a.polyfill_eq(b),
            (AlgorithmParamValue::ECDSASignatureWithSHA384(a), AlgorithmParamValue::ECDSASignatureWithSHA384(b)) => a.polyfill_eq(b),
            (AlgorithmParamValue::ECDSASignatureWithSHA512(a), AlgorithmParamValue::ECDSASignatureWithSHA512(b)) => a.polyfill_eq(b),
            (AlgorithmParamValue::RSAEncryption(a), AlgorithmParamValue::RSAEncryption(b)) => a.polyfill_eq(b),
            (AlgorithmParamValue::ECPublicKey(a), AlgorithmParamValue::ECPublicKey(b)) => a.polyfill_eq(b),
            (AlgorithmParamValue::Other(a), AlgorithmParamValue::Other(b)) => a.polyfill_eq(b),
            (AlgorithmParamValue::Unreachable, AlgorithmParamValue::Unreachable) => true,
            _ => false,
        }
    }
}

}
