use super::*;
use crate::asn1::Boolean;
use crate::asn1::Integer;
use vstd::prelude::*;

verus! {

asn1! {
    // RFC 2459, 4.2.1.1
    seq AuthorityKeyIdentifier {
        #[optional] key_id: ASN1<ImplicitTag<OctetString>> = ASN1(ImplicitTag(tag_of!(IMPLICIT 0), OctetString)),
        // TODO: Parsing of GeneralNames is not implemented yet
        #[optional] auth_cert_issuer: placeholder_type!() = placeholder!(EXPLICIT 1),
        #[optional] auth_cert_serial: ASN1<ImplicitTag<BigInt>> = ASN1(ImplicitTag(tag_of!(IMPLICIT 2), BigInt)),
    }

    // BasicConstraints ::= SEQUENCE {
    //     cA                      BOOLEAN DEFAULT FALSE,
    //     pathLenConstraint       INTEGER (0..MAX) OPTIONAL
    // }
    seq BasicConstraints {
        #[default(false)] is_ca: ASN1<Boolean> = ASN1(Boolean),
        #[optional] path_len: ASN1<Integer> = ASN1(Integer),
    }

    // PolicyInformation ::= SEQUENCE {
    //     policyIdentifier   CertPolicyId,
    //     policyQualifiers   SEQUENCE SIZE (1..MAX) OF
    //                             PolicyQualifierInfo OPTIONAL }
    //
    // CertPolicyId ::= OBJECT IDENTIFIER
    //
    // PolicyQualifierInfo ::= SEQUENCE {
    //     policyQualifierId  PolicyQualifierId,
    //     qualifier          ANY DEFINED BY policyQualifierId }
    //
    // PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
    seq PolicyInfo {
        policy_id: ASN1<ObjectIdentifier> = ASN1(ObjectIdentifier),
        #[optional] qualifiers: placeholder_type!() = placeholder!(SEQUENCE),
    }

    // certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
    seq of CertificatePolicies(ASN1(PolicyInfo)): ASN1<PolicyInfo>;

    seq of ExtendedKeyUsage(ASN1(ObjectIdentifier)): ASN1<ObjectIdentifier>;

    // NameConstraints ::= SEQUENCE {
    //     permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
    //     excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }

    // GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree

    // GeneralSubtree ::= SEQUENCE {
    //     base                    GeneralName,
    //     minimum         [0]     BaseDistance DEFAULT 0,
    //     maximum         [1]     BaseDistance OPTIONAL }

    // BaseDistance ::= INTEGER (0..MAX)
    seq NameConstraints {
        // NOTE: implicit tag of a SEQ OF still has the constructed bit set?
        #[optional] permitted: ASN1<ImplicitTag<GeneralSubtrees>> = ASN1(ImplicitTag(tag_of!(EXPLICIT 0), GeneralSubtrees)),
        #[optional] excluded: ASN1<ImplicitTag<GeneralSubtrees>> = ASN1(ImplicitTag(tag_of!(EXPLICIT 1), GeneralSubtrees)),
    }

    seq of GeneralSubtrees(ASN1(GeneralSubtree)): ASN1<GeneralSubtree>;

    // AuthorityInfoAccessSyntax  ::=
    //         SEQUENCE SIZE (1..MAX) OF AccessDescription

    // AccessDescription  ::=  SEQUENCE {
    //         accessMethod          OBJECT IDENTIFIER,
    //         accessLocation        GeneralName  }
    seq GeneralSubtree {
        base: GeneralName = GeneralName,
        #[default(0i64)] min: ASN1<ImplicitTag<Integer>> = ASN1(ImplicitTag(tag_of!(IMPLICIT 0), Integer)),
        #[optional] max: ASN1<ImplicitTag<Integer>> = ASN1(ImplicitTag(tag_of!(IMPLICIT 1), Integer)),
    }

    seq of AuthorityInfoAccess(ASN1(AccessDescription)): ASN1<AccessDescription>;

    seq AccessDescription {
        method: ASN1<ObjectIdentifier> = ASN1(ObjectIdentifier),
        location: GeneralName = GeneralName,
    }
}

oid_match_continuation! {
    continuation ExtensionParam {
        oid(AUTH_KEY_IDENT) =>
            AuthorityKeyIdentifier(ASN1(ExplicitTag(tag_of!(OCTET_STRING), ASN1(AuthorityKeyIdentifier)))): ASN1<ExplicitTag<ASN1<AuthorityKeyIdentifier>>>,

        oid(SUBJECT_KEY_IDENT) =>
            SubjectKeyIdentifier(ASN1(ExplicitTag(tag_of!(OCTET_STRING), ASN1(OctetString)))): ASN1<ExplicitTag<ASN1<OctetString>>>,

        oid(BASIC_CONSTRAINTS) =>
            BasicConstraints(ASN1(ExplicitTag(tag_of!(OCTET_STRING), ASN1(BasicConstraints)))): ASN1<ExplicitTag<ASN1<BasicConstraints>>>,

        oid(CERT_POLICIES) =>
            CertificatePolicies(ASN1(ExplicitTag(tag_of!(OCTET_STRING), ASN1(CertificatePolicies)))): ASN1<ExplicitTag<ASN1<CertificatePolicies>>>,

        oid(EXTENDED_KEY_USAGE) =>
            ExtendedKeyUsage(ASN1(ExplicitTag(tag_of!(OCTET_STRING), ASN1(ExtendedKeyUsage)))): ASN1<ExplicitTag<ASN1<ExtendedKeyUsage>>>,

        oid(KEY_USAGE) =>
            KeyUsage(ASN1(ExplicitTag(tag_of!(OCTET_STRING), ASN1(BitString)))): ASN1<ExplicitTag<ASN1<BitString>>>,

        oid(SUBJECT_ALT_NAME) =>
            SubjectAltName(ASN1(ExplicitTag(tag_of!(OCTET_STRING), ASN1(GeneralNames)))): ASN1<ExplicitTag<ASN1<GeneralNames>>>,

        oid(NAME_CONSTRAINTS) =>
            NameConstraints(ASN1(ExplicitTag(tag_of!(OCTET_STRING), ASN1(NameConstraints)))): ASN1<ExplicitTag<ASN1<NameConstraints>>>,

        oid(AUTH_INFO_ACCESS) =>
            AuthorityInfoAccess(ASN1(ExplicitTag(tag_of!(OCTET_STRING), ASN1(AuthorityInfoAccess)))): ASN1<ExplicitTag<ASN1<AuthorityInfoAccess>>>,

        _ => Other(ASN1(OctetString)): ASN1<OctetString>,
    }
}

}
