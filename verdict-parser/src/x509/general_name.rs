use super::*;
use vstd::prelude::*;

verus! {

// GeneralName ::= CHOICE {
//     otherName                       [0]     OtherName,
//     rfc822Name                      [1]     IA5String,
//     dNSName                         [2]     IA5String,
//     x400Address                     [3]     ORAddress,
//     directoryName                   [4]     Name,
//     ediPartyName                    [5]     EDIPartyName,
//     uniformResourceIdentifier       [6]     IA5String,
//     iPAddress                       [7]     OCTET STRING,
//     registeredID                    [8]     OBJECT IDENTIFIER}
//
// OtherName ::= SEQUENCE {
//     type-id    OBJECT IDENTIFIER,
//     value      [0] EXPLICIT ANY DEFINED BY type-id }
//
// EDIPartyName ::= SEQUENCE {
//     nameAssigner            [0]     DirectoryString OPTIONAL,
//     partyName               [1]     DirectoryString }
asn1! {
    choice GeneralName {
        Other(placeholder!(EXPLICIT 0)): placeholder_type!(),
        RFC822(ASN1(ImplicitTag(tag_of!(IMPLICIT 1), IA5String))): ASN1<ImplicitTag<IA5String>>,
        DNS(ASN1(ImplicitTag(tag_of!(IMPLICIT 2), IA5String))): ASN1<ImplicitTag<IA5String>>,
        X400(placeholder!(IMPLICIT 3)): placeholder_type!(),
        Directory(ASN1(ExplicitTag(tag_of!(EXPLICIT 4), ASN1(Name)))): ASN1<ExplicitTag<ASN1<Name>>>,
        EDIParty(placeholder!(IMPLICIT 5)): placeholder_type!(),
        URI(ASN1(ImplicitTag(tag_of!(IMPLICIT 6), IA5String))): ASN1<ImplicitTag<IA5String>>,
        IP(ASN1(ImplicitTag(tag_of!(IMPLICIT 7), OctetString))): ASN1<ImplicitTag<OctetString>>,
        RegisteredID(ASN1(ImplicitTag(tag_of!(IMPLICIT 8), ObjectIdentifier))): ASN1<ImplicitTag<ObjectIdentifier>>,
    }

    seq of GeneralNames(GeneralName): GeneralName;
}

}

#[cfg(test)]
mod test {
    use super::*;

    verus! {
        /// Check that all trait bounds and preconditions are satisfied
        #[test]
        fn is_combinator() {
            let _ = GeneralName.parse(&[]);
        }
    }

    #[test]
    fn rfc822() {
        assert_eq!(
            GeneralName
                .parse(&[
                    0x82, 0x0C, 0x2A, 0x2E, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x2E, 0x63, 0x6F,
                    0x6D,
                ])
                .unwrap()
                .1,
            GeneralNameValue::DNS("*.google.com")
        );
    }

    #[test]
    fn directory_name() {
        assert!(GeneralName
            .parse(&[
                0xA4, 0x81, 0x91, 0x30, 0x81, 0x8E, 0x31, 0x47, 0x30, 0x45, 0x06, 0x03, 0x55, 0x04,
                0x0A, 0x0C, 0x3E, 0x49, 0x5A, 0x45, 0x4E, 0x50, 0x45, 0x20, 0x53, 0x2E, 0x41, 0x2E,
                0x20, 0x2D, 0x20, 0x43, 0x49, 0x46, 0x20, 0x41, 0x30, 0x31, 0x33, 0x33, 0x37, 0x32,
                0x36, 0x30, 0x2D, 0x52, 0x4D, 0x65, 0x72, 0x63, 0x2E, 0x56, 0x69, 0x74, 0x6F, 0x72,
                0x69, 0x61, 0x2D, 0x47, 0x61, 0x73, 0x74, 0x65, 0x69, 0x7A, 0x20, 0x54, 0x31, 0x30,
                0x35, 0x35, 0x20, 0x46, 0x36, 0x32, 0x20, 0x53, 0x38, 0x31, 0x43, 0x30, 0x41, 0x06,
                0x03, 0x55, 0x04, 0x09, 0x0C, 0x3A, 0x41, 0x76, 0x64, 0x61, 0x20, 0x64, 0x65, 0x6C,
                0x20, 0x4D, 0x65, 0x64, 0x69, 0x74, 0x65, 0x72, 0x72, 0x61, 0x6E, 0x65, 0x6F, 0x20,
                0x45, 0x74, 0x6F, 0x72, 0x62, 0x69, 0x64, 0x65, 0x61, 0x20, 0x31, 0x34, 0x20, 0x2D,
                0x20, 0x30, 0x31, 0x30, 0x31, 0x30, 0x20, 0x56, 0x69, 0x74, 0x6F, 0x72, 0x69, 0x61,
                0x2D, 0x47, 0x61, 0x73, 0x74, 0x65, 0x69, 0x7A,
            ])
            .is_ok());
    }
}
