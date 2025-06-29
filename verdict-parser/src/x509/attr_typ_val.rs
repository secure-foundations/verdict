use super::*;
use vstd::prelude::*;

verus! {

// AttributeTypeAndValue in X.509:
// AttributeTypeAndValue ::= SEQUENCE {
//     type     AttributeType,
//     value    AttributeValue
// }
//
// AttributeType ::= OBJECT IDENTIFIER
// AttributeValue ::= ANY DEFINED BY AttributeType
//
// where "in general AttributeValue will be a DirectoryString" (4.1.2.4, RFC 2459)
asn1! {
    seq AttributeTypeAndValue {
        typ: ASN1<ObjectIdentifier> = ASN1(ObjectIdentifier),
        value: DirectoryString = DirectoryString,
    }
}

}

#[cfg(test)]
mod test {
    use super::*;

    verus! {
        /// Check that all trait bounds and preconditions are satisfied
        #[test]
        fn is_combinator() {
            let _ = ASN1(AttributeTypeAndValue).parse(&[]);
        }
    }

    #[test]
    fn sanity() {
        assert!(ASN1(AttributeTypeAndValue)
            .parse(&[
                0x30, 0x17, 0x06, 0x0A, 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19,
                0x16, 0x09, 0x72, 0x75, 0x62, 0x79, 0x2D, 0x6C, 0x61, 0x6E, 0x67,
            ])
            .is_ok());
    }
}
