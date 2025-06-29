use super::*;
use vstd::prelude::*;

verus! {

// In X.509: RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
// TODO: support SET OF instead of using a sequence
asn1! {
    set of RDN(ASN1(AttributeTypeAndValue)): ASN1<AttributeTypeAndValue>;
}

}

#[cfg(test)]
mod test {
    use super::*;

    verus! {
        /// Check that all trait bounds and preconditions are satisfied
        #[test]
        fn is_combinator() {
            let _ = ASN1(RDN).parse(&[]);
        }
    }

    #[test]
    fn sanity() {
        assert!(ASN1(RDN)
            .parse(&[0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x50, 0x41,])
            .is_ok());
    }
}
