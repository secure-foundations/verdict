use super::*;
use vstd::prelude::*;

verus! {

// In X.509:
// Validity ::= SEQUENCE {
//     notBefore      Time,
//     notAfter       Time,
// }
asn1! {
    seq Validity {
        not_before: Time = Time,
        not_after: Time = Time,
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
            let _ = ASN1(Validity).parse(&[]);
        }
    }

    #[test]
    fn sanity() {
        assert!(ASN1(Validity)
            .parse(&[
                0x30, 0x1E, 0x17, 0x0D, 0x31, 0x36, 0x30, 0x32, 0x30, 0x34, 0x31, 0x32, 0x33, 0x32,
                0x32, 0x33, 0x5A, 0x17, 0x0D, 0x33, 0x34, 0x31, 0x32, 0x33, 0x31, 0x31, 0x37, 0x32,
                0x36, 0x33, 0x39, 0x5A,
            ])
            .is_ok());
    }
}
