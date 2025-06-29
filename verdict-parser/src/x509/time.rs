use super::*;
use vstd::prelude::*;

verus! {

// In X.509:
// Time ::= CHOICE {
//     utcTime        UTCTime, // more common
//     generalTime    GeneralizedTime
// }
asn1! {
    choice Time {
        UTCTime(ASN1(UTCTime)): ASN1<UTCTime>,
        GeneralizedTime(ASN1(GeneralizedTime)): ASN1<GeneralizedTime>,
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
            let _ = Time.parse(&[]);
        }
    }

    #[test]
    fn sanity() {
        assert!(Time
            .parse(&[
                0x17, 0x0D, 0x31, 0x36, 0x30, 0x32, 0x30, 0x34, 0x31, 0x32, 0x33, 0x32, 0x32, 0x33,
                0x5A,
            ])
            .is_ok());
    }
}
