use vstd::prelude::*;

use crate::asn1::*;
use crate::common::*;

use super::rdn::*;
use super::macros::*;

verus! {

/// In X.509: Name ::= SEQUENCE OF RelativeDistinguishedName
pub type NameInner = SequenceOf<ASN1<RDN>>;

wrap_combinator! {
    pub struct Name: NameInner =>
        spec SpecNameValue,
        exec<'a> NameValue<'a>,
        owned NameValueOwned,
    = SequenceOf(ASN1(RDN));
}

asn1_tagged!(Name, TagValue {
    class: TagClass::Universal,
    form: TagForm::Constructed,
    num: 0x10,
});

pub type SpecNameValue = Seq<SpecRDNValue>;
pub type NameValue<'a> = VecDeep<RDNValue<'a>>;
pub type NameValueOwned = VecDeep<RDNValueOwned>;

}

#[cfg(test)]
mod test {
    use super::*;

    verus! {
        /// Check that all trait bounds and preconditions are satisfied
        #[test]
        fn is_combinator() {
            let _ = ASN1(Name).parse(&[]);
        }
    }

    #[test]
    fn sanity() {
        assert!(ASN1(Name).parse(&[
            0x30, 0x81, 0xA4, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x50, 0x41, 0x31, 0x0F, 0x30, 0x0D, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x06, 0x50, 0x61, 0x6E, 0x61, 0x6D, 0x61, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x0B, 0x50, 0x61, 0x6E, 0x61, 0x6D, 0x61, 0x20, 0x43, 0x69, 0x74, 0x79, 0x31, 0x24, 0x30, 0x22, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x1B, 0x54, 0x72, 0x75, 0x73, 0x74, 0x43, 0x6F, 0x72, 0x20, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6D, 0x73, 0x20, 0x53, 0x2E, 0x20, 0x64, 0x65, 0x20, 0x52, 0x2E, 0x4C, 0x2E, 0x31, 0x27, 0x30, 0x25, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x1E, 0x54, 0x72, 0x75, 0x73, 0x74, 0x43, 0x6F, 0x72, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6F, 0x72, 0x69, 0x74, 0x79, 0x31, 0x1F, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x16, 0x54, 0x72, 0x75, 0x73, 0x74, 0x43, 0x6F, 0x72, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x43, 0x65, 0x72, 0x74, 0x20, 0x43, 0x41, 0x2D, 0x32,
        ]).is_ok());
    }
}
