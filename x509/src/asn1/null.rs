use vstd::prelude::*;

use polyfill::*;

use crate::common::*;

use super::tag::*;

verus! {

/// Combainator for NULL in ASN.1
/// NULL = 05 00 (with tag)
#[derive(Debug, View)]
pub struct Null;

#[derive(Debug, View, PolyfillClone)]
pub struct NullValue;

asn1_tagged!(Null, tag_of!(NULL));

impl SpecCombinator for Null {
    type SpecResult = NullValue;

    open spec fn spec_parse(&self, s: Seq<u8>) -> Result<(usize, Self::SpecResult), ()> {
        if s.len() >= 1 && s[0] == 0x00 {
            Ok((1, NullValue))
        } else {
            Err(())
        }
    }

    proof fn spec_parse_wf(&self, s: Seq<u8>) {}

    open spec fn spec_serialize(&self, v: Self::SpecResult) -> Result<Seq<u8>, ()> {
        Ok(seq![ 0x00 ])
    }
}

impl SecureSpecCombinator for Null {
    open spec fn is_prefix_secure() -> bool {
        true
    }

    proof fn theorem_serialize_parse_roundtrip(&self, v: Self::SpecResult) {}

    proof fn theorem_parse_serialize_roundtrip(&self, buf: Seq<u8>) {
        if let Ok((n, v)) = self.spec_parse(buf) {
            assert(self.spec_serialize(v).unwrap() =~= buf.subrange(0, 1));
        }
    }

    proof fn lemma_prefix_secure(&self, s1: Seq<u8>, s2: Seq<u8>) {}
}

impl Combinator for Null {
    type Result<'a> = NullValue;
    type Owned = NullValue;

    open spec fn spec_length(&self) -> Option<usize> {
        Some(1)
    }

    fn length(&self) -> Option<usize> {
        Some(1)
    }

    fn parse<'a>(&self, s: &'a [u8]) -> (res: Result<(usize, Self::Result<'a>), ParseError>) {
        if s.len() >= 1 && s[0] == 0x00 {
            Ok((1, NullValue))
        } else {
            Err(ParseError::Other("Invalid null value".to_string()))
        }
    }

    fn serialize(&self, v: Self::Result<'_>, data: &mut Vec<u8>, pos: usize) -> (res: Result<usize, SerializeError>) {
        if pos > usize::MAX - 1 || pos + 1 > data.len() {
            return Err(SerializeError::InsufficientBuffer);
        }
        data.set(pos, 0x00);
        assert(data@ =~= seq_splice(old(data)@, pos, self@.spec_serialize(v@).unwrap()));
        Ok(1)
    }
}

}
