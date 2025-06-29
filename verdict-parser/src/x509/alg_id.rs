use super::*;
use vstd::prelude::*;

verus! {

broadcast use super::oid::axiom_disjoint_oids;

// In X.509:
// AlgorithmIdentifier  ::=  SEQUENCE  {
//     algorithm               OBJECT IDENTIFIER,
//     parameters              ANY DEFINED BY algorithm OPTIONAL
// }
pub type AlgorithmIdentifierInner = Mapped<
    LengthWrapped<
        Depend<
            ASN1<ObjectIdentifier>,
            <AlgorithmParamCont as Continuation>::Output,
            AlgorithmParamCont,
        >,
    >,
    AlgorithmIdentifierMapper>;

wrap_combinator! {
    pub struct AlgorithmIdentifier: AlgorithmIdentifierInner =>
        spec SpecAlgorithmIdentifierValue,
        exec<'a> AlgorithmIdentifierValue<'a>,
        owned AlgorithmIdentifierValueOwned,
    = Mapped {
            inner: LengthWrapped(Depend {
                fst: ASN1(ObjectIdentifier),
                snd: AlgorithmParamCont,
                spec_snd: Ghost(|i| AlgorithmParamCont::spec_apply(i)),
            }),
            mapper: AlgorithmIdentifierMapper,
        };
}

asn1_tagged!(AlgorithmIdentifier, tag_of!(SEQUENCE));

mapper! {
    pub struct AlgorithmIdentifierMapper;

    for <Id, Param>
    from AlgorithmIdentifierFrom where type AlgorithmIdentifierFrom<Id, Param> = (Id, Param);
    to AlgorithmIdentifierPoly where pub struct AlgorithmIdentifierPoly<Id, Param> {
        pub id: Id,
        pub param: Param,
    }

    spec SpecAlgorithmIdentifierValue with <SpecObjectIdentifierValue, SpecAlgorithmParamValue>;
    exec AlgorithmIdentifierValue<'a> with <ObjectIdentifierValue, AlgorithmParamValue<'a>>;
    owned AlgorithmIdentifierValueOwned with <ObjectIdentifierValueOwned, AlgorithmParamValueOwned>;

    forward(x) {
        AlgorithmIdentifierPoly {
            id: x.0,
            param: x.1,
        }
    }

    backward(y) {
        (y.id, y.param)
    }
}

impl<'a> PolyfillEq for AlgorithmIdentifierValue<'a> {
    fn polyfill_eq(&self, other: &Self) -> bool {
        self.id.polyfill_eq(&other.id) &&
        self.param.polyfill_eq(&other.param)
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
            let _ = ASN1(AlgorithmIdentifier).parse(&[]);
        }
    }

    #[test]
    fn sanity() {
        assert!(ASN1(AlgorithmIdentifier)
            .parse(&[
                0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C, 0x05,
                0x00,
            ])
            .is_ok());
    }
}
