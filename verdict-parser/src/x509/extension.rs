use super::*;
use crate::asn1::Boolean;
use vstd::prelude::*;

verus! {

broadcast use super::oid::axiom_disjoint_oids;

/// Extension  ::=  SEQUENCE  {
///     extnID      OBJECT IDENTIFIER,
///     critical    BOOLEAN DEFAULT FALSE,
///     extnValue   OCTET STRING
/// }
pub type ExtensionInner = Mapped<
    LengthWrapped<
        Depend<
            ASN1<ObjectIdentifier>,
            <ExtensionCont as Continuation>::Output,
            ExtensionCont,
        >,
    >,
    ExtensionMapper>;

pub type ExtensionsInner = SequenceOf<ASN1<Extension>>;

wrap_combinator! {
    pub struct Extension: ExtensionInner =>
        spec SpecExtensionValue,
        exec<'a> ExtensionValue<'a>,
        owned ExtensionValueOwned,
    = Mapped {
            inner: LengthWrapped(Depend {
                fst: ASN1(ObjectIdentifier),
                snd: ExtensionCont,
                spec_snd: Ghost(|i| ExtensionCont::spec_apply(i)),
            }),
            mapper: ExtensionMapper,
        };
}

asn1_tagged!(Extension, tag_of!(SEQUENCE));

asn1! {
    seq of Extensions(ASN1(Extension)): ASN1<Extension>;
}

mapper! {
    pub struct ExtensionMapper;

    for <Id, Param>
    from ExtensionFrom where type ExtensionFrom<Id, Param> = (Id, PairValue<OptionDeep<bool>, Param>);
    to ExtensionPoly where pub struct ExtensionPoly<Id, Param> {
        pub id: Id,
        pub critical: OptionDeep<bool>,
        pub param: Param,
    }

    spec SpecExtensionValue with <SpecObjectIdentifierValue, SpecExtensionParamValue>;
    exec ExtensionValue<'a> with <ObjectIdentifierValue, ExtensionParamValue<'a>>;
    owned ExtensionValueOwned with <ObjectIdentifierValueOwned, ExtensionParamValueOwned>;

    forward(x) {
        ExtensionPoly {
            id: x.0,
            critical: x.1.0,
            param: x.1.1,
        }
    }

    backward(y) {
        (y.id, PairValue(y.critical, y.param))
    }
}

/// Parse an optional boolean field ("critical") (default to bool)
/// before the actual extension parameter
#[derive(Debug, View)]
pub struct ExtensionCont;

impl ExtensionCont {
    pub open spec fn spec_apply(i: SpecObjectIdentifierValue) -> <ExtensionCont as Continuation>::Output {
        Optional(spec_new_wrapped(ASN1(Boolean)), ExtensionParamCont::spec_apply(i))
    }
}

impl Continuation for ExtensionCont {
    type Input<'a> = ObjectIdentifierValue;
    type Output = Optional<Wrapped<ASN1<Boolean>>, <ExtensionParamCont as Continuation>::Output>;

    fn apply<'a>(&self, i: Self::Input<'a>) -> (o: Self::Output) {
        Optional(new_wrapped(ASN1(Boolean)), ExtensionParamCont.apply(i))
    }

    open spec fn requires<'a>(&self, i: Self::Input<'a>) -> bool {
        true
    }

    open spec fn ensures<'a>(&self, i: Self::Input<'a>, o: Self::Output) -> bool {
        o@ == Self::spec_apply(i@)
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
            let _ = ASN1(Extension).parse(&[]);
            let _ = ASN1(Extensions).parse(&[]);
        }
    }

    #[test]
    fn sanity() {
        assert!(ASN1(Extension)
            .parse(&[
                0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0xE4, 0xAF, 0x2B,
                0x26, 0x71, 0x1A, 0x2B, 0x48, 0x27, 0x85, 0x2F, 0x52, 0x66, 0x2C, 0xEF, 0xF0, 0x89,
                0x13, 0x71, 0x3E,
            ])
            .is_ok());

        assert!(ASN1(Extensions)
            .parse(&[
                0x30, 0x40, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04,
                0x03, 0x02, 0x01, 0x86, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF,
                0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E,
                0x04, 0x16, 0x04, 0x14, 0xE4, 0xAF, 0x2B, 0x26, 0x71, 0x1A, 0x2B, 0x48, 0x27, 0x85,
                0x2F, 0x52, 0x66, 0x2C, 0xEF, 0xF0, 0x89, 0x13, 0x71, 0x3E,
            ])
            .is_ok());
    }
}
