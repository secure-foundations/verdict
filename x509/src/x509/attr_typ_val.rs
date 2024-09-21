use vstd::prelude::*;

use crate::asn1::*;
use crate::common::*;

use super::dir_string::*;
use crate::common::SpecFrom;

verus! {

/// AttributeTypeAndValue in X.509:
/// AttributeTypeAndValue ::= SEQUENCE {
///     type     AttributeType,
///     value    AttributeValue
/// }
///
/// AttributeType ::= OBJECT IDENTIFIER
/// AttributeValue ::= ANY DEFINED BY AttributeType
///
/// where "in general AttributeValue will be a DirectoryString" (4.1.2.4, RFC 2459)
pub type AttributeTypeAndValueInner = Mapped<LengthWrapped<(ASN1<ObjectIdentifier>, DirectoryString)>, AttributeTypeAndValueMapper>;

wrap_combinator! {
    struct AttributeTypeAndValue: AttributeTypeAndValueInner =>
        spec SpecAttributeTypeAndValueValue,
        exec<'a> AttributeTypeAndValueValue<'a>,
        owned AttributeTypeAndValueValueOwned,
    = Mapped {
            inner: LengthWrapped((ASN1(ObjectIdentifier), DirectoryString)),
            mapper: AttributeTypeAndValueMapper,
        };
}

asn1_tagged!(AttributeTypeAndValue, TagValue {
    class: TagClass::Universal,
    form: TagForm::Constructed,
    num: 0x10,
});

#[derive(Debug, View, PolyfillClone)]
pub struct AttributeTypeAndValuePoly<Typ, Value> {
    pub typ: Typ,
    pub value: Value,
}

pub type SpecAttributeTypeAndValueValue = AttributeTypeAndValuePoly<SpecObjectIdentifierValue, SpecDirectoryStringValue>;
pub type AttributeTypeAndValueValue<'a> = AttributeTypeAndValuePoly<ObjectIdentifierValue, DirectoryStringValue<'a>>;
pub type AttributeTypeAndValueValueOwned = AttributeTypeAndValuePoly<ObjectIdentifierValueOwned, DirectoryStringValueOwned>;

type AttributeTypeAndValueFrom<Typ, Value> = (Typ, Value);

impl<Typ, Value> SpecFrom<AttributeTypeAndValuePoly<Typ, Value>> for AttributeTypeAndValueFrom<Typ, Value> {
    closed spec fn spec_from(s: AttributeTypeAndValuePoly<Typ, Value>) -> Self {
        (s.typ, s.value)
    }
}

impl<Typ, Value> SpecFrom<AttributeTypeAndValueFrom<Typ, Value>> for AttributeTypeAndValuePoly<Typ, Value> {
    closed spec fn spec_from(s: AttributeTypeAndValueFrom<Typ, Value>) -> Self {
        AttributeTypeAndValuePoly {
            typ: s.0,
            value: s.1,
        }
    }
}

impl<Typ: View, Value: View> From<AttributeTypeAndValuePoly<Typ, Value>> for AttributeTypeAndValueFrom<Typ, Value> {
    fn ex_from(s: AttributeTypeAndValuePoly<Typ, Value>) -> Self {
        (s.typ, s.value)
    }
}

impl<Typ: View, Value: View> From<AttributeTypeAndValueFrom<Typ, Value>> for AttributeTypeAndValuePoly<Typ, Value> {
    fn ex_from(s: AttributeTypeAndValueFrom<Typ, Value>) -> Self {
        AttributeTypeAndValuePoly {
            typ: s.0,
            value: s.1,
        }
    }
}

#[derive(Debug, View)]
pub struct AttributeTypeAndValueMapper;

impl SpecIso for AttributeTypeAndValueMapper
{
    type Src = AttributeTypeAndValueFrom<SpecObjectIdentifierValue, SpecDirectoryStringValue>;
    type Dst = AttributeTypeAndValuePoly<SpecObjectIdentifierValue, SpecDirectoryStringValue>;

    proof fn spec_iso(s: Self::Src) {
        // Somehow these trigger terms are needed after adding an irrelevant trait impl
        let _ = Self::Src::spec_from(Self::Dst::spec_from(s));
    }

    proof fn spec_iso_rev(s: Self::Dst) {
        let _ = Self::Dst::spec_from(Self::Src::spec_from(s));
    }
}

impl Iso for AttributeTypeAndValueMapper {
    type Src<'a> = AttributeTypeAndValueFrom<ObjectIdentifierValue, DirectoryStringValue<'a>>;
    type Dst<'a> = AttributeTypeAndValuePoly<ObjectIdentifierValue, DirectoryStringValue<'a>>;

    type SrcOwned = AttributeTypeAndValueFrom<ObjectIdentifierValueOwned, DirectoryStringValueOwned>;
    type DstOwned = AttributeTypeAndValuePoly<ObjectIdentifierValueOwned, DirectoryStringValueOwned>;
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
        assert!(ASN1(AttributeTypeAndValue).parse(&[
            0x30, 0x17, 0x06, 0x0A, 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19, 0x16, 0x09, 0x72, 0x75, 0x62, 0x79, 0x2D, 0x6C, 0x61, 0x6E, 0x67,
        ]).is_ok());
    }
}
