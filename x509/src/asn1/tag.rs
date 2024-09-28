use vstd::prelude::*;
use vstd::slice::slice_subrange;

use crate::common::*;

verus! {

/// Combinator for ASN.1 tags
#[derive(Debug, View)]
pub struct ASN1Tag;

#[derive(Debug)]
pub struct TagValue {
    pub class: TagClass,
    pub form: TagForm,

    /// Currently we only support tag numbers up to 31
    /// Larger tag numbers require the long form of tags
    pub num: u8,
}

impl View for TagValue {
    type V = TagValue;

    open spec fn view(&self) -> Self::V {
        *self
    }
}

#[derive(Debug)]
pub enum TagClass {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

#[derive(Debug)]
pub enum TagForm {
    Primitive,
    Constructed,
}

impl TagValue {
    pub fn eq(self, other: TagValue) -> (res: bool)
        ensures res == (self == other)
    {
        // TODO: fix this once Verus supports equality for enum
        (match (self.class, other.class) {
            (TagClass::Universal, TagClass::Universal) => true,
            (TagClass::Application, TagClass::Application) => true,
            (TagClass::ContextSpecific, TagClass::ContextSpecific) => true,
            (TagClass::Private, TagClass::Private) => true,
            _ => false,
        }) && (match (self.form, other.form) {
            (TagForm::Primitive, TagForm::Primitive) => true,
            (TagForm::Constructed, TagForm::Constructed) => true,
            _ => false,
        }) && self.num == other.num
    }

    /// TODO: fix after Verus supports Clone
    pub fn clone(&self) -> (res: TagValue)
        ensures res == *self
    {
        TagValue {
            class: match self.class {
                TagClass::Universal => TagClass::Universal,
                TagClass::Application => TagClass::Application,
                TagClass::ContextSpecific => TagClass::ContextSpecific,
                TagClass::Private => TagClass::Private,
            },
            form: match self.form {
                TagForm::Primitive => TagForm::Primitive,
                TagForm::Constructed => TagForm::Constructed,
            },
            num: self.num,
        }
    }
}

impl SpecCombinator for ASN1Tag {
    type SpecResult = TagValue;

    open spec fn spec_parse(&self, s: Seq<u8>) -> Result<(usize, Self::SpecResult), ()> {
        if s.len() == 0 {
            Err(())
        } else {
            let class_num = s[0] >> 6 & 0b11;
            let class = if class_num == 0 {
                TagClass::Universal
            } else if class_num == 1 {
                TagClass::Application
            } else if class_num == 2 {
                TagClass::ContextSpecific
            } else {
                TagClass::Private
            };

            let form_num = s[0] >> 5 & 1;
            let form = if form_num == 0 {
                TagForm::Primitive
            } else {
                TagForm::Constructed
            };

            Ok((1, TagValue {
                class,
                form,
                num: s[0] & 0b11111,
            }))
        }
    }

    proof fn spec_parse_wf(&self, s: Seq<u8>) {}

    open spec fn spec_serialize(&self, v: Self::SpecResult) -> Result<Seq<u8>, ()> {
        let class: u8 = match v.class {
            TagClass::Universal => 0,
            TagClass::Application => 1,
            TagClass::ContextSpecific => 2,
            _ => 3,
        };

        let form: u8 = match v.form {
            TagForm::Primitive => 0,
            _ => 1,
        };

        if v.num > 0b11111 {
            Err(())
        } else {
            Ok(seq![(class << 6) | (form << 5) | (v.num & 0b11111)])
        }
    }
}

impl SecureSpecCombinator for ASN1Tag {
    open spec fn is_prefix_secure() -> bool {
        true
    }

    proof fn theorem_serialize_parse_roundtrip(&self, v: Self::SpecResult) {
        let class_num: u8 = match v.class {
            TagClass::Universal => 0,
            TagClass::Application => 1,
            TagClass::ContextSpecific => 2,
            _ => 3,
        };

        let form_num: u8 = match v.form {
            TagForm::Primitive => 0,
            _ => 1,
        };

        let num = v.num;

        // Restate parse(serialize(v)) = v, but purely in BV
        assert(
            0 <= class_num < 4 &&
            0 <= form_num < 2 &&
            0 <= num <= 0b11111 ==> {
            let ser = (class_num << 6) | (form_num << 5) | (num & 0b11111);
            &&& ser >> 6 & 0b11 == class_num
            &&& ser >> 5 & 1 == form_num
            &&& ser & 0b11111 == num
        }) by (bit_vector);
    }

    proof fn theorem_parse_serialize_roundtrip(&self, buf: Seq<u8>) {
        let tag = buf[0];

        // Restate serialize(parse(v)) = v, but purely in BV
        assert(
            (tag >> 6 & 0b11) << 6 | (tag >> 5 & 1) << 5 | ((tag & 0b11111) & 0b11111) == tag
        ) by (bit_vector);

        // Some bound facts
        assert(tag >> 6 & 0b11 < 4) by (bit_vector);
        assert(tag >> 5 & 1 < 2) by (bit_vector);
        assert(tag & 0b11111 <= 0b11111) by (bit_vector);

        if let Ok((n, v)) = self.spec_parse(buf) {
            let ser = self.spec_serialize(v).unwrap();
            assert(ser =~= buf.subrange(0, 1));
        }
    }

    proof fn lemma_prefix_secure(&self, s1: Seq<u8>, s2: Seq<u8>) {}
}

impl Combinator for ASN1Tag {
    type Result<'a> = TagValue;
    type Owned = TagValue;

    open spec fn spec_length(&self) -> Option<usize> {
        Some(1)
    }

    fn length(&self) -> Option<usize> {
        Some(1)
    }

    fn parse<'a>(&self, s: &'a [u8]) -> (res: Result<(usize, Self::Result<'a>), ParseError>) {
        if s.len() == 0 {
            return Err(ParseError::UnexpectedEndOfInput);
        } else {
            let class_num = s[0] >> 6 & 0b11;
            let class = if class_num == 0 {
                TagClass::Universal
            } else if class_num == 1 {
                TagClass::Application
            } else if class_num == 2 {
                TagClass::ContextSpecific
            } else {
                TagClass::Private
            };

            let form_num = s[0] >> 5 & 1;
            let form = if form_num == 0 {
                TagForm::Primitive
            } else {
                TagForm::Constructed
            };

            Ok((1, TagValue {
                class,
                form,
                num: s[0] & 0b11111,
            }))
        }
    }

    fn serialize(&self, v: Self::Result<'_>, data: &mut Vec<u8>, pos: usize) -> (res: Result<usize, SerializeError>) {
        let class: u8 = match v.class {
            TagClass::Universal => 0,
            TagClass::Application => 1,
            TagClass::ContextSpecific => 2,
            _ => 3,
        };

        let form: u8 = match v.form {
            TagForm::Primitive => 0,
            _ => 1,
        };

        if v.num > 0b11111 {
            return Err(SerializeError::Other("Invalid tag number".to_string()));
        }

        if pos < data.len() {
            let tag = (class << 6) | (form << 5) | (v.num & 0b11111);
            data.set(pos, tag);
            assert(data@ == seq_splice(old(data)@, pos, seq![tag]));
            Ok(1)
        } else {
            Err(SerializeError::InsufficientBuffer)
        }
    }
}

/// A trait for combinators to mark their original tags
/// (e.g. 0x02 for INTEGER)
///
/// Can be overwritten by explicit or implicit tagging
pub trait ASN1Tagged
{
    spec fn spec_tag(&self) -> TagValue;
    fn tag(&self) -> (res: TagValue)
        ensures res == self.spec_tag();
}

/// An additional property that if an ASN1Tagged
/// implements View, then the viewed version preserves the tag
pub trait ViewWithASN1Tagged: View + ASN1Tagged where
    Self::V: ASN1Tagged,
{
    proof fn lemma_view_preserves_tag(&self)
        ensures self@.spec_tag() == self.spec_tag();
}

/// A combinator wrapper that also emits a tag before
/// parsing/serializing the inner value
#[derive(Debug)]
pub struct ASN1<T>(pub T);

impl<T: View> View for ASN1<T> {
    type V = ASN1<T::V>;

    open spec fn view(&self) -> Self::V {
        ASN1(self.0.view())
    }
}

impl<T: ASN1Tagged> ASN1Tagged for ASN1<T> {
    open spec fn spec_tag(&self) -> TagValue {
        self.0.spec_tag()
    }

    fn tag(&self) -> TagValue {
        self.0.tag()
    }
}

impl<T: ASN1Tagged + ViewWithASN1Tagged> ViewWithASN1Tagged for ASN1<T> where
    T::V: ASN1Tagged,
{
    proof fn lemma_view_preserves_tag(&self) {
        self.0.lemma_view_preserves_tag();
    }
}

impl<T: ASN1Tagged + SpecCombinator> SpecCombinator for ASN1<T> {
    type SpecResult = <T as SpecCombinator>::SpecResult;

    open spec fn spec_parse(&self, s: Seq<u8>) -> Result<(usize, Self::SpecResult), ()> {
        match (ASN1Tag, self.0).spec_parse(s) {
            Ok((n, (tag, v))) =>
                if tag == self.0.spec_tag() {
                    Ok((n, v))
                } else {
                    Err(())
                }
            Err(()) => Err(()),
        }
    }

    proof fn spec_parse_wf(&self, s: Seq<u8>) {
        (ASN1Tag, self.0).spec_parse_wf(s);
    }

    open spec fn spec_serialize(&self, v: Self::SpecResult) -> Result<Seq<u8>, ()> {
        (ASN1Tag, self.0).spec_serialize((self.0.spec_tag(), v))
    }
}

impl<T: ASN1Tagged + SecureSpecCombinator> SecureSpecCombinator for ASN1<T> {
    open spec fn is_prefix_secure() -> bool {
        T::is_prefix_secure()
    }

    proof fn theorem_serialize_parse_roundtrip(&self, v: Self::SpecResult) {
        (ASN1Tag, self.0).theorem_serialize_parse_roundtrip((self.0.spec_tag(), v));
    }

    proof fn theorem_parse_serialize_roundtrip(&self, buf: Seq<u8>) {
        (ASN1Tag, self.0).theorem_parse_serialize_roundtrip(buf);
    }

    proof fn lemma_prefix_secure(&self, s1: Seq<u8>, s2: Seq<u8>) {
        (ASN1Tag, self.0).lemma_prefix_secure(s1, s2);
    }
}

impl<T: ASN1Tagged + Combinator> Combinator for ASN1<T> where
    // T: SecureSpecCombinator<SpecResult = <<T as Combinator>::Owned as View>::V>,
    <T as View>::V: SecureSpecCombinator<SpecResult = <<T as Combinator>::Owned as View>::V>,
    <T as View>::V: ASN1Tagged,
    T: ViewWithASN1Tagged,
{
    type Result<'a> = T::Result<'a>;
    type Owned = T::Owned;

    open spec fn spec_length(&self) -> Option<usize> {
        match self.0.spec_length() {
            Some(len) => len.checked_add(1),
            None => None,
        }
    }

    fn length(&self) -> Option<usize> {
        match self.0.length() {
            Some(len) => len.checked_add(1),
            None => None,
        }
    }

    open spec fn parse_requires(&self) -> bool {
        self.0.parse_requires()
    }

    fn parse<'a>(&self, s: &'a [u8]) -> (res: Result<(usize, Self::Result<'a>), ParseError>) {
        proof {
            self.0.lemma_view_preserves_tag();
        }

        let (n1, tag) = ASN1Tag.parse(s)?;
        let (n2, v) = self.0.parse(slice_subrange(s, n1, s.len()))?;

        if tag.eq(self.0.tag()) && n1 <= usize::MAX - n2 {
            Ok((n1 + n2, v))
        } else {
            Err(ParseError::Other("Unmatching tags".to_string()))
        }
    }

    open spec fn serialize_requires(&self) -> bool {
        self.0.serialize_requires()
    }

    fn serialize(&self, v: Self::Result<'_>, data: &mut Vec<u8>, pos: usize) -> (res: Result<usize, SerializeError>) {
        proof {
            self.0.lemma_view_preserves_tag();
        }

        let n1 = ASN1Tag.serialize(self.0.tag(), data, pos)?;
        if n1 > usize::MAX - pos || n1 + pos > data.len() {
            return Err(SerializeError::InsufficientBuffer);
        }

        let n2 = self.0.serialize(v, data, pos + n1)?;

        if n1 <= usize::MAX - n2 {
            assert(data@ =~= seq_splice(old(data)@, pos, self@.spec_serialize(v@).unwrap()));
            Ok(n1 + n2)
        } else {
            Err(SerializeError::SizeOverflow)
        }
    }
}

/// Macro to generate a ASN1Tagged and ViewWithASN1Tagged trait impl
#[allow(unused_macros)]
macro_rules! asn1_tagged {
    ($ty:ident, $tag:expr) => {
        ::builtin_macros::verus! {
            impl ASN1Tagged for $ty {
                open spec fn spec_tag(&self) -> TagValue {
                    $tag
                }

                fn tag(&self) -> TagValue {
                    $tag
                }
            }

            impl ViewWithASN1Tagged for $ty {
                proof fn lemma_view_preserves_tag(&self) {}
            }
        }
    };
}
pub(crate) use asn1_tagged;

}
