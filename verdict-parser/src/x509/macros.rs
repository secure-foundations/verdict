use vstd::prelude::*;

verus! {

/// Generate a combinator for an ASN.1 SEQUENCE (with default or optional fields)
///
/// For example
/// ```rust
/// asn1_sequence! {
///     sequence Test {
///         typ: ASN1<ObjectIdentifier> = ASN1(ObjectIdentifier),
///         value: DirectoryString = DirectoryString,
///     }
/// }
/// ```
///
/// NOTE: all sub-combinators have to be prefix secure (for Pair to work)
/// NOTE: we have the restriction that an OrdChoice combinator cannot
/// be following an optional or default field.
#[allow(unused_macros)]
#[macro_export]
macro_rules! asn1_sequence {
    // This assumes the view of $field_combinator is also $field_combinator
    (
        seq $name:ident {
            $(
                $(#[$modifier:ident $(($modifier_arg:expr))?])? $field_name:ident : $field_combinator_type:ty = $field_combinator:expr
            ),*

            $(,)?
        }
    ) => {
        crate::x509::macros::asn1_sequence! {
            seq $name {
                $($(#[$modifier $(($modifier_arg))?])? $field_name : $field_combinator_type = $field_combinator, spec $field_combinator),*
            }
        }
    };

    (
        seq $name:ident {
            $(
                $(#[$modifier:ident $(($modifier_arg:expr))?])? $field_name:ident : $field_combinator_type:ty = $field_combinator:expr, spec $spec_field_combinator:expr
            ),*

            $(,)?
        }
    ) => {
        ::paste::paste! {
            ::builtin_macros::verus! {
                // Only export the combinator, and the spec/normal/owned result types
                pub use [< internal_ $name >]::$name;
                pub use [< internal_ $name >]::SpecValue as [< Spec $name Value >];
                pub use [< internal_ $name >]::Value as [< $name Value >];
                pub use [< internal_ $name >]::ValueOwned as [< $name ValueOwned >];

                mod [< internal_ $name >] {
                    // Since snake-case field names are directly used as type parameters
                    #![allow(non_camel_case_types)]
                    #![allow(non_snake_case)]

                    use super::*;
                    use crate::x509::macros::*;
                    use crate::asn1::*;
                    use crate::common::*;

                    // Wrap the final combinator in a unit struct called $name
                    wrap_combinator! {
                        pub struct $name: Mapped<LengthWrapped<
                                gen_inner_combinator_type!($(($($modifier $(($modifier_arg))?)?, $field_combinator_type));*)
                            >, Mapper> =>
                            spec SpecValue,
                            exec<'a> Value<'a>,
                            owned ValueOwned,
                        = Mapped {
                                inner: LengthWrapped(gen_inner_combinator!($(($($modifier $(($modifier_arg))?)?, $field_combinator));*)),
                                mapper: Mapper,
                            };
                    }

                    asn1_tagged!($name, tag_of!(SEQUENCE));

                    // Add an indirection here since we can't put it inside the struct definition
                    $(
                        pub type [<FieldType_ $field_name>]<$field_name> = gen_field_poly_type!(($($modifier $(($modifier_arg))?)?, $field_name));
                    )*

                    // Mapper from the inner nested pair type to a struct
                    mapper! {
                        pub struct Mapper;

                        for <$($field_name),*>
                        from FromType where
                            type FromType<$($field_name),*> = gen_inner_combinator_poly_result_type!($(($($modifier $(($modifier_arg))?)?, $field_name));*);
                        to PolyType where
                            #[derive(Eq, PartialEq)]
                            pub struct PolyType<$($field_name),*> {
                                $(pub $field_name: [<FieldType_ $field_name>]<$field_name>,)*
                            }

                        spec SpecValue with <$(<<$field_combinator_type as View>::V as SpecCombinator>::SpecResult),*>;
                        exec Value<'a> with <$(<$field_combinator_type as Combinator>::Result<'a>),*>;
                        owned ValueOwned with <$(<$field_combinator_type as Combinator>::Owned),*>;

                        forward(x) {
                            gen_forward_body!(x; $(($($modifier $(($modifier_arg))?)?, $field_name)),*);
                            PolyType { $($field_name),* }
                        } by {
                            assert(get_end_field!(x; $(($($modifier $(($modifier_arg))?)?, $field_name)),*) == EndValue);
                        }

                        backward(y) {
                            gen_backward_body!(y; $(($($modifier $(($modifier_arg))?)?, $field_name)),*)
                        }
                    }
                }
            }
        }
    };
}
pub use asn1_sequence;

/// gen_inner_combinator_type!((optional, type1); (, type2); (default(v), type3))
#[allow(unused_macros)]
#[macro_export]
macro_rules! gen_inner_combinator_type {
    () => { End };

    ((, $first:ty) $(; ($($modifier:ident $(($modifier_arg:expr))?)?, $rest:ty))*) => {
        Pair<$first, gen_inner_combinator_type!($(($($modifier $(($modifier_arg))?)?, $rest));*)>
    };

    ((optional, $first:ty) $(; ($($modifier:ident $(($modifier_arg:expr))?)?, $rest:ty))*) => {
        Optional<$first, gen_inner_combinator_type!($(($($modifier $(($modifier_arg))?)?, $rest));*)>
    };

    ((default($_:expr), $first:ty) $(; ($($modifier:ident $(($modifier_arg:expr))?)?, $rest:ty))*) => {
        Default<<$first as Combinator>::Owned, $first, gen_inner_combinator_type!($(($($modifier $(($modifier_arg))?)?, $rest));*)>
    };

    ((tail, $first:ty)) => {
        $first
    };
}
pub use gen_inner_combinator_type;

#[allow(unused_macros)]
#[macro_export]
macro_rules! gen_inner_combinator {
    () => { End };

    ((, $first:expr) $(; ($($modifier:ident $(($modifier_arg:expr))?)?, $rest:expr))*) => {
        Pair($first, gen_inner_combinator!($(($($modifier $(($modifier_arg))?)?, $rest));*))
    };

    ((optional, $first:expr) $(; ($($modifier:ident $(($modifier_arg:expr))?)?, $rest:expr))*) => {
        Optional($first, gen_inner_combinator!($(($($modifier $(($modifier_arg))?)?, $rest));*))
    };

    ((default($default:expr), $first:expr) $(; ($($modifier:ident $(($modifier_arg:expr))?)?, $rest:expr))*) => {
        Default($default, $first, gen_inner_combinator!($(($($modifier $(($modifier_arg))?)?, $rest));*))
    };

    ((tail, $first:expr)) => {
        $first
    };
}
pub use gen_inner_combinator;

#[allow(unused_macros)]
#[macro_export]
macro_rules! gen_inner_combinator_poly_result_type {
    () => { EndValue };

    ((, $first:ident) $(; ($($modifier:ident $(($modifier_arg:expr))?)?, $rest:ident))*) => {
        PairValue<$first, gen_inner_combinator_poly_result_type!($(($($modifier $(($modifier_arg))?)?, $rest));*)>
    };

    ((optional, $first:ident) $(; ($($modifier:ident $(($modifier_arg:expr))?)?, $rest:ident))*) => {
        PairValue<OptionDeep<$first>, gen_inner_combinator_poly_result_type!($(($($modifier $(($modifier_arg))?)?, $rest));*)>
    };

    ((default($_:expr), $first:ident) $(; ($($modifier:ident $(($modifier_arg:expr))?)?, $rest:ident))*) => {
        PairValue<$first, gen_inner_combinator_poly_result_type!($(($($modifier $(($modifier_arg))?)?, $rest));*)>
    };

    ((tail, $first:ident)) => {
        $first
    };
}
pub use gen_inner_combinator_poly_result_type;

#[allow(unused_macros)]
#[macro_export]
macro_rules! gen_forward_body {
    ($prev_sel:expr ;) => {};

    // Special case: if the last field is marked with tail, we use it directly without doing Pair(last combinator, End)
    ($prev_sel:expr ; (tail, $first:ident)) => {
        let $first = $prev_sel;
    };

    ($prev_sel:expr ; ($($modifier:ident $(($modifier_arg:expr))?)?, $first:ident) $(, ($($rest_modifier:ident $(($rest_modifier_arg:expr))?)?, $rest:ident))*) => {
        let $first = $prev_sel.0;
        gen_forward_body!($prev_sel.1 ; $(($($rest_modifier $(($rest_modifier_arg))?)?, $rest)),*)
    };
}
pub use gen_forward_body;

#[allow(unused_macros)]
#[macro_export]
macro_rules! get_end_field {
    ($prev_sel:expr ;) => {
        $prev_sel
    };

    // Special case: if the last field is marked with tail, we use it directly without doing Pair(last combinator, End)
    // No proof required for the forward direction
    ($prev_sel:expr ; (tail, $first:ident)) => {
        EndValue
    };

    ($prev_sel:expr ; ($($modifier:ident $(($modifier_arg:expr))?)?, $first:ident) $(, ($($rest_modifier:ident $(($rest_modifier_arg:expr))?)?, $rest:ident))*) => {
        get_end_field!($prev_sel.1 ; $(($($rest_modifier $(($rest_modifier_arg))?)?, $rest)),*)
    };
}
pub use get_end_field;

#[allow(unused_macros)]
#[macro_export]
macro_rules! gen_backward_body {
    ($src:expr ;) => {
        EndValue
    };

    ($src:expr ; (tail, $first:ident)) => {
        $src.$first
    };

    ($src:expr ; ($($modifier:ident $(($modifier_arg:expr))?)?, $first:ident) $(, ($($rest_modifier:ident $(($rest_modifier_arg:expr))?)?, $rest:ident))*) => {
        PairValue($src.$first, gen_backward_body!($src ; $(($($rest_modifier $(($rest_modifier_arg))?)?, $rest)),*))
    };
}
pub use gen_backward_body;

#[allow(unused_macros)]
#[macro_export]
macro_rules! gen_field_poly_type {
    ((, $field:ident)) => {
        $field
    };

    ((optional, $field:ident)) => {
        OptionDeep<$field>
    };

    ((default($_:expr), $field:ident)) => {
        $field
    };

    ((tail, $field:ident)) => {
        $field
    };
}
pub use gen_field_poly_type;

/// Generate a continuation that matches the input
/// against a set of values and for each value,
/// the result is parsed with different a combinator
/// and stored in the suitable variant.
///
/// This generates the following types:
/// - `[< $name Cont >]`: a continuation struct to be used in Depend
/// - `[< Spec $name Value >]`: the spec result enum
/// - `[< $name Value >]`: the normal result enum
/// - `[< $name ValueOwned >]`: the owned result enum
///
/// Example:
/// ```rust
/// match_continuation! {
///     continuation ExtensionParam<'a>(ObjectIdentifierValue, spec SpecObjectIdentifierValue) {
///         oid!(2, 5, 29, 35), spec spec_oid!(2, 5, 29, 35) => AuthorityKeyIdentifier, ASN1<OctetString>, ASN1(OctetString),
///         _ => Other, ASN1<OctetString>, ASN1(OctetString),
///     }
/// }
/// ```
#[allow(unused_macros)]
#[macro_export]
macro_rules! match_continuation {
    (
        continuation $name:ident<$lt:lifetime>($input_type:ty, spec $spec_input_type:ty) {
            $(
                $value:expr, spec $spec_value:expr => $variant:ident, $combinator_type:ty, $combinator:expr,
            )*

            _ => $last_variant:ident, $last_combinator_type:ty, $last_combinator:expr,

            $(,)?
        }
    ) => {
        ::paste::paste! {
            ::builtin_macros::verus! {
                pub use [< internal_ $name >]::Cont as [< $name Cont >];
                pub use [< internal_ $name >]::SpecValue as [< Spec $name Value >];
                pub use [< internal_ $name >]::Value as [< $name Value >];
                pub use [< internal_ $name >]::ValueOwned as [< $name ValueOwned >];

                mod [< internal_ $name >] {
                    #![allow(non_camel_case_types)]
                    #![allow(non_snake_case)]

                    use super::*;
                    use crate::x509::macros::*;
                    use crate::asn1::*;
                    use crate::common::*;

                    #[derive(Debug, View)]
                    pub struct Cont;

                    impl Cont {
                        gen_match_continuation_spec_apply! {
                            Mapper, Cont, $spec_input_type;
                            $(($spec_value, $combinator),)*
                            (, $last_combinator)
                        }
                    }

                    impl Continuation for Cont {
                        type Input<$lt> = $input_type;
                        type Output = Mapped<ord_choice_type!(
                            $(
                                Cond<$combinator_type>,
                            )*
                            Cond<$last_combinator_type>,

                            // Since we can't generate match arms with macros
                            // the gen_* macros are using a sequence of if let's
                            // and Rust doesn't know that the if let's are exhaustive
                            // so we have a "wildcard" case in the end that should
                            // never be reached
                            Unreachable,
                        ), Mapper>;

                        gen_match_continuation_apply! {
                            Mapper;
                            $(($value, $spec_value, $combinator),)*
                            (, $last_combinator)
                        }

                        open spec fn requires<'a>(&self, i: Self::Input<'a>) -> bool {
                            true
                        }

                        open spec fn ensures<'a>(&self, i: Self::Input<'a>, o: Self::Output) -> bool {
                            &&& o@ == Self::spec_apply(i@)
                        }
                    }

                    mapper! {
                        pub struct Mapper;

                        for <$($variant,)* $last_variant>
                        from FromType where type FromType<$($variant,)* $last_variant> = ord_choice_result!($($variant,)* $last_variant, ());
                        to PolyType where pub enum PolyType<$($variant,)* $last_variant> {
                            $($variant($variant),)*
                            $last_variant($last_variant),
                            Unreachable,
                        }

                        spec SpecValue with <
                            $(<<$combinator_type as View>::V as SpecCombinator>::SpecResult,)*
                            <<$last_combinator_type as View>::V as SpecCombinator>::SpecResult
                        >;
                        exec Value<'a> with <
                            $(<$combinator_type as Combinator>::Result<'a>,)*
                            <$last_combinator_type as Combinator>::Result<'a>
                        >;
                        owned ValueOwned with <
                            $(<$combinator_type as Combinator>::Owned,)*
                            <$last_combinator_type as Combinator>::Owned
                        >;

                        forward(x) {
                            gen_choice_forward! {
                                x;
                                $($variant,)* $last_variant
                            }
                        } by {
                            // One extra * for the last variant
                            if let gen_choice_last_field_pat!(p, (*,); $($variant),*) = x {
                                assert(p == ());
                            }
                        }

                        backward(y) {
                            gen_choice_backward! {
                                y;
                                $($variant,)* $last_variant
                            }
                        }
                    }
                }
            }
        }
    };
}
pub use match_continuation;

/// Special case for matching against OIDs
///
/// In addition to match_continuation, this macro also generates
/// a lemma that the OIDs are disjoint.
///
/// NOTE: the provided OIDs are assumed to be disjoint (due to
/// the missing proof in gen_lemma_disjoint), otherwise we may
/// have a soundness issue
#[allow(unused_macros)]
#[macro_export]
macro_rules! oid_match_continuation {
    (
        continuation $name:ident {
            $(
                oid($($arc:expr),+) => $variant:ident($combinator:expr): $combinator_type:ty,
            )*

            _ => $last_variant:ident($last_combinator:expr): $last_combinator_type:ty,

            $(,)?
        }
    ) => {
        crate::x509::macros::match_continuation! {
            continuation $name<'a>(ObjectIdentifierValue, spec SpecObjectIdentifierValue) {
                $(
                    crate::x509::oid!($($arc),+), spec crate::x509::spec_oid!($($arc),+) => $variant, $combinator_type, $combinator,
                )*

                _ => $last_variant, $last_combinator_type, $last_combinator,
            }
        }
    }
}
pub use oid_match_continuation;

#[allow(unused_macros)]
#[macro_export]
macro_rules! gen_match_continuation_spec_apply_helper {
    ($input:expr, $last_cond:expr; (, $last_combinator:expr)) => {
        OrdChoice(
            Cond { cond: $last_cond, inner: $last_combinator },
            Unreachable,
        )
    };

    ($input:expr, $last_cond:expr; ($first_spec_value:expr, $first_combinator:expr), $(($rest_spec_value:expr, $rest_combinator:expr),)* (, $last_combinator:expr)) => {
        OrdChoice(
            Cond { cond: ext_equal($input, $first_spec_value), inner: $first_combinator },
            gen_match_continuation_spec_apply_helper!($input, $last_cond; $(($rest_spec_value, $rest_combinator),)* (, $last_combinator))
        )
    };
}
pub use gen_match_continuation_spec_apply_helper;

#[allow(unused_macros)]
#[macro_export]
macro_rules! gen_match_continuation_spec_apply {
    ($mapper:expr, $cont_name:ident, $spec_input_type:ty; $(($spec_value:expr, $combinator:expr),)* (, $last_combinator:expr)) => {
        ::builtin_macros::verus! {
            pub open spec fn spec_apply(i: $spec_input_type) -> <$cont_name as Continuation>::Output {
                let other = $(!ext_equal(i, $spec_value) &&)* true;
                Mapped {
                    inner: gen_match_continuation_spec_apply_helper!(i, other; $(($spec_value, $combinator),)* (, $last_combinator)),
                    mapper: $mapper,
                }
            }
        }
    };
}
pub use gen_match_continuation_spec_apply;

#[allow(unused_macros)]
#[macro_export]
macro_rules! gen_match_continuation_apply_helper {
    ($input:expr, $last_cond:expr; (, $last_combinator:expr)) => {
        OrdChoice(
            Cond { cond: $last_cond, inner: $last_combinator },
            Unreachable,
        )
    };

    ($input:expr, $last_cond:expr; ($first_value:expr, $first_combinator:expr), $(($rest_value:expr, $rest_combinator:expr),)* (, $last_combinator:expr)) => {
        OrdChoice(
            Cond { cond: $input.polyfill_eq(&$first_value), inner: $first_combinator },
            gen_match_continuation_apply_helper!($input, $last_cond; $(($rest_value, $rest_combinator),)* (, $last_combinator))
        )
    };
}
pub use gen_match_continuation_apply_helper;

#[allow(unused_macros)]
#[macro_export]
macro_rules! gen_match_continuation_apply {
    ($mapper:expr; $(($value:expr, $spec_value:expr, $combinator:expr),)* (, $last_combinator:expr)) => {
        ::builtin_macros::verus! {
            #[inline(always)]
            fn apply<'a>(&self, i: Self::Input<'a>) -> (o: Self::Output) {
                let other = $(!i.polyfill_eq(&$value) &&)* true;
                $({ #[allow(unused_variables)] let v = $value; assert(ext_equal(v.view(), $spec_value)); })*

                Mapped {
                    inner: gen_match_continuation_apply_helper!(i, other; $(($value, $combinator),)* (, $last_combinator)),
                    mapper: $mapper,
                }
            }
        }
    };
}
pub use gen_match_continuation_apply;

/// Given variants, generate if let branches to transform $src
/// from a nested Either term to a specific variant
#[allow(unused_macros)]
#[macro_export]
macro_rules! gen_choice_forward {
    ($src:expr; $($variant:ident),*) => {
        gen_choice_forward_branches! {
            $src, (); $($variant),*
        }
    };
}
pub use gen_choice_forward;

#[allow(unused_macros)]
#[macro_export]
macro_rules! gen_choice_forward_branches {
    ($src:expr, ($($stars:tt,)*); $last_variant:ident) => {
        if let inj_ord_choice_pat!($($stars,)* p, *) = $src {
            PolyType::$last_variant(p)
        } else {
            PolyType::Unreachable
        }
    };

    ($src:expr, ($($stars:tt,)*); $first_variant:ident $(, $rest_variant:ident)+) => {
        if let inj_ord_choice_pat!($($stars,)* p, *) = $src {
            PolyType::$first_variant(p)
        } else {
            gen_choice_forward_branches! {
                $src, ($($stars,)* *,); $($rest_variant),*
            }
        }
    };
}
pub use gen_choice_forward_branches;

/// Generate inj_ord_choice_pat!(*, ..., *, p) with |$variant| stars before p
#[allow(unused_macros)]
#[macro_export]
macro_rules! gen_choice_last_field_pat {
    ($pat:pat, ($($stars:tt,)*);) => {
        inj_ord_choice_pat!($($stars),*, $pat)
    };

    ($pat:pat, ($($stars:tt,)*); $_:ident $(, $rest:ident)*) => {
        gen_choice_last_field_pat!($pat, ($($stars,)* *,); $($rest),*)
    };
}
pub use gen_choice_last_field_pat;

/// Given variants, generate if let branches to transform $src
/// to a nested Either term
/// if let variant1(p) = x {
///    inj_ord_choice_result!(...)
/// } else if let variant2(p) = x {
///    ...
/// } ...
#[allow(unused_macros)]
#[macro_export]
macro_rules! gen_choice_backward {
    ($src:expr; $($variant:ident),+) => {
        gen_choice_backward_branches! {
            $src, (); $($variant),+
        }
    };
}
pub use gen_choice_backward;

#[allow(unused_macros)]
#[macro_export]
macro_rules! gen_choice_backward_branches {
    ($src:expr, ($($stars:tt,)*); $last_variant:ident) => {
        if let PolyType::$last_variant(p) = $src {
            inj_ord_choice_result!($($stars,)* p, *)
        } else {
            inj_ord_choice_result!($($stars,)* *, ())
        }
    };

    ($src:expr, ($($stars:tt,)*); $first_variant:ident $(, $rest_variant:ident)+) => {
        if let PolyType::$first_variant(p) = $src {
            inj_ord_choice_result!($($stars,)* p, *)
        } else {
            gen_choice_backward_branches! {
                $src, ($($stars,)* *,); $($rest_variant),*
            }
        }
    };
}
pub use gen_choice_backward_branches;

/// Generate a combinator for an ASN.1 CHOICE
///
/// For example
/// ```rust
/// asn1_choice! {
///     choice Test {
///         PrintableString(ASN1(PrintableString)): ASN1<PrintableString>,
///         UTF8String(ASN1(UTF8String)): ASN1<UTF8String>,
///     }
/// }
/// ```
///
/// This essentially generates an `OrdChoice` combinator over all the choices
///
/// NOTE: Since we can't generate match branches in macros, there is a small
/// artifact in the definition of the result type: a last variant with name
/// `Unreachable`, which should never be produced at runtime as the combinator
/// of Unreachable always fails
#[allow(unused_macros)]
#[macro_export]
macro_rules! asn1_choice {
    // This assumes the view of $field_combinator is also $field_combinator
    (
        choice $name:ident {
            $( $variant:ident($combinator:expr): $combinator_type:ty ),+
            $(,)?
        }
    ) => {
        ::paste::paste! {
            ::builtin_macros::verus! {
                pub use [< internal_ $name >]::$name;
                pub use [< internal_ $name >]::SpecValue as [< Spec $name Value >];
                pub use [< internal_ $name >]::Value as [< $name Value >];
                pub use [< internal_ $name >]::ValueOwned as [< $name ValueOwned >];

                mod [< internal_ $name >] {
                    #![allow(non_camel_case_types)]
                    #![allow(non_snake_case)]

                    use super::*;
                    use crate::x509::macros::*;
                    use crate::asn1::*;
                    use crate::common::*;

                    wrap_combinator! {
                        pub struct $name: Mapped<ord_choice_type!(
                                $($combinator_type,)+
                                Unreachable,
                            ), Mapper> =>
                            spec SpecValue,
                            exec<'a> Value<'a>,
                            owned ValueOwned,
                        = Mapped {
                                inner: ord_choice!(
                                    $($combinator,)+
                                    Unreachable,
                                ),
                                mapper: Mapper,
                            };
                    }

                    mapper! {
                        // Implement a mapper from nested Eithers to a specific variant
                        // TODO: same as the mapper in match_continuation, merge?
                        pub struct Mapper;

                        for <$($variant),+>
                        from FromType where type FromType<$($variant),+> = ord_choice_result!($($variant),+, ());
                        to PolyType where #[derive(Eq, PartialEq)] pub enum PolyType<$($variant),+> {
                            $($variant($variant),)+
                            Unreachable,
                        }

                        spec SpecValue with <
                            $(<<$combinator_type as View>::V as SpecCombinator>::SpecResult),+
                        >;
                        exec Value<'a> with <
                            $(<$combinator_type as Combinator>::Result<'a>),+
                        >;
                        owned ValueOwned with <
                            $(<$combinator_type as Combinator>::Owned),+
                        >;

                        forward(x) {
                            gen_choice_forward! { x; $($variant),+ }
                        } by {
                            if let gen_choice_last_field_pat!(p, (); $($variant),+) = x {
                                assert(p == ());
                            }
                        }

                        backward(y) {
                            gen_choice_backward! { y; $($variant),+ }
                        }
                    }
                }
            }
        }
    };
}
pub use asn1_choice;

/// Generate a combinator for an ASN.1 SEQUENCE OF
#[allow(unused_macros)]
#[macro_export]
macro_rules! asn1_sequence_of {
    (
        seq of $name:ident($combinator:expr): $combinator_type:ty;
    ) => {
        ::paste::paste! {
            ::builtin_macros::verus! {
                pub use [< internal_ $name >]::$name;
                pub use [< internal_ $name >]::SpecValue as [< Spec $name Value >];
                pub use [< internal_ $name >]::Value as [< $name Value >];
                pub use [< internal_ $name >]::ValueOwned as [< $name ValueOwned >];

                mod [< internal_ $name >] {
                    #![allow(non_camel_case_types)]
                    #![allow(non_snake_case)]

                    use super::*;
                    use crate::x509::macros::*;
                    use crate::asn1::*;
                    use crate::common::*;

                    wrap_combinator! {
                        pub struct $name: SequenceOf<$combinator_type> =>
                            spec SpecValue,
                            exec<'a> Value<'a>,
                            owned ValueOwned,
                        = SequenceOf($combinator);
                    }

                    asn1_tagged!($name, tag_of!(SEQUENCE));

                    pub type SpecValue = Seq<<<$combinator_type as View>::V as SpecCombinator>::SpecResult>;
                    pub type Value<'a> = VecDeep<<$combinator_type as Combinator>::Result<'a>>;
                    pub type ValueOwned = VecDeep<<$combinator_type as Combinator>::Owned>;
                }
            }
        }
    };
}
pub use asn1_sequence_of;

/// Same as above, but for SET OF
#[allow(unused_macros)]
#[macro_export]
macro_rules! asn1_set_of {
    (
        set of $name:ident($combinator:expr): $combinator_type:ty;
    ) => {
        ::paste::paste! {
            ::builtin_macros::verus! {
                pub use [< internal_ $name >]::$name;
                pub use [< internal_ $name >]::SpecValue as [< Spec $name Value >];
                pub use [< internal_ $name >]::Value as [< $name Value >];
                pub use [< internal_ $name >]::ValueOwned as [< $name ValueOwned >];

                mod [< internal_ $name >] {
                    #![allow(non_camel_case_types)]
                    #![allow(non_snake_case)]

                    use super::*;
                    use crate::x509::macros::*;
                    use crate::asn1::*;
                    use crate::common::*;

                    wrap_combinator! {
                        pub struct $name: SequenceOf<$combinator_type> =>
                            spec SpecValue,
                            exec<'a> Value<'a>,
                            owned ValueOwned,
                        = SequenceOf($combinator);
                    }

                    asn1_tagged!($name, tag_of!(SET));

                    pub type SpecValue = Seq<<<$combinator_type as View>::V as SpecCombinator>::SpecResult>;
                    pub type Value<'a> = VecDeep<<$combinator_type as Combinator>::Result<'a>>;
                    pub type ValueOwned = VecDeep<<$combinator_type as Combinator>::Owned>;
                }
            }
        }
    };
}
pub use asn1_set_of;

/// Allows multiple definitions involving SEQUENCE, SEQUENCE OF, SET OF, and CHOICE
#[allow(unused_macros)]
#[macro_export]
macro_rules! asn1 {
    () => {};

    (seq $def:tt { $($body:tt)* } $($rest:tt)*) => {
        crate::x509::macros::asn1_sequence! { seq $def { $($body)* } }
        crate::x509::macros::asn1! { $($rest)* }
    };

    (choice $def:tt { $($body:tt)* } $($rest:tt)*) => {
        crate::x509::macros::asn1_choice! { choice $def { $($body)* } }
        crate::x509::macros::asn1! { $($rest)* }
    };

    (seq of $name:ident($combinator:expr): $combinator_type:ty; $($rest:tt)*) => {
        crate::x509::macros::asn1_sequence_of! { seq of $name($combinator): $combinator_type; }
        crate::x509::macros::asn1! { $($rest)* }
    };

    (set of $name:ident($combinator:expr): $combinator_type:ty; $($rest:tt)*) => {
        crate::x509::macros::asn1_set_of! { set of $name($combinator): $combinator_type; }
        crate::x509::macros::asn1! { $($rest)* }
    };
}
pub use asn1;

}
