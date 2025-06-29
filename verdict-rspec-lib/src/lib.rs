#![forbid(unsafe_code)]

use std::fmt::Debug;
use vstd::prelude::*;

verus! {

/// Use this type to tell rspec to generate
/// String as exec impl instead of [`Vec<char>`]
pub type SpecString = Seq<char>;

// A marker to denote that the compiled type should have a reference
pub type ExecRef<T> = T;

pub struct RSpec;

/// Verus doesn't support exec mode equalities between certain types
/// so we implement our own versions
pub trait Eq<A: DeepView, B: DeepView<V = A::V>> {
    fn eq(a: A, b: B) -> (res: bool)
        ensures res == (a.deep_view() == b.deep_view());
}

impl<'a, 'b> Eq<&'a String, &'b str> for RSpec {
    #[verifier::external_body]
    #[inline(always)]
    fn eq(a: &'a String, b: &'b str) -> (res: bool) {
        a == b
    }
}

impl<'a, 'b> Eq<&'a str, &'b String> for RSpec {
    #[verifier::external_body]
    #[inline(always)]
    fn eq(a: &'a str, b: &'b String) -> (res: bool) {
        a == b
    }
}

impl<'a, 'b> Eq<&'a String, String> for RSpec {
    #[verifier::external_body]
    #[inline(always)]
    fn eq(a: &'a String, b: String) -> (res: bool) {
        a == &b
    }
}

impl<'a, 'b> Eq<&'a String, &'b String> for RSpec {
    #[verifier::external_body]
    #[inline(always)]
    fn eq(a: &'a String, b: &'b String) -> (res: bool) {
        a == b
    }
}

impl<'a, 'b, 'c> Eq<&'a String, &'b &'c String> for RSpec {
    #[verifier::external_body]
    #[inline(always)]
    fn eq(a: &'a String, b: &'b &'c String) -> (res: bool) {
        a == *b
    }
}

macro_rules! native_eq {
    () => {};
    ($ty:ident $($rest:ident)*) => {
        verus! {
            impl Eq<$ty, $ty> for RSpec {
                #[inline(always)]
                fn eq(a: $ty, b: $ty) -> (res: bool) {
                    a == b
                }
            }

            impl<'a> Eq<&'a $ty, $ty> for RSpec {
                #[inline(always)]
                fn eq(a: &'a $ty, b: $ty) -> (res: bool) {
                    *a == b
                }
            }

            impl<'b> Eq<$ty, &'b $ty> for RSpec {
                #[inline(always)]
                fn eq(a: $ty, b: &'b$ty) -> (res: bool) {
                    a == *b
                }
            }
        }

        native_eq!($($rest)*);
    };
}

native_eq! {
    bool
    u8 u16 u32 u64 u128
    i8 i16 i32 i64 i128
    usize char
}

/// An index trait for both Vec and String
/// ExecT and SpecT are separated to support both returning a reference
/// and returning a Copy value (e.g. String => char)
pub trait Index<E: DeepView>: DeepView<V = Seq<E::V>> {
    fn rspec_index(&self, i: usize) -> (res: &E)
        requires i < self.deep_view().len()
        ensures res.deep_view() == self.deep_view()[i as int];
}

impl<E: DeepView> Index<E> for Vec<E> {
    #[inline(always)]
    fn rspec_index(&self, i: usize) -> (res: &E) {
        &self[i]
    }
}

/// SpecString::char_at
pub trait SpecCharAt {
    spec fn char_at(&self, i: int) -> char;
}

impl SpecCharAt for SpecString {
    open spec fn char_at(&self, i: int) -> char {
        self[i]
    }
}

/// Exec version of SpecString::char_at
pub trait CharAt: DeepView<V = Seq<char>> {
    fn rspec_char_at(&self, i: usize) -> (res: char)
        requires i < self.deep_view().len()
        ensures res == self.deep_view()[i as int];
}

impl CharAt for String {
    #[inline(always)]
    fn rspec_char_at(&self, i: usize) -> (res: char) {
        self.as_str().get_char(i)
    }
}

impl CharAt for str {
    #[inline(always)]
    fn rspec_char_at(&self, i: usize) -> (res: char) {
        self.get_char(i)
    }
}

/// SpecString::has_char
pub trait SpecHasChar {
    spec fn has_char(&self, c: char) -> bool;
}

impl SpecHasChar for SpecString {
    open spec fn has_char(&self, c: char) -> bool {
        self.contains(c)
    }
}

/// Exec version of SpecString::char_at
pub trait HasChar: DeepView<V = Seq<char>> {
    fn rspec_has_char(&self, c: char) -> (res: bool)
        ensures res == self.deep_view().contains(c);
}

impl HasChar for String {
    #[verifier::external_body]
    #[inline(always)]
    fn rspec_has_char(&self, c: char) -> (res: bool) {
        self.chars().any(|x| x == c)
    }
}

impl HasChar for str {
    #[verifier::external_body]
    #[inline(always)]
    fn rspec_has_char(&self, c: char) -> (res: bool) {
        self.chars().any(|x| x == c)
    }
}

/// Length method for both Vec and String
pub trait Len<E: DeepView>: DeepView<V = Seq<E::V>> {
    fn rspec_len(&self) -> (res: usize)
        ensures res == self.deep_view().len();
}

impl<E: DeepView> Len<E> for Vec<E> {
    #[inline(always)]
    fn rspec_len(&self) -> (res: usize) {
        self.len()
    }
}

impl Len<char> for String {
    #[inline(always)]
    fn rspec_len(&self) -> (res: usize) {
        self.as_str().unicode_len()
    }
}

/// Skip method for strings
/// TODO: performance: this method will actually copy the entire string
/// due to interface/compiler limitations
pub trait Skip<E, R: DeepView<V = Seq<E>>>: DeepView<V = Seq<E>> {
    fn rspec_skip(&self, n: usize) -> (res: R)
        requires n <= self.deep_view().len()
        ensures res.deep_view() == self.deep_view().skip(n as int);
}

impl Skip<char, String> for String {
    #[verifier::external_body]
    #[inline(always)]
    fn rspec_skip(&self, n: usize) -> (res: String) {
        self.as_str().rspec_skip(n)
    }
}

impl Skip<char, String> for str {
    #[verifier::external_body]
    #[inline(always)]
    fn rspec_skip(&self, n: usize) -> (res: String) {
        let offset = self.char_indices().nth(n).unwrap().0;
        self[offset..].to_string()
    }
}

/// Take, similar to Skip
pub trait Take<E, R: DeepView<V = Seq<E>>>: DeepView<V = Seq<E>> {
    fn rspec_take(&self, n: usize) -> (res: R)
        requires n <= self.deep_view().len()
        ensures res.deep_view() == self.deep_view().take(n as int);
}

impl Take<char, String> for String {
    #[verifier::external_body]
    #[inline(always)]
    fn rspec_take(&self, n: usize) -> (res: String) {
        self.as_str().rspec_take(n)
    }
}

impl Take<char, String> for str {
    #[verifier::external_body]
    #[inline(always)]
    fn rspec_take(&self, n: usize) -> (res: String) {
        let offset = self.char_indices().nth(n).unwrap().0;
        self[..offset].to_string()
    }
}

/// Used for tracing the evaluation of rspec functions
#[verifier::external_body]
pub fn rspec_trace_result<T: Debug>(s: &str, res: T) {
    eprintln!("[rspec] fn {}: {:?}", s, res);
}

pub open spec fn debug<T>(t: T) { () }

#[verifier::external_body]
pub fn rspec_debug<T: Debug>(t: T) {
    eprintln!("[rspec] debug: {:?}", t);
}

}
