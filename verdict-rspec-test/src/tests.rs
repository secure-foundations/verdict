#![allow(unused)]

use verdict_rspec::test_rspec;
#[allow(unused_imports)]
use verdict_rspec_lib::*;
use vstd::prelude::*;

test_rspec!(
    mod simple_struct1 {
        pub struct Test {
            pub a: SpecString,
            pub b: u32,
        }
    }
);

test_rspec!(
    mod simple_struct2 {
        pub struct Test1 {
            pub a: SpecString,
            pub b: u32,
            pub c: Seq<u32>,
            pub d: Seq<Seq<u32>>,
        }

        pub struct Test2 {
            a: Option<Test1>,
            b: Seq<Test1>,
        }
    }
);

test_rspec!(mod simple_function1 {
    pub closed spec fn test1(i: u32) -> bool {
        if i <= 10 {
            let a = &i + 19;
            i <= 10 && a < 100
        } else {
            true
        }
    }

    pub closed spec fn test2(i: &u32) -> bool {
        *i == 100
    }
});

test_rspec!(mod simple_function2 {
    pub closed spec fn test1(s: &SpecString) -> bool {
        &&& s.len() >= 3
        &&& s.char_at(0) == '*'
        &&& s.char_at(1) == '.'
    }

    pub closed spec fn test2(s: SpecString) -> bool {
        &&& test1(&s)
        &&& s.len() <= 5
        &&& s.char_at(2) == '*'
    }
});

test_rspec!(mod simple_function3 {
    pub closed spec fn test1(s: &SpecString) -> bool {
        &&& s.len() >= 3
        &&& s.char_at(0) == '*'
        &&& s.char_at(1) == '.'
        &&& s != "hello"@ || s == "*.haha"@
    }
});

test_rspec!(mod simple_function4 {
    pub closed spec fn test1(s: &Seq<u32>) -> bool {
        &&& s.len() != 2 - 2
        &&& s[0] == 0
    }

    pub closed spec fn test2(s: Seq<u32>) -> bool {
        test1(&s)
    }
});

test_rspec!(mod simple_function5 {
    pub closed spec fn test1(s: &Seq<u32>) -> bool {
        let a: u32 = (10 + 123) as u32;
        &&& s.len() != 2 - 2
        &&& s[0] == a
    }

    pub closed spec fn test2(s: Seq<u32>) -> bool {
        test1(&s)
    }
});

test_rspec!(mod quantifier {
    struct S {
        n: usize,
        s: SpecString,
    }

    struct Test {
        v: Seq<S>,
    }

    spec fn test_quant(t: &Test, max_len: usize) -> bool {
        forall |i: usize| #![auto] 0 <= i < t.v.len() ==> {
            &&& t.v[i as int].n == i
            &&& t.v[i as int].s.len() <= max_len
        }
    }
});

test_rspec!(mod nested_seq {
    struct Elem {
        s: SpecString,
    }

    spec fn elem_eq(e1: &Elem, e2: &Elem) -> bool {
        &e1.s == &e2.s || &e1.s == "*"@
    }

    spec fn eq(s: Seq<Seq<Elem>>, t: Seq<Seq<Elem>>) -> bool {
        &&& s.len() == t.len()
        &&& forall |i: usize| #![auto] 0 <= i < s.len() ==> {
            &&& s[i as int].len() == t[i as int].len()
            &&& forall |j: usize| #![auto] 0 <= j < s[i as int].len() ==>
                elem_eq(&s[i as int][j as int], &t[i as int][j as int])
        }
    }
});

test_rspec!(mod random_test {
    pub struct Test2 {
        pub content: SpecString,
    }

    pub struct Test3 {
        pub test2: Option<Test2>,
    }

    pub struct Test {
        pub fingerprint: SpecString,
        pub version: u32,
        pub some_seq: Seq<u32>,
        test2: Option<Test2>,
        test3: Seq<Test3>,
    }

    pub closed spec fn other(s: &u32) -> bool {
        s == 10 || *s < 100
    }

    pub closed spec fn test2(t: &Test2, s: &SpecString) -> bool {
        s.len() > 1
    }

    pub closed spec fn test(t: &Test, s: &SpecString, v: &Seq<char>, v2: Seq<char>, v3: &Seq<Seq<u32>>) -> bool {
        let a = 10u32;
        &&& t.version < a + 2
        &&& t.version >= a
        &&& v.len() > 1
        &&& v[0] == 'c'
        &&& v[1] == 'b'
        &&& s.len() > 1
        &&& s.char_at(0) == 'c'
        &&& s.char_at(1) == 'b'
        // &&& "asd"@[0] == 'a' // this doesn't work because we need reveal_lit
        &&& {
            let b = 10usize;

            &&& other(&t.version)
            &&& s.len() > b
            &&& s == "hello"@ || s == "sadsa"@ || &"sadd"@ == s

            &&& t.fingerprint.len() == 16
            &&& t.fingerprint.char_at(1) == 'a'

            &&& t.some_seq.len() > 1
            &&& t.some_seq[0] == 1

            &&& &"what"@ == &"what"@
        }

        &&& forall |i: usize| 0 <= i < v2.len() ==> #[trigger] v2[i as int] == 'c' || v2[i as int] == 'b'
        &&& forall |i: usize| #![trigger v3[i as int]] 0 <= i < v3.len() ==> {
            forall |j: usize| 0 <= j < v3[i as int].len() ==> #[trigger] other(&v3[i as int][j as int])
        }

        &&& match &t.test2 {
            Some(t2) => test2(t2, s),
            None => false,
        }
    }
});

test_rspec!(mod test_exists {
    spec fn test(s: Seq<u32>, needle: u32) -> bool {
        exists |i: usize| 0 <= i < s.len() && s[i as int] == needle
    }
});

test_rspec!(mod test_match {
    struct Test {
        a: Option<Seq<u32>>,
    }

    spec fn all_zeros(v: &Seq<u32>) -> bool {
        forall |i: usize| 0 <= i < v.len() ==> v[i as int] == 0
    }

    spec fn test(s: Option<Option<Test>>) -> bool {
        match s {
            Some(Some(t)) => match &t.a {
                Some(v) => all_zeros(v),
                None => true,
            },
            _ => true,
        }
    }
});

test_rspec!(
    mod test_enum {
        enum A {
            B(u32),
            C,
            D { a: Seq<u32>, b: Option<SpecString> },
        }
    }
);

test_rspec!(
    mod test_struct_unnamed {
        struct Test(u32, SpecString);
        struct UnitStruct;
        struct UnitStruct2();
    }
);

mod extern_functions {
    use super::*;

    test_rspec!(mod test {
        use exec_f as f;

        closed spec fn test() -> bool {
            &f() == "hi"@
        }
    });

    verus! {
        closed spec fn f() -> SpecString { "hi"@ }

        fn exec_f() -> (res: String)
            ensures res@ == "hi"@
        {
            "hi".to_string()
        }
    }
}
