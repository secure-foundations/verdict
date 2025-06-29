use super::*;
use vstd::prelude::*;

verus! {

// DirectoryString ::= CHOICE {
//     teletexString           TeletexString (SIZE (1..MAX)),
//     printableString         PrintableString (SIZE (1..MAX)),
//     universalString         UniversalString (SIZE (1..MAX)),
//     utf8String              UTF8String (SIZE (1.. MAX)), // More common
//     bmpString               BMPString (SIZE (1..MAX))
//     ia5String               IA5String (SIZE (1..MAX))
// }
asn1! {
    choice DirectoryString {
        PrintableString(ASN1(PrintableString)): ASN1<PrintableString>,
        UTF8String(ASN1(UTF8String)): ASN1<UTF8String>,
        IA5String(ASN1(IA5String)): ASN1<IA5String>,
        TeletexString(placeholder!(TELETEX_STRING)): placeholder_type!(),
        UniversalString(placeholder!(UNIVERSAL_STRING)): placeholder_type!(),
        BMPString(placeholder!(BMP_STRING)): placeholder_type!(),
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
            let _ = DirectoryString.parse(&[]);
        }
    }

    #[test]
    fn utf8() {
        assert_eq!(
            DirectoryString
                .parse(&[0x0C, 0x07, 0x52, 0x75, 0x62, 0x79, 0x20, 0x43, 0x41,])
                .unwrap()
                .1,
            DirectoryStringValue::UTF8String("Ruby CA")
        );
    }

    #[test]
    fn ia5_string() {
        let parsed = DirectoryString
            .parse(&[
                0x16, 0x09, 0x72, 0x75, 0x62, 0x79, 0x2D, 0x6C, 0x61, 0x6E, 0x67,
            ])
            .unwrap()
            .1;

        match parsed {
            DirectoryStringValue::IA5String(s) => {
                assert_eq!(s, "ruby-lang");
            }
            _ => panic!("{:?}", parsed),
        }
    }

    #[test]
    fn printable_string() {
        let parsed = DirectoryString
            .parse(&[
                0x13, 0x19, 0x47, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x20, 0x54, 0x72, 0x75, 0x73, 0x74,
                0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x20, 0x4C, 0x4C, 0x43,
            ])
            .unwrap()
            .1;

        match parsed {
            DirectoryStringValue::PrintableString(s) => {
                assert_eq!(s, "Google Trust Services LLC");
            }
            _ => panic!("{:?}", parsed),
        }
    }
}
