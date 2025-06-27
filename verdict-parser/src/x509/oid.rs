// Shorthands for OIDs and their equality axioms

use vstd::prelude::*;

pub use crate::asn1::UInt;
pub use crate::asn1::ObjectIdentifierValue;
pub use crate::common::VecDeep;

verus! {

/// Map OID names to their values
/// NOTE: to add a new OID, add an entry here
/// and also in `gen_oid_axioms` below (if disjointness is required)
#[allow(unused_macros)]
#[macro_export]
macro_rules! oid_name {
    // Extension names
    (SUBJECT_KEY_IDENT)     => { [2, 5, 29, 14] };
    (KEY_USAGE)             => { [2, 5, 29, 15] };
    (SUBJECT_ALT_NAME)      => { [2, 5, 29, 17] };
    (BASIC_CONSTRAINTS)     => { [2, 5, 29, 19] };
    (NAME_CONSTRAINTS)      => { [2, 5, 29, 30] };
    (CERT_POLICIES)         => { [2, 5, 29, 32] };
    (AUTH_KEY_IDENT)        => { [2, 5, 29, 35] };
    (EXTENDED_KEY_USAGE)    => { [2, 5, 29, 37] };
    (AUTH_INFO_ACCESS)      => { [1, 3, 6, 1, 5, 5, 7, 1, 1] };

    // Signature algorithms
    (RSA_SIGNATURE_MD2)     => { [1, 2, 840, 113549, 1, 1, 2] };
    (RSA_SIGNATURE_MD5)     => { [1, 2, 840, 113549, 1, 1, 4] };
    (RSA_SIGNATURE_SHA1)    => { [1, 2, 840, 113549, 1, 1, 5] };
    (RSA_SIGNATURE_SHA256)  => { [1, 2, 840, 113549, 1, 1, 11] };
    (RSA_SIGNATURE_SHA384)  => { [1, 2, 840, 113549, 1, 1, 12] };
    (RSA_SIGNATURE_SHA512)  => { [1, 2, 840, 113549, 1, 1, 13] };
    (RSA_SIGNATURE_SHA224)  => { [1, 2, 840, 113549, 1, 1, 14] };
    (DSA_SIGNATURE)         => { [1, 2, 840, 10040, 4, 1] };

    (ECDSA_SIGNATURE_SHA224) => { [1, 2, 840, 10045, 4, 3, 1] };
    (ECDSA_SIGNATURE_SHA256) => { [1, 2, 840, 10045, 4, 3, 2] };
    (ECDSA_SIGNATURE_SHA384) => { [1, 2, 840, 10045, 4, 3, 3] };
    (ECDSA_SIGNATURE_SHA512) => { [1, 2, 840, 10045, 4, 3, 4] };

    (RSA_ENCRYPTION)        => { [1, 2, 840, 113549, 1, 1, 1] };
    (EC_PUBLIC_KEY)         => { [1, 2, 840, 10045, 2, 1] };

    // EC curves
    (EC_P_256)              => { [1, 2, 840, 10045, 3, 1, 7] };
    (EC_P_384)              => { [1, 3, 132, 0, 34] };

    // Directory names
    (COMMON_NAME)           => { [2, 5, 4, 3] };
    (COUNTRY_NAME)          => { [2, 5, 4, 6] };
    (LOCALITY_NAME)         => { [2, 5, 4, 7] };
    (STATE_NAME)            => { [2, 5, 4, 8] };
    (ORGANIZATION_NAME)     => { [2, 5, 4, 10] };
    (ORGANIZATIONAL_UNIT)   => { [2, 5, 4, 11] };
    (ORGANIZATIONAL_IDENT)  => { [2, 5, 4, 97] };
    (STREET_ADDRESS)        => { [2, 5, 4, 9] };
    (SERIAL_NUMBER)         => { [2, 5, 4, 5] };
    (GIVEN_NAME)            => { [2, 5, 4, 42] };
    (POSTAL_CODE)           => { [2, 5, 4, 17] };
    (SURNAME)               => { [2, 5, 4, 4] };
    (EMAIL_ADDRESS)         => { [1, 2, 840, 113549, 1, 9, 1] };

    (DOMAIN_COMPONENT)      => { [0, 9, 2342, 19200300, 100, 1, 25] };

    // Extended key usage purposes
    (SERVER_AUTH)           => { [1, 3, 6, 1, 5, 5, 7, 3, 1] };
    (CLIENT_AUTH)           => { [1, 3, 6, 1, 5, 5, 7, 3, 2] };
    (CODE_SIGNING)          => { [1, 3, 6, 1, 5, 5, 7, 3, 3] };
    (EMAIL_PROTECTION)      => { [1, 3, 6, 1, 5, 5, 7, 3, 4] };
    (TIME_STAMPING)         => { [1, 3, 6, 1, 5, 5, 7, 3, 8] };
    (OCSP_SIGNING)          => { [1, 3, 6, 1, 5, 5, 7, 3, 9] };
}
pub use oid_name;

// Generate axioms for OID names
macro_rules! gen_oid_axioms {
    ($($id:ident)*) => {
        // Generate an axiom saying that the OIDs defined above are all disjoint
        gen_lemma_disjoint! {
            axiom_disjoint_oids {
                $(spec_oid!($id),)*
            }
        }
    };
}

gen_oid_axioms! {
    SUBJECT_KEY_IDENT
    KEY_USAGE
    SUBJECT_ALT_NAME
    BASIC_CONSTRAINTS
    NAME_CONSTRAINTS
    CERT_POLICIES
    AUTH_KEY_IDENT
    EXTENDED_KEY_USAGE
    RSA_SIGNATURE_MD2
    RSA_SIGNATURE_MD5
    RSA_SIGNATURE_SHA1
    RSA_SIGNATURE_SHA256
    RSA_SIGNATURE_SHA384
    RSA_SIGNATURE_SHA512
    RSA_SIGNATURE_SHA224
    DSA_SIGNATURE
    ECDSA_SIGNATURE_SHA224
    ECDSA_SIGNATURE_SHA256
    ECDSA_SIGNATURE_SHA384
    ECDSA_SIGNATURE_SHA512
    RSA_ENCRYPTION
    EC_PUBLIC_KEY
}

impl ObjectIdentifierValue {
    pub fn from_slice(slice: &[UInt]) -> (res: Self)
        ensures res@ =~= slice@
    {
        ObjectIdentifierValue(VecDeep::from_slice(slice))
    }
}

/// Macro for constructing an OID
#[allow(unused_macros)]
#[macro_export]
macro_rules! oid {
    ($($x:literal),+) => {
        ObjectIdentifierValue::from_slice(&[$($x),+])
    };

    ($id:ident) => {
        ObjectIdentifierValue::from_slice(&oid_name!($id))
    };
}
pub use oid;

#[allow(unused_macros)]
#[macro_export]
macro_rules! spec_oid {
    ($($x:literal),+) => {{
        // Convert from slice so that we don't need to
        // assert trivial facts such as oid!(...)@ == spec_oid!(...)
        let oid: Seq<UInt> = [$($x),+].view();
        oid
    }};

    ($id:ident) => {{
        let oid: Seq<UInt> = oid_name!($id).view();
        oid
    }};
}
pub use spec_oid;

/// Used to suppress Verus warning about broadcast missing triggers
pub uninterp spec fn lemma_disjoint_trigger() -> bool;

/// Macro to generate a lemma that states the disjointness of a list of spec terms
/// NOTE: the disjointness of the provided terms are trusted
/// incorrect calls to this might lead to unsoundness
#[allow(unused_macros)]
#[macro_export]
macro_rules! gen_lemma_disjoint {
    ($name:ident { $($term:expr),* $(,)? }) => {
        ::builtin_macros::verus! {
            pub broadcast proof fn $name()
                ensures
                    (true || #[trigger] lemma_disjoint_trigger()),
                    gen_lemma_disjoint_helper! {; $($term),* }
            {}
        }
    };
}
pub use gen_lemma_disjoint;

#[allow(unused_macros)]
#[macro_export]
macro_rules! gen_lemma_disjoint_helper {
    ($($term:expr),* ; ) => { true };

    ($($prev_term:expr),* ; $term:expr $(, $rest_term:expr)*) => {
        $(::builtin_macros::verus_proof_expr! { $prev_term != $term } &&)* true && gen_lemma_disjoint_helper!($($prev_term,)* $term ; $($rest_term),*)
    };
}
pub use gen_lemma_disjoint_helper;

}
