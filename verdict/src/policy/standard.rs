/// Traits of `Policy` that specify selected rules from RFC 5280 and CA/B BRs

use vstd::prelude::*;

use super::common::*;

verus! {

/// A validated chain should not contain expired certificates
pub trait NoExpiration: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task)
        ensures
            forall |i: usize| #![trigger chain[i as int]]
                0 <= i < chain.len() ==>
                chain[i as int].not_before <= task.now <= chain[i as int].not_after;
}

/// Outer signature algorithm should match the inner one
pub trait OuterInnerSigMatch: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task)
        ensures
            forall |i: usize| #![trigger chain[i as int]]
                0 <= i < chain.len() ==>
                chain[i as int].sig_alg_inner.bytes == chain[i as int].sig_alg_outer.bytes;
}

/// If the extension KeyUsage is present, at least one bit must be set
pub trait KeyUsageNonEmpty: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task)
        ensures
            forall |i: usize| #![trigger chain[i as int]]
                0 <= i < chain.len() ==>
                (chain[i as int].ext_key_usage matches Some(key_usage) ==> {
                    ||| key_usage.digital_signature
                    ||| key_usage.non_repudiation
                    ||| key_usage.key_encipherment
                    ||| key_usage.data_encipherment
                    ||| key_usage.key_agreement
                    ||| key_usage.key_cert_sign
                    ||| key_usage.crl_sign
                    ||| key_usage.encipher_only
                    ||| key_usage.decipher_only
                });
}

/// Issuer and subject UID should only appear if version is 2 or 3
pub trait IssuerSubjectUIDVersion: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task)
        ensures
            forall |i: usize| #![trigger chain[i as int]]
                0 <= i < chain.len() ==>
                (chain[i as int].issuer_uid matches Some(_) ||
                 chain[i as int].subject_uid matches Some(_)) ==>
                chain[i as int].version == 2 || chain[i as int].version == 3;
}

/// PathLenConstraints should be non-negative
pub trait PathLenNonNegative: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task)
        ensures
            forall |i: usize| #![trigger chain[i as int]]
                0 <= i < chain.len() ==>
                (chain[i as int].ext_basic_constraints matches Some(bc) ==>
                (bc.path_len matches Some(limit) ==> limit >= 0));
}

/// If BasicConstraints.PathLenConstraint is present,
/// is_ca is set, and key_usage.key_cert_sign is set (if present)
/// then the cert must not be followed by more than PathLenConstraint
/// non-leaf certificates
pub trait PathLenConstraint: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task)
        ensures
            forall |i: usize| #![trigger chain[i as int]]
                1 <= i < chain.len() ==> {
                    &chain[i as int].ext_basic_constraints matches Some(bc) ==> {
                        bc.path_len matches Some(limit) ==> {
                            bc.is_ca &&
                            (chain[i as int].ext_key_usage matches Some(key_usage) ==> key_usage.key_cert_sign)
                            ==>
                            (i - 1) <= limit as usize
                        }
                    }
                };
}

/// Every non-leaf certificate must be a CA certificate
pub trait NonLeafMustBeCA: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task)
        ensures
            forall |i: usize| #![trigger chain[i as int]]
                1 <= i < chain.len() ==>
                (&chain[i as int].ext_basic_constraints matches Some(bc) && bc.is_ca);
}

/// Every non-leaf certificate must have keyCertSign set in KeyUsage (if present)
pub trait NonLeafHasKeyCertSign: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task)
        ensures
            forall |i: usize| #![trigger chain[i as int]]
                1 <= i < chain.len() ==>
                (&chain[i as int].ext_key_usage matches Some(key_usage) ==> key_usage.key_cert_sign);
}

/// If SubjectAltName is present, it should contain at least one name
pub trait NonEmptySAN: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task)
        ensures
            forall |i: usize| #![trigger chain[i as int]]
                0 <= i < chain.len() ==>
                (chain[i as int].ext_subject_alt_name matches Some(san) ==> san.names.len() > 0);
}

/// Generalized from x509-limbo::rfc5280::aki::critical-aki
/// Conforming CAs MUST mark this (AKI) extension as non-critical.
pub trait AKINonCritical: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task)
        ensures
            chain.last().ext_authority_key_id matches Some(akid)
            ==> !akid.critical.unwrap_or(false);
}

/// Generalized from x509-limbo::rfc5280::aki::leaf/intermediate-missing-aki
/// The keyIdentifier field of the authorityKeyIdentifier extension MUST
/// be included in all certificates generated by conforming CAs to
/// facilitate certification path construction.
pub trait NonRootHasAKI: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task)
        ensures
            forall |i: usize| #![trigger chain[i as int]]
                0 <= i < chain.len() - 1 ==>
                (chain[i as int].ext_authority_key_id matches Some(akid) &&
                akid.key_id matches Some(..));
}

/// Generalized from x509-limbo::rfc5280::ski::intermediate-missing-ski
/// To facilitate certification path construction, this extension MUST
/// appear in all conforming CA certificates, that is, all certificates
/// including the basic constraints extension (Section 4.2.1.9) where the
/// value of cA is TRUE.
pub trait NonLeafHasSKI: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task)
        ensures
            forall |i: usize| #![trigger chain[i as int]]
                1 <= i < chain.len() ==>
                chain[i as int].ext_subject_key_id matches Some(..);
}

/// Generalized from x509-limbo::rfc5280::san::noncritical-with-empty-subject
/// If the subject field contains an empty sequence, then the issuing CA MUST
/// include a subjectAltName extension that is marked as critical.
pub trait EmptySubjectImpliesCriticalSAN: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task)
        ensures
            chain[0].subject.0.len() == 0
            ==> (chain[0].ext_subject_alt_name matches Some(san) &&
                san.critical.unwrap_or(false));
}

/// Generalized from x509-limbo::rfc5280::ski::critical-ski
/// Conforming CAs MUST mark this extension (SKI) as non-critical.
pub trait NonCriticalRootSKI: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task)
        ensures
            chain.last().ext_subject_key_id matches Some(skid)
            ==> !skid.critical.unwrap_or(false);
}

/// Generalized from x509-limbo::webpki::aki::root-with-aki-missing-keyidentifier
/// CA/B BR 7.1.2.1.3 Root CA Authority Key Identifier
/// keyIdentifier MUST be present. MUST be identical to the subjectKeyIdentifier field.
pub trait RootCAHasAKI: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task)
        ensures
            chain.last().ext_authority_key_id matches Some(akid)
            && akid.key_id matches Some(..);
}

/// Generalized from x509-limbo::webpki::aki::root-with-aki-authoritycertissuer
/// CA/B BR 7.1.2.1.3 Root CA Authority Key Identifier
/// authorityCertIssuer MUST NOT be present
/// authorityCertSerialNumber MUST NOT be present
pub trait RootCAAKINoIssuerOrSerial: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task)
        ensures
            chain.last().ext_authority_key_id matches Some(akid)
            ==> akid.issuer matches None && akid.serial matches None;
}

/// Generalized from x509-limbo::webpki::eku::ee-without-eku
/// CA/B BR 7.1.2.7.6
pub trait LeafHasEKU: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task)
        ensures
            chain[0].ext_extended_key_usage matches Some(eku)
            && !eku.critical.unwrap_or(false);
}

/// Generalized from x509-limbo::webpki::eku::root-has-eku
/// CA/B BR 7.1.2.1.2
pub trait RootHasNoEKU: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task)
        ensures
            chain.last().ext_extended_key_usage matches None;
}

/// Generalized from x509-limbo::webpki::forbidden-dsa-root
/// CA/B BR does not allow DSA keys
pub trait NoDSA: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task)
        ensures
            forall |i: usize| #![trigger chain[i as int]]
                0 <= i < chain.len() ==>
                !(chain[i as int].subject_key matches SubjectKey::DSA { .. });
}

/// Generalized from x509-limbo::webpki::forbidden-weak-rsa-key-in-root
/// CA/B BR For RSA key pairs the CA SHALL:
///   - Ensure that the modulus size, when encoded, is at least 2048 bits
pub trait RSA2048: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task)
        ensures
            forall |i: usize| #![trigger chain[i as int]]
                0 <= i < chain.len()
                ==> (chain[i as int].subject_key matches SubjectKey::RSA { mod_length }
                ==> mod_length >= 2048);
}

/// Tries to automatically prove the provided standard rules
#[allow(unused_macros)]
macro_rules! auto_std {
    () => {};
    ($policy:ty => $rule:ty $proof:block $($rest_policy:ty => $rest:ty $rest_proof:block)*) => {
        ::builtin_macros::verus! {
            impl $rule for $policy {
                proof fn conformance(
                    &self,
                    chain: Seq<crate::policy::Certificate>,
                    task: crate::policy::Task,
                ) $proof
            }
        }

        crate::policy::standard::auto_std!($($rest_policy => $rest $rest_proof)*);
    };
}
pub(crate) use auto_std;

}
