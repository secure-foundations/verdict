#![allow(unused_parens)]
#![allow(unexpected_cfgs)]

use vstd::prelude::*;
#[cfg(feature = "trace")] use verdict_rspec::rspec_trace as rspec;
#[cfg(not(feature = "trace"))] use verdict_rspec::rspec;
use verdict_rspec_lib::*;

use crate::issue;

#[allow(unused_imports)]
pub use super::*;

verus! {

/// Common trait for all policies (e.g. [`super::chrome::ChromePolicy`]).
/// NOTE: this is the internal version.
pub trait Policy: Send + Sync {
    /// User-defined issuing relation without checking signature
    spec fn spec_likely_issued(&self, issuer: Certificate, subject: Certificate) -> bool;

    /// A policy-dependent predicate to check if `subject`
    /// is likely issued by `issuer` without signature checking.
    fn likely_issued(&self, issuer: &ExecCertificate, subject: &ExecCertificate) -> (res: bool)
        ensures res == self.spec_likely_issued(issuer.deep_view(), subject.deep_view());

    /// User-defined chain/path validation
    spec fn spec_valid_chain(&self, chain: Seq<Certificate>, task: Task) -> bool;

    /// A policy-specific predicate to check if a certificate chain is
    /// considered valid with the provided [`ExecTask`], provided that
    /// for each `i`, `chain[i]` is issued by `chain[i + 1]`,
    /// and `chain.last()` is a trusted root certificate.
    fn valid_chain(&self, chain: &Vec<&ExecCertificate>, task: &ExecTask) -> (res: bool)
        ensures res.deep_view() == self.spec_valid_chain(chain.deep_view(), task.deep_view());
}

rspec! {

/// Corresponds to `AttributeTypeAndValue` in X.509
pub struct Attribute {
    pub oid: SpecString,
    pub value: SpecString,
}

pub struct DistinguishedName(pub Seq<Seq<Attribute>>);

pub enum GeneralName {
    DNSName(SpecString),
    DirectoryName(DistinguishedName),
    IPAddr(Seq<u8>),
    OtherName,
    Unsupported,
}

pub enum SubjectKey {
    RSA {
        mod_length: usize,
    },
    DSA {
        p_len: usize,
        q_len: usize,
        g_len: usize,
    },
    Other,
}

pub struct AuthorityKeyIdentifier {
    pub critical: Option<bool>,
    pub key_id: Option<SpecString>,
    pub issuer: Option<SpecString>,
    pub serial: Option<SpecString>,
}

pub struct SubjectKeyIdentifier {
    pub critical: Option<bool>,
    pub key_id: SpecString,
}

pub enum ExtendedKeyUsageType {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OCSPSigning,
    Any,
    Other(SpecString),
}

pub struct ExtendedKeyUsage {
    pub critical: Option<bool>,
    pub usages: Seq<ExtendedKeyUsageType>,
}

pub struct BasicConstraints {
    pub critical: Option<bool>,
    pub is_ca: bool,
    pub path_len: Option<i64>,
}

pub struct KeyUsage {
    pub critical: Option<bool>,
    pub digital_signature: bool,
    pub non_repudiation: bool,
    pub key_encipherment: bool,
    pub data_encipherment: bool,
    pub key_agreement: bool,
    pub key_cert_sign: bool,
    pub crl_sign: bool,
    pub encipher_only: bool,
    pub decipher_only: bool,
}

pub struct SubjectAltName {
    pub critical: Option<bool>,
    pub names: Seq<GeneralName>,
}

pub struct NameConstraints {
    pub critical: Option<bool>,
    pub permitted: Seq<GeneralName>,
    pub excluded: Seq<GeneralName>,
}

pub struct CertificatePolicies {
    pub critical: Option<bool>,
    pub policies: Seq<SpecString>,
}

pub struct AuthorityInfoAccess {
    pub critical: Option<bool>,
    // Other info is not encoded
}

pub struct SignatureAlgorithm {
    pub id: SpecString,
    pub bytes: SpecString,
}

pub struct Extension {
    pub oid: SpecString,
    pub critical: Option<bool>,
}

pub struct Certificate {
    pub fingerprint: SpecString,
    pub version: u32,
    pub serial: SpecString,
    pub sig_alg_outer: SignatureAlgorithm,
    pub sig_alg_inner: SignatureAlgorithm,
    pub not_after: u64,
    pub not_before: u64,

    pub issuer: DistinguishedName,
    pub subject: DistinguishedName,
    pub subject_key: SubjectKey,

    pub issuer_uid: Option<SpecString>,
    pub subject_uid: Option<SpecString>,

    pub ext_authority_key_id: Option<AuthorityKeyIdentifier>,
    pub ext_subject_key_id: Option<SubjectKeyIdentifier>,
    pub ext_extended_key_usage: Option<ExtendedKeyUsage>,
    pub ext_basic_constraints: Option<BasicConstraints>,
    pub ext_key_usage: Option<KeyUsage>,
    pub ext_subject_alt_name: Option<SubjectAltName>,
    pub ext_name_constraints: Option<NameConstraints>,
    pub ext_certificate_policies: Option<CertificatePolicies>,
    pub ext_authority_info_access: Option<AuthorityInfoAccess>,

    // All extensions without parameters
    pub all_exts: Option<Seq<Extension>>,
}

#[derive(Copy, Clone)]
pub enum Purpose {
    ServerAuth,
}

pub struct Task {
    pub hostname: Option<SpecString>,
    pub purpose: Purpose,
    pub now: u64,
}

pub enum PolicyError {
    UnsupportedTask,
}

use exec_starts_with as starts_with;
use exec_ends_with as ends_with;

/// Match a pattern with wildcard (e.g. "*.example.com") against a string
pub open spec fn match_name(pattern: &SpecString, name: &SpecString) -> bool {
    if starts_with(pattern, &"*."@) {
        let name_len = name.len();
        let pattern_len = pattern.len();

        pattern_len > 2 && {
            ||| &pattern.skip(2) == name // *.a.com matches a.com
            ||| name_len > pattern_len - 1 && // `name` should be longer than ".{suffix}"
                ends_with(name, &pattern.skip(1)) &&
                // the prefix of `name` that matches '*' should not contain '.'
            !name.take(name_len - (pattern_len - 1)).has_char('.')
        }
    } else {
        pattern == name
    }
}

/// Additional checks for issuing relation
/// TODO: check subject.akid.auth_cert_issuer
/// References:
/// - RFC 2459, 4.2.1.1
/// - https://github.com/openssl/openssl/blob/ed6862328745c51c2afa2b6485cc3e275d543c4e/crypto/x509/v3_purp.c#L1002
pub open spec fn check_auth_key_id(issuer: &Certificate, subject: &Certificate) -> bool {
    match &subject.ext_authority_key_id {
        Some(auth_key_id) => {
            // Subject's AKID matches issuer's SKID if both exist
            &&& match (&issuer.ext_subject_key_id, &auth_key_id.key_id) {
                (Some(skid), Some(akid)) => &skid.key_id == akid,
                _ => true,
            }

            // Subject's AKID serial matches issuer's serial if both exist
            &&& match &auth_key_id.serial {
                Some(akid_serial) => akid_serial == &issuer.serial,
                None => true,
            }
        }
        None => true,
    }
}

use exec_normalize_string as normalize_string;
use exec_bv_and_u8 as bv_and_u8;

/// We offer a switch `normalize` since:
/// - Chrome does string normalization (folding the ASCII space and lower casing (ASCII-only))
///   - https://github.com/chromium/chromium/blob/0590dcf7b036e15c133de35213be8fe0986896aa/net/cert/internal/verify_name_match.cc#L70
/// - Firefox does not do string normalization
///   - https://searchfox.org/mozilla-central/source/security/nss/lib/mozpkix/lib/pkixnames.cpp#1345
/// - OpenSSL considers more characters as white space (https://github.com/openssl/openssl/blob/ea5817854cf67b89c874101f209f06ae016fd333/crypto/ctype.c#L21),
///   whereas Chrome only considers a single ASCII space character ' '
pub open spec fn rdn_has_name(rdn: &Seq<Attribute>, name: &Attribute, normalize: bool) -> bool {
    exists |i: usize| 0 <= i < rdn.len() && {
        &&& #[trigger] &rdn[i as int].oid == &name.oid
        &&& if normalize {
            &normalize_string(&rdn[i as int].value) == &normalize_string(&name.value)
        } else {
            &rdn[i as int].value == &name.value
        }
    }
}

/// Check if for any item in rdn2, there is a corresponding item in rdn1 with the same OID
/// and same value
pub open spec fn is_subtree_rdn(rdn1: &Seq<Attribute>, rdn2: &Seq<Attribute>, normalize: bool) -> bool {
    &&& rdn1.len() <= rdn2.len()
    &&& forall |i: usize| 0 <= i < rdn1.len() ==> rdn_has_name(&rdn2, #[trigger] &rdn1[i as int], normalize)
}

/// Check if name1 is a subset set of name2
/// See: https://github.com/google/boringssl/blob/571c76e919c0c48219ced35bef83e1fc83b00eed/pki/verify_name_match.cc#L261C6-L261C29
pub open spec fn is_subtree_of(name1: &DistinguishedName, name2: &DistinguishedName, normalize: bool) -> bool {
    &&& name1.0.len() <= name2.0.len()
    &&& forall |i: usize| 0 <= i < name1.0.len() ==> is_subtree_rdn(#[trigger] &name1.0[i as int], &name2.0[i as int], normalize)
}

pub open spec fn same_attr(attr1: &Attribute, attr2: &Attribute, normalize: bool) -> bool
{
    &&& &attr1.oid == &attr2.oid
    &&& if normalize {
        &attr1.value == &attr2.value ||
        &normalize_string(&attr1.value) == &normalize_string(&attr2.value)
    } else {
        &attr1.value == &attr2.value
    }
}

pub open spec fn same_rdn(rdn1: &Seq<Attribute>, rdn2: &Seq<Attribute>, normalize: bool) -> bool
{
    &&& rdn1.len() == rdn2.len()
    &&& forall |i: usize| 0 <= i < rdn1.len()
        ==> same_attr(#[trigger] &rdn1[i as int], &rdn2[i as int], normalize)
}

/// Check if two distinguished names are the same, with/without normalization
/// References:
/// - RFC 5280, 4.1.2.4
/// - https://github.com/openssl/openssl/blob/ed6862328745c51c2afa2b6485cc3e275d543c4e/crypto/x509/x509_cmp.c#L254
pub open spec fn same_dn(name1: &DistinguishedName, name2: &DistinguishedName, normalize: bool) -> bool
{
    &&& name1.0.len() == name2.0.len()
    &&& forall |i: usize| 0 <= i < name1.0.len()
        ==> same_rdn(#[trigger] &name1.0[i as int], &name2.0[i as int], normalize)
}

/// Similar to `match_name`, but used for checking name constraints
/// TODO: reference
pub open spec fn permit_name(name_constraint: &SpecString, name: &SpecString) -> bool {
    ||| name_constraint.len() == 0 // empty string matches everything
    ||| if name_constraint.char_at(0) == '.' {
        // name_constraint starts with '.': name_constraint should be a suffix of name
        &&& name_constraint.len() <= name.len()
        &&& &name.skip(name.len() - name_constraint.len()) == name_constraint
    } else {
        // name_constraint starts with a label: name must be the same
        // or have a suffix of '.<name_constraint>'
        ||| name == name_constraint
        ||| name.len() > name_constraint.len() &&
            name.char_at(name.len() - name_constraint.len() - 1) == '.' &&
            &name.skip(name.len() - name_constraint.len()) == name_constraint
    }
}

/// Check if the IP address `addr` fall into `range`
/// See RFC 5280, 4.2.1.10. Name Constraints
pub open spec fn ip_addr_in_range(range: &Seq<u8>, addr: &Seq<u8>) -> bool {
    // Both IPv4
    ||| {
        &&& range.len() == 8
        &&& addr.len() == 4
        &&& forall |i: usize| 0 <= i < 4 ==>
                bv_and_u8(&range[i as int], &range[i + 4]) == bv_and_u8(&addr[i as int], &range[i + 4])
    }

    // Both IPv6
    ||| {
        &&& range.len() == 32
        &&& addr.len() == 16
        &&& forall |i: usize| 0 <= i < 16 ==>
                bv_and_u8(&range[i as int], &range[i + 16]) == bv_and_u8(&addr[i as int], &range[i + 16])
    }
}

/// Check if a NameConstraints has a directory name constraint in the permitted list
pub open spec fn has_directory_name_constraint(constraints: &NameConstraints) -> bool {
    exists |i: usize| 0 <= i < constraints.permitted.len() &&
        #[trigger] &constraints.permitted[i as int] matches GeneralName::DirectoryName(_)
}

/// Same check for DNS name
pub open spec fn has_dns_name_constraint(constraints: &NameConstraints) -> bool {
    exists |j: usize|
        0 <= j < constraints.permitted.len() &&
        #[trigger] constraints.permitted[j as int] matches GeneralName::DNSName(_)
}

/// Same check for IP addresses
pub open spec fn has_ip_addr_name_constraint(constraints: &NameConstraints) -> bool {
    exists |i: usize| 0 <= i < constraints.permitted.len() &&
        #[trigger] &constraints.permitted[i as int] matches GeneralName::IPAddr(_)
}

/// Check that there is no two extensions with the same OID
pub open spec fn check_duplicate_extensions(cert: &Certificate) -> bool
{
    &cert.all_exts matches Some(all_exts) ==>
    forall |i: usize| #![trigger all_exts[i as int]] 0 <= i < all_exts.len() ==>
    forall |j: usize| #![trigger all_exts[j as int]] 0 <= j < i ==>
        &all_exts[i as int].oid != &all_exts[j as int].oid
}

} // rspec!

/// NOTE: unspecified
pub uninterp spec fn str_lower(s: &SpecString) -> SpecString;

#[verifier::external_body]
pub fn exec_str_lower(s: &String) -> (res: String)
    ensures res.deep_view() == str_lower(&s.deep_view())
{
    s.to_lowercase()
}

impl Clone for ExecAttribute {
    fn clone(&self) -> (res: Self)
        ensures res.deep_view() == self.deep_view()
    {
        ExecAttribute {
            oid: self.oid.clone(),
            value: self.value.clone(),
        }
    }
}

pub open spec fn normalize_string(s: &SpecString) -> SpecString {
    issue::spec_normalize_string(*s)
}

pub fn exec_normalize_string(s: &String) -> (res: String)
    ensures res.deep_view() == normalize_string(&s.deep_view())
{
    issue::normalize_string(s.as_str())
}

pub open spec fn starts_with(s: &SpecString, r: &SpecString) -> bool {
    s.len() >= r.len() && s.take(r.len() as int) == r
}

#[verifier::external_body]
#[inline(always)]
pub fn exec_starts_with(s: &String, r: &String) -> (res: bool)
    ensures res.deep_view() == starts_with(&s.deep_view(), &r.deep_view())
{
    s.starts_with(r)
}

pub open spec fn ends_with(s: &SpecString, r: &SpecString) -> bool {
    s.len() >= r.len() && s.skip(s.len() - r.len()) == r
}

#[verifier::external_body]
#[inline(always)]
pub fn exec_ends_with(s: &String, r: &String) -> (res: bool)
    ensures res.deep_view() == ends_with(&s.deep_view(), &r.deep_view())
{
    s.ends_with(r)
}

pub open spec fn bv_and_u8(a: &u8, b: &u8) -> u8 { *a & *b }
pub fn exec_bv_and_u8(a: &u8, b: &u8) -> (res: u8)
    ensures res.deep_view() == bv_and_u8(&a.deep_view(), &b.deep_view())
{ *a & *b }

impl Clone for ExecTask {
    fn clone(&self) -> (res: Self)
        ensures res.deep_view() == self.deep_view()
    {
        ExecTask {
            hostname: match &self.hostname {
                Some(hostname) => Some(hostname.clone()),
                None => None,
            },
            purpose: self.purpose,
            now: self.now,
        }
    }
}

} // verus!
