#![allow(unused_parens)]
#![allow(unexpected_cfgs)]

#[cfg(not(feature = "trace"))]
use verdict_rspec::rspec;
#[cfg(feature = "trace")]
use verdict_rspec::rspec_trace as rspec;
use verdict_rspec_lib::*;
use vstd::prelude::*;

use super::common::*;

verus! {

pub use internal::ExecPolicy as OpenSSLPolicy;

impl Policy for OpenSSLPolicy {
    closed spec fn spec_likely_issued(&self, issuer: Certificate, subject: Certificate) -> bool {
        internal::likely_issued(&issuer, &subject)
    }

    fn likely_issued(&self, issuer: &ExecCertificate, subject: &ExecCertificate) -> (res: bool) {
        internal::exec_likely_issued(issuer, subject)
    }

    closed spec fn spec_valid_chain(&self, chain: Seq<Certificate>, task: Task) -> bool {
        internal::valid_chain(&self.deep_view(), &chain, &task)
    }

    fn valid_chain(&self, chain: &Vec<&ExecCertificate>, task: &ExecTask) -> bool {
        internal::exec_valid_chain(self, chain, task)
    }
}

// Automatically prove some standard requirements
// Unchecked rules are commented out
standard::auto_std! {
    OpenSSLPolicy => standard::NoExpiration {}
    OpenSSLPolicy => standard::OuterInnerSigMatch {}
    OpenSSLPolicy => standard::KeyUsageNonEmpty {}

    // OpenSSLPolicy => standard::IssuerSubjectUIDVersion {}

    OpenSSLPolicy => standard::PathLenNonNegative {}
    OpenSSLPolicy => standard::PathLenConstraint {}
    OpenSSLPolicy => standard::NonLeafMustBeCA {}
    OpenSSLPolicy => standard::NonLeafHasKeyCertSign {}
    OpenSSLPolicy => standard::NonEmptySAN {}

    OpenSSLPolicy => standard::AKINonCritical {}

    // Only checked for V3
    // OpenSSLPolicy => standard::NonRootHasAKI {}
    // OpenSSLPolicy => standard::NonLeafHasSKI {}

    OpenSSLPolicy => standard::EmptySubjectImpliesCriticalSAN {}

    OpenSSLPolicy => standard::NonCriticalRootSKI {}
    // OpenSSLPolicy => standard::RootCAHasAKI {}
    // OpenSSLPolicy => standard::RootCAAKINoIssuerOrSerial {}
    // OpenSSLPolicy => standard::LeafHasEKU {}
    // OpenSSLPolicy => standard::RootHasNoEKU {}

    // OpenSSLPolicy => standard::NoDSA {}

    // This can be configured in OpenSSL, however
    // OpenSSLPolicy => standard::RSA2048 {}
}

impl OpenSSLPolicy {
    /// Create a Firefox policy with the same settings in Hammurabi
    pub fn default() -> Self {
        OpenSSLPolicy
    }
}

mod internal {

use super::*;

rspec! {

use ExecAttribute as Attribute;
use ExecGeneralName as GeneralName;
use ExecSubjectKey as SubjectKey;
use ExecExtendedKeyUsageType as ExtendedKeyUsageType;
use ExecExtendedKeyUsage as ExtendedKeyUsage;
use ExecBasicConstraints as BasicConstraints;
use ExecKeyUsage as KeyUsage;
use ExecSubjectAltName as SubjectAltName;
use ExecNameConstraints as NameConstraints;
use ExecCertificatePolicies as CertificatePolicies;
use ExecCertificate as Certificate;
use ExecPurpose as Purpose;
use ExecTask as Task;
use ExecPolicyError as PolicyError;
use ExecDistinguishedName as DistinguishedName;

use exec_str_lower as str_lower;
use exec_match_name as match_name;
use exec_check_auth_key_id as check_auth_key_id;
use exec_is_subtree_of as is_subtree_of;
use exec_permit_name as permit_name;
use exec_clone_dn as clone_dn;
use exec_clone_string as clone_string;
use exec_same_dn as same_dn;
use exec_ip_addr_in_range as ip_addr_in_range;
use exec_check_duplicate_extensions as check_duplicate_extensions;
use exec_starts_with as starts_with;

pub struct Policy;

// Some global assumptions/settings
// - Purpose is set to X509_PURPOSE_SSL_SERVER
// - X509_V_FLAG_X509_STRICT is true
// - X509_V_FLAG_POLICY_CHECK is false
// - X509_V_FLAG_CRL_CHECK is false
// - X509_V_FLAG_SUITEB_128_LOS is false
// - X509_V_FLAG_ALLOW_PROXY_CERTS is false
// - OPENSSL_NO_RFC3779 is false at compile time (this is for IP and AS ids)
// - self-issued intermediate CAs are not yet supported
// - EXFLAG_PROXY is false
// - ctx->param->auth_level = 0

/// https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L3633
/// ctx->param->auth_level = 0 requires the number of estimated security bits >= 80
/// (https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L3599)
pub open spec fn check_cert_key_level(cert: &Certificate) -> bool
{
    match cert.subject_key {
        // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/rsa/rsa_lib.c#L322
        // 1024 => 80 security bits
        SubjectKey::RSA { mod_length } => mod_length >= 1024,

        // TODO: EC and DSA security levels
        _ => true,
    }
}

/// https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L1785
pub open spec fn check_cert_time(cert: &Certificate, now: u64) -> bool
{
    // NOTE: X509_cmp_time(a, b) returns
    // 1 iff a > b
    // -1 if a <= b
    //
    // ossl_x509_check_cert_time checks that
    // X509_cmp_time(not_before, now) == -1 ==> not_before <= now
    // X509_cmp_time(not_after, now) == 1 ==> not_after > now
    &&& cert.not_before <= now
    &&& cert.not_after > now
}

/// https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/v3_purp.c#L653
/// 0: not CA
/// 1: CA
/// 2: all other cases
pub open spec fn check_ca(cert: &Certificate) -> u32
{
    if &cert.ext_key_usage matches Some(key_usage) && !key_usage.key_cert_sign {
        0
    } else if &cert.ext_basic_constraints matches Some(bc) && bc.is_ca {
        1
    } else if &cert.ext_basic_constraints matches Some(bc) && !bc.is_ca {
        0
    } else if cert.version == 1 || &cert.ext_key_usage matches Some(..) {
        2
    } else {
        0
    }
}

/// https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L584-L593
pub open spec fn check_basic_constraints(cert: &Certificate) -> bool
{
    &cert.ext_basic_constraints matches Some(bc) ==> {
        &&& bc.path_len matches Some(..) ==> {
            &&& bc.is_ca
            &&& &cert.ext_key_usage matches Some(key_usage)
            &&& key_usage.key_cert_sign
        }
        &&& bc.is_ca ==> (bc.critical matches Some(c) && c)
    }
}

/// https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L594-L601
pub open spec fn check_key_usage(cert: &Certificate) -> bool
{
    if &cert.ext_basic_constraints matches Some(bc) && bc.is_ca {
        cert.ext_key_usage matches Some(..)
    } else {
        &cert.ext_key_usage matches Some(usage) ==> !usage.key_cert_sign
    }
}

// https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L615-L618
pub open spec fn check_san(cert: &Certificate) -> bool
{
    &cert.ext_subject_alt_name matches Some(san) ==> san.names.len() != 0
}

pub open spec fn check_auth_subject_key_id(cert: &Certificate, is_root: bool, is_leaf: bool) -> bool
{
    // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L622-L627
    &&& &cert.ext_authority_key_id matches Some(akid) ==> !match akid.critical { Some(t) => t, None => false }
    &&& &cert.ext_subject_key_id matches Some(skid) ==> !match skid.critical { Some(t) => t, None => false }

    // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L628-L642
    &&& if cert.version >= 2 {
        &&& !is_root ==> (&cert.ext_authority_key_id matches Some(akid) && akid.key_id matches Some(..))
        &&& !is_leaf ==> &cert.ext_subject_key_id matches Some(..)
    } else {
        &&& cert.all_exts matches None
        &&& cert.ext_authority_key_id matches None
        &&& cert.ext_subject_key_id matches None
        &&& cert.ext_extended_key_usage matches None
        &&& cert.ext_basic_constraints matches None
        &&& cert.ext_key_usage matches None
        &&& cert.ext_subject_alt_name matches None
        &&& cert.ext_name_constraints matches None
        &&& cert.ext_certificate_policies matches None
        &&& cert.ext_authority_info_access matches None
    }
}

/// nc_dns: https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/v3_ncons.c#L629
pub open spec fn match_dns_name(pattern: &SpecString, name: &SpecString) -> bool {
    ||| pattern.len() == 0
    ||| {
        &&& name.len() > pattern.len()
        &&& name.char_at(name.len() - pattern.len() - 1) == '.' || pattern.char_at(0) == '.'
        &&& &name.skip(name.len() - pattern.len()) == pattern
    }
    ||| name.len() == pattern.len() && &str_lower(pattern) == &str_lower(name)
}

/// nc_match_single: https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/v3_ncons.c#L570
/// NOTE: we only support DNSName and DirectoryName for now
pub open spec fn is_general_subtree_of(name1: &GeneralName, name2: &GeneralName) -> bool {
    match (name1, name2) {
        (GeneralName::DNSName(name1), GeneralName::DNSName(name2)) => match_dns_name(name1, name2),
        (GeneralName::DirectoryName(name1), GeneralName::DirectoryName(name2)) => is_subtree_of(name1, name2, true),
        (GeneralName::IPAddr(range), GeneralName::IPAddr(addr)) => ip_addr_in_range(range, addr),
        _ => false,
    }
}

/// Check if `nc.permitted` has the same general name type as `name`
pub open spec fn has_general_name_constraint(name: &GeneralName, nc: &NameConstraints) -> bool {
    exists |i: usize| 0 <= i < nc.permitted.len() && {
        match (name, #[trigger] &nc.permitted[i as int]) {
            (GeneralName::DNSName(..), GeneralName::DNSName(..)) => true,
            (GeneralName::DirectoryName(..), GeneralName::DirectoryName(..)) => true,
            (GeneralName::IPAddr(..), GeneralName::IPAddr(..)) => true,
            _ => false,
        }
    }
}

/// https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/v3_ncons.c#L501
pub open spec fn nc_match(name: &GeneralName, nc: &NameConstraints) -> bool
{
    let permitted_enabled = has_general_name_constraint(name, nc);

    &&& !(name matches GeneralName::OtherName)

    &&& permitted_enabled ==>
            exists |j: usize| 0 <= j < nc.permitted.len() &&
                is_general_subtree_of(#[trigger] &nc.permitted[j as int], &name)

    // Not explicitly excluded
    &&& forall |j: usize| 0 <= j < nc.excluded.len() ==>
            !is_general_subtree_of(#[trigger] &nc.excluded[j as int], &name)
}

/// https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/v3_ncons.c#L331-L336
pub open spec fn check_san_constraints(san: &SubjectAltName, nc: &NameConstraints) -> bool
{
    forall |i: usize| 0 <= i < san.names.len() ==>
        nc_match(#[trigger] &san.names[i as int], &nc)
}

/// NAME_CONSTRAINTS_check_CN
/// https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/v3_ncons.c#L438C5-L438C30
pub open spec fn check_common_name_constraints(cert: &Certificate, nc: &NameConstraints) -> bool
{
    forall |i: usize| #![trigger cert.subject.0[i as int]] 0 <= i < cert.subject.0.len() ==>
    forall |j: usize| #![trigger cert.subject.0[i as int][j as int]] 0 <= j < cert.subject.0[i as int].len() ==> {
        let name = &cert.subject.0[i as int][j as int];

        &name.oid == "2.5.4.3"@ // CN
        ==> nc_match(&GeneralName::DNSName(clone_string(&name.value)), &nc)
    }
}

/// Check if there is any DNS name in SAN
pub open spec fn check_san_has_dns(cert: &Certificate) -> bool
{
    &&& &cert.ext_subject_alt_name matches Some(san)
    &&& exists |i: usize| 0 <= i < san.names.len() &&
            #[trigger] san.names[i as int] matches GeneralName::DNSName(..)
}

/// min(a + b, usize::MAX)
pub open spec fn add_usize(a: usize, b: usize) -> usize
{
    if a <= usize::MAX - b {
        (a + b) as usize
    } else {
        usize::MAX
    }
}

/// Sum of subject RDNs and SANs
pub open spec fn get_name_count(cert: &Certificate) -> usize
{
    let san_count = match &cert.ext_subject_alt_name {
        Some(san) => san.names.len(),
        None => 0,
    };

    add_usize(cert.subject.0.len() as usize, san_count as usize)
}

/// This check is a best-effort encoding of the two functions in OpenSSL:
/// - Name normalization: https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x_name.c#L310
/// - Comparison (directly done via memcmp): https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/v3_ncons.c#L615
/// NOTE that for normalization,
pub open spec fn check_name_constraints_helper(cert: &Certificate, nc: &NameConstraints, is_leaf: bool) -> bool
{
    // NOTE: no support for these
    // - Email name https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/v3_ncons.c#L310-L327
    // - nc_minmax_valid

    // Avoid expensive name constraints check
    // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/v3_ncons.c#L290-L296
    &&& {
        let name_count = get_name_count(cert);
        let constraint_count = add_usize(nc.permitted.len() as usize, nc.excluded.len() as usize);
        name_count == 0 || constraint_count <= 1048576usize / name_count
    }

    &&& nc_match(&GeneralName::DirectoryName(clone_dn(&cert.subject)), nc)
    &&& &cert.ext_subject_alt_name matches Some(san) ==> check_san_constraints(san, nc)

    // In the case of a leaf certificate, OpenSSL checks if SAN has any DNS name (if it exists) if not, it checks CN
    // https://github.com/openssl/openssl/blob/b3bb214720f20f3b126ae4b9c330e9a48b835415/crypto/x509/x509_vfy.c#L843C35-L843C45
    &&& is_leaf ==> !check_san_has_dns(cert) ==> check_common_name_constraints(cert, nc)
}

/// https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L711
pub open spec fn check_name_constraints(chain: &Seq<ExecRef<Certificate>>) -> bool
{
    forall |i: usize| #![trigger chain[i as int]] 1 <= i < chain.len() ==>
        (&chain[i as int].ext_name_constraints matches Some(nc) ==>
        forall |j: usize| 0 <= j < i ==>
            // NameConstraints do not apply to self-issued certificates
            !same_dn(&chain[j as int].subject, &chain[j as int].issuer, true) ==>
            check_name_constraints_helper(#[trigger] &chain[j as int], &nc, j == 0))
}

/// Check for purpose == X509_PURPOSE_SSL_SERVER, i.e. special case of the following calls
/// - check_purpose: https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L462
/// - X509_check_purpose: https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/v3_purp.c#L86
/// - check_purpose_ssl_server: https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/v3_purp.c#L736
/// Assuming X509_check_trust returns X509_TRUST_UNTRUSTED
/// XKU_SGC is not supported
pub open spec fn check_purpose(cert: &Certificate, is_leaf: bool) -> bool
{
    &&& &cert.ext_extended_key_usage matches Some(eku) ==>
        exists |i: usize| 0 <= i < eku.usages.len() &&
            (#[trigger] &eku.usages[i as int] matches ExtendedKeyUsageType::ServerAuth)

    &&& if is_leaf {
        // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/v3_purp.c#L733
        &cert.ext_key_usage matches Some(ku) ==>
            ku.digital_signature || ku.key_encipherment || ku.key_agreement
    } else {
        // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/v3_purp.c#L702
        check_ca(cert) == 1
    }
}

/// Check for critical extensions unsupported by Chrome
/// https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/v3_purp.c#L270
pub open spec fn check_unhandled_extensions(cert: &Certificate) -> bool {
    &cert.all_exts matches Some(all_exts) ==>
    forall |i: usize| #![trigger all_exts[i as int]]
        0 <= i < all_exts.len() ==>
        (all_exts[i as int].critical matches Some(c) && c) ==>
        {
            ||| &all_exts[i as int].oid == "2.16.840.1.113730.1.1"@ // NetscapeCertType
            ||| &all_exts[i as int].oid == "2.5.29.15"@ // KeyUsage
            ||| &all_exts[i as int].oid == "2.5.29.17"@ // SubjectAltName
            ||| &all_exts[i as int].oid == "2.5.29.19"@ // BasicConstraints
            ||| &all_exts[i as int].oid == "2.5.29.32"@ // CertificatePolicies
            ||| &all_exts[i as int].oid == "2.5.29.31"@ // CRLDistributionPoints
            ||| &all_exts[i as int].oid == "2.5.29.37"@ // ExtendedKeyUsage
            // NOTE: Assuming no OPENSSL_NO_RFC3779
            // ||| &all_exts[i as int].oid == "1.3.6.1.5.5.7.1.7"@ // SbgpIpAddrBlock
            // ||| &all_exts[i as int].oid == "1.3.6.1.5.5.7.1.8"@ // SbgpAutonomousSysNum
            ||| &all_exts[i as int].oid == "1.3.6.1.5.5.7.48.1.5"@ // OCSPNoCheck
            ||| &all_exts[i as int].oid == "2.5.29.36"@ // PolicyConstraints
            ||| &all_exts[i as int].oid == "1.3.6.1.5.5.7.1.14"@ // ProxyCertInfo
            ||| &all_exts[i as int].oid == "2.5.29.30"@ // NameConstraints
            ||| &all_exts[i as int].oid == "2.5.29.33"@ // PolicyMappings
            ||| &all_exts[i as int].oid == "2.5.29.54"@ // InhibitAnyPolicy
        }
}

/// Common checks for certificates, this includes checks in
/// - check_extensions: https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L1785
pub open spec fn valid_cert_common(_env: &Policy, task: &Task, cert: &Certificate, is_leaf: bool, is_root: bool, depth: usize) -> bool
{
    // NOTE: unhandled critical extensions not checked
    // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L543-L545

    &&& check_cert_key_level(cert)
    &&& check_cert_time(cert, task.now)
    &&& check_basic_constraints(cert)
    &&& check_key_usage(cert)

    // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L551C45-L553
    &&& if is_leaf {
        check_ca(cert) != 2
    } else {
        check_ca(cert) == 1
    }

    // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L602-L614
    &&& cert.issuer.0.len() != 0
    &&& cert.subject.0.len() == 0 ==> {
        &&& &cert.ext_subject_alt_name matches Some(san)
        &&& san.names.len() != 0
        &&& san.critical matches Some(c) && c
        &&& &cert.ext_basic_constraints matches Some(bc) ==> !bc.is_ca
        &&& &cert.ext_key_usage matches Some(ku) ==> !ku.key_cert_sign
    }

    &&& check_san(cert)

    // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L619-L621
    &&& &cert.sig_alg_inner.bytes == &cert.sig_alg_outer.bytes

    // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L645-L647
    &&& check_purpose(cert, is_leaf)

    &&& check_auth_subject_key_id(cert, is_root, is_leaf)

    // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/v3_purp.c#L443-L444
    &&& &cert.ext_basic_constraints matches Some(bc) ==>
        (bc.path_len matches Some(path_len) ==> path_len >= 0)

    // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L648-L651
    &&& !is_leaf ==>
        (&cert.ext_basic_constraints matches Some(bc) ==>
        (bc.path_len matches Some(path_len) ==> depth <= path_len as usize))

    // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L543-L545
    &&& check_unhandled_extensions(cert)

    &&& check_duplicate_extensions(cert)
}

/// Part of valid_star
/// https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/v3_utl.c#L742
pub open spec fn check_valid_pattern(pattern: &SpecString) -> bool {
    if starts_with(pattern, &"*."@) {
        // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/v3_utl.c#L800
        pattern.len() >= 2 && pattern.skip(2).has_char('.')
    } else {
        true
    }
}

/// Check if the given hostname is specified in the leaf certificate
/// https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/v3_utl.c#L1007
pub open spec fn check_hostname(cert: &Certificate, hostname: &SpecString) -> bool {
    // NOTE: case-insensitivity is set here
    // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/v3_utl.c#L901
    let hostname = str_lower(hostname);

    // Check SAN
    // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/v3_utl.c#L912-L914
    ||| &cert.ext_subject_alt_name matches Some(san) &&
        exists |i: usize|
            0 <= i < san.names.len() && {
                &&& #[trigger] &san.names[i as int] matches GeneralName::DNSName(dns_name)
                &&& check_valid_pattern(dns_name)
                &&& match_name(&str_lower(dns_name), &hostname)
            }

    // Check CN
    // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/v3_utl.c#L994-L995
    //
    // NOTE: by this line, CN is only checked if there is no DNS name in SAN
    // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/v3_utl.c#L985
    ||| !check_san_has_dns(cert) &&
            exists |i: usize| #![trigger cert.subject.0[i as int]]
                0 <= i < cert.subject.0.len() &&
            exists |j: usize| #![trigger cert.subject.0[i as int][j as int]]
                0 <= j < cert.subject.0[i as int].len() &&
                {
                    let name = &cert.subject.0[i as int][j as int];
                    &&& &name.oid == "2.5.4.3"@ // common name
                    &&& check_valid_pattern(&name.value)
                    &&& match_name(&str_lower(&name.value), &hostname)
                }
}

pub open spec fn valid_leaf(env: &Policy, task: &Task, cert: &Certificate) -> bool {
    valid_cert_common(env, task, cert, true, false, 0)
}

pub open spec fn valid_intermediate(env: &Policy, task: &Task, cert: &Certificate, depth: usize) -> bool {
    valid_cert_common(env, task, cert, false, false, depth)
}

pub open spec fn valid_root(env: &Policy, task: &Task, cert: &Certificate, depth: usize) -> bool {
    &&& valid_cert_common(env, task, cert, false, true, depth)

    // // Per x509-limbo::webpki::aki::root-with-aki-*
    // &&& &cert.ext_authority_key_id matches Some(aki) ==>
    //     (aki.issuer matches None) == (aki.serial matches None)
}

/// chain[0] is the leaf, and assume chain[i] is issued by chain[i + 1] for all i < chain.len() - 1
/// chain.last() must be a trusted root
pub open spec fn valid_chain(env: &Policy, chain: &Seq<ExecRef<Certificate>>, task: &Task) -> bool
{
    chain.len() >= 2 && {
        &&& valid_leaf(env, task, &chain[0])
        &&& forall |i: usize| 1 <= i < chain.len() - 1 ==> valid_intermediate(&env, &task, #[trigger] &chain[i as int], (i - 1) as usize)
        &&& valid_root(env, task, &chain[chain.len() - 1], (chain.len() - 2) as usize)
        &&& check_name_constraints(chain)
        &&& &task.hostname matches Some(hostname) ==> check_hostname(&chain[0], hostname)
    }
}

pub open spec fn likely_issued(issuer: &Certificate, subject: &Certificate) -> bool
{
    &&& same_dn(&issuer.subject, &subject.issuer, true)
    &&& check_auth_key_id(issuer, subject)
}

} // rspec!

pub open spec fn clone_dn(name: &DistinguishedName) -> DistinguishedName {
    *name
}

#[verifier::external_body]
fn exec_clone_dn(name: &ExecDistinguishedName) -> (res: ExecDistinguishedName)
    ensures res.deep_view() == name.deep_view()
{
    ExecDistinguishedName(name.0.clone())
}

pub open spec fn clone_string(name: &SpecString) -> SpecString {
    *name
}

fn exec_clone_string(name: &String) -> (res: String)
    ensures res == *name
{
    name.clone()
}

} // mod internal

}
