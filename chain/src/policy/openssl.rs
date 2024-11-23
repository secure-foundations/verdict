use vstd::prelude::*;
use rspec::rspec;
use rspec_lib::*;

use super::common::*;

verus! {

rspec! {

use ExecDirectoryName as DirectoryName;
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
use ExecPolicyResult as PolicyResult;

use exec_str_lower as str_lower;
use exec_match_name as match_name;
use exec_check_auth_key_id as check_auth_key_id;
use exec_is_subtree_of as is_subtree_of;
use exec_permit_name as permit_name;

pub struct Environment {
    pub time: u64,
}

// Some global assumptions/settings
// - X509_V_FLAG_X509_STRICT is true
// - X509_V_FLAG_POLICY_CHECK is false
// - X509_V_FLAG_CRL_CHECK is false
// - OPENSSL_NO_RFC3779 is false at compile time (this is for IP and AS ids)
// - EXFLAG_PROXY is false; no proxy certificates

/// https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L3633
/// Assuming ctx->param->auth_level = 0,
/// which requires the number of estimated security bits >= 80
/// (https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L3599)
pub open spec fn check_cert_key_level(cert: &Certificate) -> bool
{
    match cert.subject_key {
        // https://github.com/openssl/openssl/blob/ea5817854cf67b89c874101f209f06ae016fd333/crypto/rsa/rsa_lib.c#L322
        // 1024 => 80 security bits
        SubjectKey::RSA { mod_length } => mod_length >= 1024,

        // TODO: EC and DSA security levels
        _ => true,
    }
}

/// https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L1785
pub open spec fn check_cert_time(env: &Environment, cert: &Certificate) -> bool
{
    &&& cert.not_before < env.time
    &&& cert.not_after > env.time
}

/// https://github.com/openssl/openssl/blob/ea5817854cf67b89c874101f209f06ae016fd333/crypto/x509/v3_purp.c#L653
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
    } else if cert.version == 1 || &cert.ext_key_usage matches Some(key_usage) {
        2
    } else {
        0
    }
}

/// https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L584-L593
pub open spec fn check_basic_constraints(cert: &Certificate) -> bool
{
    &cert.ext_basic_constraints matches Some(bc) ==> {
        &&& bc.path_len matches Some(path_len) ==> {
            &&& !bc.is_ca
            &&& &cert.ext_key_usage matches Some(key_usage)
            &&& key_usage.key_cert_sign
        }
        &&& bc.is_ca ==> bc.critical
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

/// Common checks for certificates, this includes checks in
/// - check_extensions: https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L1785
pub open spec fn valid_cert_common(env: &Environment, cert: &Certificate, is_leaf: bool, is_root: bool, depth: usize) -> bool
{
    // TODO: unhandled critical extensions
    // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L543-L545

    &&& check_cert_key_level(cert)
    &&& check_cert_time(env, cert)
    &&& check_basic_constraints(cert)
    &&& check_key_usage(cert)

    // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L551C45-L553
    &&& if is_leaf {
        check_ca(cert) != 2
    } else {
        check_ca(cert) == 1
    }

    // TODO: https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L602-L614

    // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L615-L618
    &&& &cert.ext_subject_alt_name matches Some(san) ==> san.names.len() != 0

    // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L619-L621
    &&& &cert.sig_alg_inner.bytes == &cert.sig_alg_outer.bytes

    // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L622-L627
    &&& &cert.ext_authority_key_id matches Some(akid) ==> !akid.critical
    &&& &cert.ext_subject_key_id matches Some(skid) ==> !skid.critical

    // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L628-L642
    &&& if cert.version >= 3 {
        &&& !is_root ==> (&cert.ext_authority_key_id matches Some(akid) && akid.key_id matches Some(..))
        &&& (&cert.ext_basic_constraints matches Some(bc) && bc.is_ca) ==> &cert.ext_subject_key_id matches Some(..)
    } else {
        cert.all_exts matches None
    }

    // TODO: https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L645-L647

    // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L648-L651
    &&& !is_leaf ==>
        (&cert.ext_basic_constraints matches Some(bc) ==>
        (bc.path_len matches Some(path_len) ==> depth as i64 <= path_len))

    // TODO: handle intermediate self-issued cert?
    // https://github.com/openssl/openssl/blob/5c5b8d2d7c59fc48981861629bb0b75a03497440/crypto/x509/x509_vfy.c#L652
}

pub open spec fn valid_leaf(env: &Environment, cert: &Certificate) -> bool {
    &&& valid_cert_common(env, cert, true, false, 0)
    // TODO
}

pub open spec fn valid_intermediate(env: &Environment, cert: &Certificate, leaf: &Certificate, depth: usize) -> bool {
    &&& valid_cert_common(env, cert, false, false, depth)
    // TODO
}

pub open spec fn valid_root(env: &Environment, cert: &Certificate, leaf: &Certificate, depth: usize) -> bool {
    &&& valid_cert_common(env, cert, false, true, depth)
    // TODO
}

/// chain[0] is the leaf, and assume chain[i] is issued by chain[i + 1] for all i < chain.len() - 1
/// chain.last() must be a trusted root
pub open spec fn valid_chain(env: &Environment, chain: &Seq<Certificate>, task: &Task) -> PolicyResult
{
    match task {
        Task::ChainValidation(Purpose::ServerAuth) => {
            if chain.len() >= 2 && {
                let leaf = &chain[0];
                let root = &chain[chain.len() - 1];

                &&& forall |i: usize| 0 <= i < chain.len() - 1 ==> check_auth_key_id(&chain[i + 1], #[trigger] &chain[i as int])
                &&& valid_leaf(env, leaf)
                &&& forall |i: usize| 1 <= i < chain.len() - 1 ==> valid_intermediate(&env, #[trigger] &chain[i as int], &leaf, (i - 1) as usize)
                &&& valid_root(env, root, leaf, (chain.len() - 2) as usize)
            } {
                PolicyResult::Valid
            } else {
                PolicyResult::Invalid
            }
        }

        _ => PolicyResult::UnsupportedTask,
    }
}

}

}
