/// Conversion from the more concrete CertificateValue to policy::Certificate

use vstd::prelude::*;

use chrono::NaiveDate;

use verdict_polyfill::*;
use verdict_parser::{*, asn1::*, x509::*};

use crate::policy;
use crate::hash;
use crate::error::*;

verus! {

/// A macro to find the first occurrence of an extension with the given OID
/// and then abstract it using the given function
#[allow(unused_macros)]
macro_rules! spec_get_extension {
    ($cert: expr, $oid: ident, $converter: expr) => {
        if let Some(ext) = Self::spec_get_extension($cert, spec_oid!($oid)) {
            Self::map_some($converter(ext))
        } else {
            Some(None)
        }
    }
}

/// Used for error handling in specs
#[allow(unused_macros)]
macro_rules! if_let {
    ($body:expr) => {
        ::builtin_macros::verus_proof_expr! { $body }
    };

    (let $pat:pat = $opt:expr; $(let $rest_pat:pat = $rest_opt:expr;)* $body:expr) => {
        #[allow(irrefutable_let_patterns)]
        if let $pat = ::builtin_macros::verus_proof_expr! { $opt } {
            if_let!($(let $rest_pat = $rest_opt;)* { $body })
        } else {
            None
        }
    };
}

impl policy::Certificate {
    /// Convert a more concrete parsed certificate to
    /// an abstract certificate to be used in a policy
    pub open spec fn spec_from(c: SpecCertificateValue) -> Option<policy::Certificate> {
        if_let! {
            let Ok(ser_cert) = ASN1(CertificateInner).view().spec_serialize(c);

            let Ok(sig_alg_outer) = ASN1(AlgorithmIdentifier).view().spec_serialize(c.sig_alg);
            let Ok(sig_alg_inner) = ASN1(AlgorithmIdentifier).view().spec_serialize(c.cert.signature);

            let Some(not_after) = Self::spec_time_to_timestamp(c.cert.validity.not_after);
            let Some(not_before) = Self::spec_time_to_timestamp(c.cert.validity.not_before);
            let Some(subject_key) = policy::SubjectKey::spec_from(c.cert.subject_key);

            let Some(ext_authority_key_id) = spec_get_extension!(c, AUTH_KEY_IDENT, policy::AuthorityKeyIdentifier::spec_from);
            let Some(ext_subject_key_id) = spec_get_extension!(c, SUBJECT_KEY_IDENT, policy::SubjectKeyIdentifier::spec_from);
            let Some(ext_extended_key_usage) = spec_get_extension!(c, EXTENDED_KEY_USAGE, policy::ExtendedKeyUsage::spec_from);
            let Some(ext_basic_constraints) = spec_get_extension!(c, BASIC_CONSTRAINTS, policy::BasicConstraints::spec_from);
            let Some(ext_key_usage) = spec_get_extension!(c, KEY_USAGE, policy::KeyUsage::spec_from);
            let Some(ext_subject_alt_name) = spec_get_extension!(c, SUBJECT_ALT_NAME, policy::SubjectAltName::spec_from);
            let Some(ext_name_constraints) = spec_get_extension!(c, NAME_CONSTRAINTS, policy::NameConstraints::spec_from);
            let Some(ext_certificate_policies) = spec_get_extension!(c, CERT_POLICIES, policy::CertificatePolicies::spec_from);
            let Some(ext_authority_info_access) = spec_get_extension!(c, AUTH_INFO_ACCESS, policy::AuthorityInfoAccess::spec_from);

            Some(policy::Certificate {
                fingerprint: hash::spec_to_hex_upper(hash::spec_sha256_digest(ser_cert)),
                version: c.cert.version as u32,
                serial: hash::spec_to_hex_upper(c.cert.serial),

                sig_alg_outer: policy::SignatureAlgorithm {
                    id: Self::spec_oid_to_string(c.sig_alg.id),
                    bytes: hash::spec_to_hex_upper(sig_alg_outer),
                },
                sig_alg_inner: policy::SignatureAlgorithm {
                    id: Self::spec_oid_to_string(c.cert.signature.id),
                    bytes: hash::spec_to_hex_upper(sig_alg_inner),
                },

                not_after: not_after as u64,
                not_before: not_before as u64,

                issuer: policy::DistinguishedName::spec_from(c.cert.issuer),
                subject: policy::DistinguishedName::spec_from(c.cert.subject),
                subject_key,

                issuer_uid: if let OptionDeep::Some(uid) = c.cert.issuer_uid {
                    Some(hash::spec_to_hex_upper(BitStringValue::spec_bytes(uid)))
                } else {
                    None
                },
                subject_uid: if let OptionDeep::Some(uid) = c.cert.subject_uid {
                    Some(hash::spec_to_hex_upper(BitStringValue::spec_bytes(uid)))
                } else {
                    None
                },

                ext_authority_key_id,
                ext_subject_key_id,
                ext_extended_key_usage,
                ext_basic_constraints,
                ext_key_usage,
                ext_subject_alt_name,
                ext_name_constraints,
                ext_certificate_policies,
                ext_authority_info_access,

                all_exts: if let OptionDeep::Some(exts) = c.cert.extensions {
                    Some(Self::spec_from_exts(exts))
                } else {
                    None
                },
            })
        }
    }

    /// Exec version of spec_from
    pub fn from(c: &CertificateValue<'_>) -> (res: Result<policy::ExecCertificate, ValidationError>)
        ensures
            res matches Ok(res) ==> Some(res.deep_view()) =~= Self::spec_from(c@),
    {
        let not_after = Self::time_to_timestamp(&c.get().cert.get().validity.not_after)
            .ok_or(ValidationError::TimeParseError)?;

        let not_before = Self::time_to_timestamp(&c.get().cert.get().validity.not_before)
            .ok_or(ValidationError::TimeParseError)?;

        if not_after < 0 || not_before < 0 {
            return Err(ValidationError::TimeParseError);
        }

        let subject_key = policy::SubjectKey::from(&c.get().cert.get().subject_key)?;

        let ext_authority_key_id = if let Some(ext) = Self::get_extension(c, &oid!(AUTH_KEY_IDENT)) {
            Some(policy::AuthorityKeyIdentifier::from(ext)?)
        } else {
            None
        };

        let ext_subject_key_id = if let Some(ext) = Self::get_extension(c, &oid!(SUBJECT_KEY_IDENT)) {
            Some(policy::SubjectKeyIdentifier::from(ext)?)
        } else {
            None
        };

        let ext_extended_key_usage = if let Some(ext) = Self::get_extension(c, &oid!(EXTENDED_KEY_USAGE)) {
            Some(policy::ExtendedKeyUsage::from(ext)?)
        } else {
            None
        };

        let ext_basic_constraints = if let Some(ext) = Self::get_extension(c, &oid!(BASIC_CONSTRAINTS)) {
            Some(policy::BasicConstraints::from(ext)?)
        } else {
            None
        };

        let ext_key_usage = if let Some(ext) = Self::get_extension(c, &oid!(KEY_USAGE)) {
            Some(policy::KeyUsage::from(ext)?)
        } else {
            None
        };

        let ext_subject_alt_name = if let Some(ext) = Self::get_extension(c, &oid!(SUBJECT_ALT_NAME)) {
            Some(policy::SubjectAltName::from(ext)?)
        } else {
            None
        };

        let ext_name_constraints = if let Some(ext) = Self::get_extension(c, &oid!(NAME_CONSTRAINTS)) {
            Some(policy::NameConstraints::from(ext)?)
        } else {
            None
        };

        let ext_certificate_policies = if let Some(ext) = Self::get_extension(c, &oid!(CERT_POLICIES)) {
            Some(policy::CertificatePolicies::from(ext)?)
        } else {
            None
        };

        let ext_authority_info_access = if let Some(ext) = Self::get_extension(c, &oid!(AUTH_INFO_ACCESS)) {
            Some(policy::AuthorityInfoAccess::from(ext)?)
        } else {
            None
        };

        Ok(policy::ExecCertificate {
            fingerprint: hash::to_hex_upper(&hash::sha256_digest(c.serialize())),
            version: c.get().cert.get().version as u32,
            serial: hash::to_hex_upper(c.get().cert.get().serial.bytes()),

            sig_alg_outer: policy::ExecSignatureAlgorithm {
                id: Self::oid_to_string(&c.get().sig_alg.get().id),
                bytes: hash::to_hex_upper(c.get().sig_alg.serialize()),
            },
            sig_alg_inner: policy::ExecSignatureAlgorithm {
                id: Self::oid_to_string(&c.get().cert.get().signature.get().id),
                bytes: hash::to_hex_upper(c.get().cert.get().signature.serialize()),
            },

            not_after: not_after as u64,
            not_before: not_before as u64,

            issuer: policy::DistinguishedName::from(&c.get().cert.get().issuer),
            subject: policy::DistinguishedName::from(&c.get().cert.get().subject),
            subject_key,

            issuer_uid: if let OptionDeep::Some(uid) = &c.get().cert.get().issuer_uid {
                Some(hash::to_hex_upper(uid.bytes()))
            } else {
                None
            },
            subject_uid: if let OptionDeep::Some(uid) = &c.get().cert.get().subject_uid {
                Some(hash::to_hex_upper(uid.bytes()))
            } else {
                None
            },

            ext_authority_key_id,
            ext_subject_key_id,
            ext_extended_key_usage,
            ext_basic_constraints,
            ext_key_usage,
            ext_subject_alt_name,
            ext_name_constraints,
            ext_certificate_policies,
            ext_authority_info_access,

            all_exts: if let OptionDeep::Some(exts) = &c.get().cert.get().extensions {
                Some(Self::from_exts(exts))
            } else {
                None
            },
        })
    }

    /// Map the seq of extensions to a seq of policy::Extension
    pub open spec fn spec_from_exts(exts: Seq<SpecExtensionValue>) -> Seq<policy::Extension>
    {
        exts.map_values(|ext: SpecExtensionValue| policy::Extension {
            oid: Self::spec_oid_to_string(ext.id),
            critical: ext.critical.to_opt(),
        })
    }

    pub fn from_exts(exts: &VecDeep<ExtensionValue<'_>>) -> (res: Vec<policy::ExecExtension>)
        ensures res.deep_view() =~= Self::spec_from_exts(exts@),
    {
        vec_map(exts.to_vec(), |ext: &ExtensionValue<'_>| -> (res: policy::ExecExtension)
            ensures res.deep_view() == (policy::Extension {
                oid: Self::spec_oid_to_string(ext@.id),
                critical: ext.critical.to_opt(),
            })
        {
            policy::ExecExtension {
                oid: Self::oid_to_string(&ext.id),
                critical: PolyfillClone::clone(&ext.critical).to_opt(),
            }
        })
    }

    pub open spec fn spec_map_some<A>(opt: Option<A>) -> Option<Option<A>>
    {
        match opt {
            Some(a) => Some(Some(a)),
            None => None,
        }
    }

    #[verifier::when_used_as_spec(spec_map_some)]
    pub fn map_some<A>(opt: Option<A>) -> (res: Option<Option<A>>)
        ensures res == Self::spec_map_some(opt)
    {
        match opt {
            Some(a) => Some(Some(a)),
            None => None,
        }
    }

    /// Convert OID to a string by concatenating all arcs with '.'
    // pub closed spec fn spec_oid_to_string(oid: SpecObjectIdentifierValue) -> Seq<char>
    // {
    //     seq_join(Seq::new(oid.len(), |i| spec_u64_to_string(oid[i])), "."@)
    // }

    pub closed spec fn spec_oid_to_string(oid: SpecObjectIdentifierValue) -> Seq<char>
        decreases oid.len()
    {
        if oid.len() == 0 {
            seq![]
        } else if oid.len() == 1 {
            spec_u64_to_string(oid[0])
        } else {
            spec_u64_to_string(oid.first()) + "."@ + Self::spec_oid_to_string(oid.drop_first())
        }
    }

    /// Exec version of the above
    pub fn oid_to_string(oid: &ObjectIdentifierValue) -> (res: String)
        ensures res@ =~= Self::spec_oid_to_string(oid@)
    {
        // Estimate the number of characters needed to be 4 * number of arcs
        let oid_len = oid.0.len();
        let mut res = if oid_len <= usize::MAX / 4 { string_new_with_cap(oid_len * 3) }
            else { string_new() };

        assert(oid@.skip(0) == oid@);

        for i in 0..oid_len
            invariant
                oid_len == oid@.len(),

                Self::spec_oid_to_string(oid@) =~=
                    res@ + Self::spec_oid_to_string(oid@.skip(i as int))
        {
            let ghost prev_res = res@;
            u64_to_string_inplace(&mut res, *oid.0.get(i));

            if i + 1 != oid_len {
                string_push(&mut res, '.');
            }

            proof { reveal_strlit("."); }
            assert(oid@.skip(i as int).drop_first() == oid@.skip(i + 1));
        }

        res
    }

    pub closed spec fn spec_time_to_timestamp(time: SpecTimeValue) -> Option<i64>;

    /// Convert an X.509 Time to a UNIX timestamp
    /// NOTE: this implementation is unverified and trusted
    #[verifier::external_body]
    pub fn time_to_timestamp(time: &TimeValue<'_>) -> (res: Option<i64>)
        ensures res == Self::spec_time_to_timestamp(time@)
    {
        // Convert UTCTime/GeneralizedTime to chrono::NaiveDateTime
        let dt = match time {
            TimeValue::UTCTime(t) => {
                let date = NaiveDate::from_ymd_opt(t.year as i32, t.month as u32, t.day as u32)?;
                let naive = date.and_hms_opt(
                    t.hour as u32,
                    t.minute as u32,
                    *t.second.as_ref().unwrap_or(&0) as u32,
                )?;

                if let UTCTimeZone::UTC = t.time_zone {
                    naive.and_utc()
                } else {
                    return Option::None;
                }
            }
            TimeValue::GeneralizedTime(t) => {
                let date = NaiveDate::from_ymd_opt(t.year as i32, t.month as u32, t.day as u32)?;
                let naive = date.and_hms_opt(
                    t.hour as u32,
                    *t.minute.as_ref().unwrap_or(&0) as u32,
                    *t.second.as_ref().unwrap_or(&0) as u32,
                )?;

                if let GeneralizedTimeZone::UTC = t.time_zone {
                    naive.and_utc()
                } else {
                    return Option::None;
                }
            }

            TimeValue::Unreachable => return Option::None,
        };

        Option::Some(dt.timestamp())
    }

    /// Get the first extension with the given OID
    /// return (critical, param)
    pub open spec fn spec_get_extension(cert: SpecCertificateValue, oid: SpecObjectIdentifierValue) -> Option<SpecExtensionValue>
    {
        if let OptionDeep::Some(exts) = cert.cert.extensions {
            Self::spec_get_extension_helper(exts, oid)
        } else {
            None
        }
    }

    pub open spec fn spec_get_extension_helper(exts: Seq<SpecExtensionValue>, oid: SpecObjectIdentifierValue) -> Option<SpecExtensionValue>
        decreases exts.len()
    {
        if exts.len() == 0 {
            None
        } else {
            if exts[0].id =~= oid {
                Some(exts[0])
            } else {
                Self::spec_get_extension_helper(exts.drop_first(), oid)
            }
        }
    }

    /// Exec version of spec_get_extension
    pub fn get_extension<'a, 'b>(cert: &'b CertificateValue<'a>, oid: &ObjectIdentifierValue) -> (res: Option<&'b ExtensionValue<'a>>)
        ensures
            res matches Some(res) ==> Self::spec_get_extension(cert@, oid@) == Some(res@),
            res matches None ==> Self::spec_get_extension(cert@, oid@).is_none(),
    {
        if let OptionDeep::Some(exts) = &cert.get().cert.get().extensions {
            let len = exts.len();

            assert(exts@.skip(0) == exts@);

            for i in 0..len
                invariant
                    len == exts@.len(),
                    forall |j| #![auto] 0 <= j < i ==> exts@[j].id != oid@,
                    Self::spec_get_extension(cert@, oid@)
                        == Self::spec_get_extension_helper(exts@.skip(i as int), oid@),
            {
                if exts.get(i).id.polyfill_eq(oid) {
                    return Some(exts.get(i));
                }

                assert(exts@.skip(i as int).drop_first() == exts@.skip(i + 1));
            }

            None
        } else {
            None
        }
    }
}

impl policy::AuthorityKeyIdentifier {
    pub open spec fn spec_from(ext: SpecExtensionValue) -> Option<policy::AuthorityKeyIdentifier> {
        if_let! {
            let SpecExtensionParamValue::AuthorityKeyIdentifier(akid) = ext.param;
            Some(policy::AuthorityKeyIdentifier {
                critical: ext.critical.to_opt(),
                key_id: match akid.key_id {
                    OptionDeep::Some(key_id) => Some(hash::spec_to_hex_upper(key_id)),
                    OptionDeep::None => None,
                },
                issuer: match akid.auth_cert_issuer {
                    OptionDeep::Some(issuer) => Some(hash::spec_to_hex_upper(issuer)),
                    OptionDeep::None => None,
                },
                serial: match akid.auth_cert_serial {
                    OptionDeep::Some(serial) => Some(hash::spec_to_hex_upper(serial)),
                    OptionDeep::None => None,
                },
            })
        }
    }

    pub fn from(ext: &ExtensionValue<'_>) -> (res: Result<policy::ExecAuthorityKeyIdentifier, ValidationError>)
        ensures
            res matches Ok(res) ==> Some(res.deep_view()) =~= Self::spec_from(ext@),
    {
        if let ExtensionParamValue::AuthorityKeyIdentifier(akid) = &ext.param {
            Ok(policy::ExecAuthorityKeyIdentifier {
                critical: PolyfillClone::clone(&ext.critical).to_opt(),
                key_id: match akid.key_id {
                    OptionDeep::Some(key_id) => Some(hash::to_hex_upper(key_id)),
                    OptionDeep::None => None,
                },
                issuer: match akid.auth_cert_issuer {
                    OptionDeep::Some(issuer) => Some(hash::to_hex_upper(issuer)),
                    OptionDeep::None => None,
                },
                serial: match &akid.auth_cert_serial {
                    OptionDeep::Some(serial) => Some(hash::to_hex_upper(serial.bytes())),
                    OptionDeep::None => None,
                },
            })
        } else {
            Err(ValidationError::UnexpectedExtParam)
        }
    }
}

impl policy::SubjectKeyIdentifier {
    pub open spec fn spec_from(ext: SpecExtensionValue) -> Option<policy::SubjectKeyIdentifier> {
        if_let! {
            let SpecExtensionParamValue::SubjectKeyIdentifier(skid) = ext.param;
            Some(policy::SubjectKeyIdentifier {
                critical: ext.critical.to_opt(),
                key_id: hash::spec_to_hex_upper(skid),
            })
        }
    }

    pub fn from(ext: &ExtensionValue<'_>) -> (res: Result<policy::ExecSubjectKeyIdentifier, ValidationError>)
        ensures
            res matches Ok(res) ==> Some(res.deep_view()) =~= Self::spec_from(ext@),
    {
        if let ExtensionParamValue::SubjectKeyIdentifier(skid) = &ext.param {
            Ok(policy::ExecSubjectKeyIdentifier {
                critical: PolyfillClone::clone(&ext.critical).to_opt(),
                key_id: hash::to_hex_upper(skid),
            })
        } else {
            Err(ValidationError::UnexpectedExtParam)
        }
    }
}

impl policy::ExtendedKeyUsage {
    pub open spec fn spec_from(ext: SpecExtensionValue) -> Option<policy::ExtendedKeyUsage> {
        if_let! {
            let SpecExtensionParamValue::ExtendedKeyUsage(usages) = ext.param;
            Some(policy::ExtendedKeyUsage {
                critical: ext.critical.to_opt(),
                usages: usages.map_values(|oid| Self::spec_oid_to_key_usage_type(oid)),
            })
        }
    }

    pub fn from(ext: &ExtensionValue<'_>) -> (res: Result<policy::ExecExtendedKeyUsage, ValidationError>)
        ensures
            res matches Ok(res) ==> Some(res.deep_view()) =~= Self::spec_from(ext@),
    {
        if let ExtensionParamValue::ExtendedKeyUsage(usages) = &ext.param {
            let usage_types = vec_map(usages.to_vec(), |oid| -> (res: policy::ExecExtendedKeyUsageType)
                ensures res.deep_view() =~= Self::spec_oid_to_key_usage_type(oid@)
            {
                Self::oid_to_key_usage_type(oid)
            });

            assert(usage_types.deep_view() =~= usages@.map_values(|oid| Self::spec_oid_to_key_usage_type(oid)));

            Ok(policy::ExecExtendedKeyUsage {
                critical: PolyfillClone::clone(&ext.critical).to_opt(),
                usages: usage_types,
            })
        } else {
            Err(ValidationError::UnexpectedExtParam)
        }
    }

    pub open spec fn spec_oid_to_key_usage_type(oid: SpecObjectIdentifierValue) -> policy::ExtendedKeyUsageType {
        if oid == spec_oid!(SERVER_AUTH) {
            policy::ExtendedKeyUsageType::ServerAuth
        } else if oid == spec_oid!(CLIENT_AUTH) {
            policy::ExtendedKeyUsageType::ClientAuth
        } else if oid == spec_oid!(CODE_SIGNING) {
            policy::ExtendedKeyUsageType::CodeSigning
        } else if oid == spec_oid!(EMAIL_PROTECTION) {
            policy::ExtendedKeyUsageType::EmailProtection
        } else if oid == spec_oid!(TIME_STAMPING) {
            policy::ExtendedKeyUsageType::TimeStamping
        } else if oid == spec_oid!(OCSP_SIGNING) {
            policy::ExtendedKeyUsageType::OCSPSigning
        } else if oid == spec_oid!(EXTENDED_KEY_USAGE) {
            policy::ExtendedKeyUsageType::Any
        } else {
            policy::ExtendedKeyUsageType::Other(policy::Certificate::spec_oid_to_string(oid))
        }
    }

    pub fn oid_to_key_usage_type(oid: &ObjectIdentifierValue) -> (res: policy::ExecExtendedKeyUsageType)
        ensures res.deep_view() =~= Self::spec_oid_to_key_usage_type(oid@)
    {
        if oid.polyfill_eq(&oid!(SERVER_AUTH)) {
            policy::ExecExtendedKeyUsageType::ServerAuth
        } else if oid.polyfill_eq(&oid!(CLIENT_AUTH)) {
            policy::ExecExtendedKeyUsageType::ClientAuth
        } else if oid.polyfill_eq(&oid!(CODE_SIGNING)) {
            policy::ExecExtendedKeyUsageType::CodeSigning
        } else if oid.polyfill_eq(&oid!(EMAIL_PROTECTION)) {
            policy::ExecExtendedKeyUsageType::EmailProtection
        } else if oid.polyfill_eq(&oid!(TIME_STAMPING)) {
            policy::ExecExtendedKeyUsageType::TimeStamping
        } else if oid.polyfill_eq(&oid!(OCSP_SIGNING)) {
            policy::ExecExtendedKeyUsageType::OCSPSigning
        } else if oid.polyfill_eq(&oid!(EXTENDED_KEY_USAGE)) {
            policy::ExecExtendedKeyUsageType::Any
        } else {
            policy::ExecExtendedKeyUsageType::Other(policy::Certificate::oid_to_string(oid))
        }
    }
}

impl policy::BasicConstraints {
    pub open spec fn spec_from(ext: SpecExtensionValue) -> Option<policy::BasicConstraints> {
        if_let! {
            let SpecExtensionParamValue::BasicConstraints(bc) = ext.param;
            Some(policy::BasicConstraints {
                critical: ext.critical.to_opt(),
                is_ca: bc.is_ca,
                path_len: match bc.path_len {
                    OptionDeep::Some(len) => Some(len as i64),
                    OptionDeep::None => None,
                },
            })
        }
    }

    /// Exec version of spec_from
    pub fn from(ext: &ExtensionValue<'_>) -> (res: Result<policy::ExecBasicConstraints, ValidationError>)
        ensures
            res matches Ok(res) ==> Some(res.deep_view()) =~= Self::spec_from(ext@),
    {
        if let ExtensionParamValue::BasicConstraints(bc) = &ext.param {
            Ok(policy::ExecBasicConstraints {
                critical: PolyfillClone::clone(&ext.critical).to_opt(),
                is_ca: bc.is_ca,
                path_len: match bc.path_len {
                    OptionDeep::Some(len) => Some(len as i64),
                    OptionDeep::None => None,
                },
            })
        } else {
            Err(ValidationError::UnexpectedExtParam)
        }
    }
}

impl policy::KeyUsage {
    pub open spec fn spec_from(ext: SpecExtensionValue) -> Option<policy::KeyUsage> {
        if_let! {
            let SpecExtensionParamValue::KeyUsage(usage) = ext.param;
            Some(policy::KeyUsage {
                critical: ext.critical.to_opt(),
                digital_signature: BitStringValue::spec_has_bit(usage, 0),
                non_repudiation: BitStringValue::spec_has_bit(usage, 1),
                key_encipherment: BitStringValue::spec_has_bit(usage, 2),
                data_encipherment: BitStringValue::spec_has_bit(usage, 3),
                key_agreement: BitStringValue::spec_has_bit(usage, 4),
                key_cert_sign: BitStringValue::spec_has_bit(usage, 5),
                crl_sign: BitStringValue::spec_has_bit(usage, 6),
                encipher_only: BitStringValue::spec_has_bit(usage, 7),
                decipher_only: BitStringValue::spec_has_bit(usage, 8),
            })
        }
    }

    pub fn from(ext: &ExtensionValue<'_>) -> (res: Result<policy::ExecKeyUsage, ValidationError>)
        ensures
            res matches Ok(res) ==> Some(res.deep_view()) =~= Self::spec_from(ext@),
    {
        if let ExtensionParamValue::KeyUsage(usage) = &ext.param {
            Ok(policy::ExecKeyUsage {
                critical: PolyfillClone::clone(&ext.critical).to_opt(),
                digital_signature: BitStringValue::has_bit(usage, 0),
                non_repudiation: BitStringValue::has_bit(usage, 1),
                key_encipherment: BitStringValue::has_bit(usage, 2),
                data_encipherment: BitStringValue::has_bit(usage, 3),
                key_agreement: BitStringValue::has_bit(usage, 4),
                key_cert_sign: BitStringValue::has_bit(usage, 5),
                crl_sign: BitStringValue::has_bit(usage, 6),
                encipher_only: BitStringValue::has_bit(usage, 7),
                decipher_only: BitStringValue::has_bit(usage, 8),
            })
        } else {
            Err(ValidationError::UnexpectedExtParam)
        }
    }
}

impl policy::SubjectAltName {
    pub open spec fn spec_from(ext: SpecExtensionValue) -> Option<policy::SubjectAltName> {
        if_let! {
            let SpecExtensionParamValue::SubjectAltName(names) = ext.param;
            Some(policy::SubjectAltName {
                critical: ext.critical.to_opt(),
                names: policy::GeneralName::spec_from_names(names),
            })
        }
    }

    /// Exec version of spec_from
    pub fn from(ext: &ExtensionValue<'_>) -> (res: Result<policy::ExecSubjectAltName, ValidationError>)
        ensures
            res matches Ok(res) ==> Some(res.deep_view()) =~= Self::spec_from(ext@),
    {
        if let ExtensionParamValue::SubjectAltName(names) = &ext.param {
            Ok(policy::ExecSubjectAltName {
                critical: PolyfillClone::clone(&ext.critical).to_opt(),
                names: policy::GeneralName::from_names(names),
            })
        } else {
            Err(ValidationError::UnexpectedExtParam)
        }
    }
}

impl policy::NameConstraints {
    pub open spec fn spec_from(ext: SpecExtensionValue) -> Option<policy::NameConstraints> {
        if_let! {
            let SpecExtensionParamValue::NameConstraints(constraints) = ext.param;
            Some(policy::NameConstraints {
                critical: ext.critical.to_opt(),
                // Flattened list of permitted/excluded names
                permitted: if let OptionDeep::Some(permitted) = constraints.permitted {
                    policy::GeneralName::spec_from_general_subtrees(permitted)
                } else {
                    seq![]
                },
                excluded: if let OptionDeep::Some(excluded) = constraints.excluded {
                    policy::GeneralName::spec_from_general_subtrees(excluded)
                } else {
                    seq![]
                },
            })
        }
    }

    pub fn from(ext: &ExtensionValue<'_>) -> (res: Result<policy::ExecNameConstraints, ValidationError>)
        ensures
            res matches Ok(res) ==> Some(res.deep_view()) =~= Self::spec_from(ext@),
    {
        if let ExtensionParamValue::NameConstraints(constraints) = &ext.param {
            let permitted = if let OptionDeep::Some(permitted) = &constraints.permitted {
                policy::GeneralName::from_general_subtrees(permitted)
            } else {
                vec![]
            };

            let excluded = if let OptionDeep::Some(excluded) = &constraints.excluded {
                policy::GeneralName::from_general_subtrees(excluded)
            } else {
                vec![]
            };

            assert(permitted.deep_view() =~= if let OptionDeep::Some(permitted) = constraints@.permitted {
                policy::GeneralName::spec_from_general_subtrees(permitted)
            } else {
                seq![]
            });

            assert(excluded.deep_view() =~= if let OptionDeep::Some(excluded) = constraints@.excluded {
                policy::GeneralName::spec_from_general_subtrees(excluded)
            } else {
                seq![]
            });

            Ok(policy::ExecNameConstraints {
                critical: PolyfillClone::clone(&ext.critical).to_opt(),
                permitted,
                excluded,
            })
        } else {
            Err(ValidationError::UnexpectedExtParam)
        }
    }
}

impl policy::CertificatePolicies {
    pub open spec fn spec_from(ext: SpecExtensionValue) -> Option<policy::CertificatePolicies> {
        if_let! {
            let SpecExtensionParamValue::CertificatePolicies(policies) = ext.param;

            Some(policy::CertificatePolicies {
                critical: ext.critical.to_opt(),
                policies: policies.map_values(|policy: SpecPolicyInfoValue|
                    policy::Certificate::spec_oid_to_string(policy.policy_id)),
            })
        }
    }

    /// Exec version of spec_from
    pub fn from(ext: &ExtensionValue<'_>) -> (res: Result<policy::ExecCertificatePolicies, ValidationError>)
        ensures
            res matches Ok(res) ==> Some(res.deep_view()) =~= Self::spec_from(ext@),
    {
        if let ExtensionParamValue::CertificatePolicies(policies) = &ext.param {
            let policy_oid_strings = vec_map(policies.to_vec(), |policy| -> (res: String)
                ensures res.deep_view() =~= policy::Certificate::spec_oid_to_string(policy@.policy_id)
            {
                policy::Certificate::oid_to_string(&policy.policy_id)
            });

            assert(policy_oid_strings.deep_view() =~= policies@.map_values(|policy: SpecPolicyInfoValue|
                policy::Certificate::spec_oid_to_string(policy.policy_id)));

            Ok(policy::ExecCertificatePolicies {
                critical: PolyfillClone::clone(&ext.critical).to_opt(),
                policies: policy_oid_strings,
            })
        } else {
            Err(ValidationError::UnexpectedExtParam)
        }
    }
}

impl policy::AuthorityInfoAccess {
    pub open spec fn spec_from(ext: SpecExtensionValue) -> Option<policy::AuthorityInfoAccess> {
        if_let! {
            let SpecExtensionParamValue::AuthorityInfoAccess(..) = ext.param;

            Some(policy::AuthorityInfoAccess {
                critical: ext.critical.to_opt(),
            })
        }
    }

    pub fn from(ext: &ExtensionValue<'_>) -> (res: Result<policy::ExecAuthorityInfoAccess, ValidationError>)
        ensures
            res matches Ok(res) ==> Some(res.deep_view()) =~= Self::spec_from(ext@),
    {
        if let ExtensionParamValue::AuthorityInfoAccess(..) = &ext.param {
            Ok(policy::ExecAuthorityInfoAccess {
                critical: PolyfillClone::clone(&ext.critical).to_opt(),
            })
        } else {
            Err(ValidationError::UnexpectedExtParam)
        }
    }
}

/// Conversions from/to GeneralName and related structures
impl policy::GeneralName {
    /// Convert each general name to a list of policy::GeneralName's
    pub open spec fn spec_from(name: SpecGeneralNameValue) -> policy::GeneralName {
        match name {
            SpecGeneralNameValue::DNS(s) =>
                policy::GeneralName::DNSName(s),
            SpecGeneralNameValue::Directory(dir_names) =>
                policy::GeneralName::DirectoryName(policy::DistinguishedName::spec_from(dir_names)),
            SpecGeneralNameValue::IP(addr) =>
                policy::GeneralName::IPAddr(addr),
            SpecGeneralNameValue::Other(..) => policy::GeneralName::OtherName,
            _ => policy::GeneralName::Unsupported,
        }
    }

    /// Exec version of spec_from
    pub fn from(name: &GeneralNameValue<'_>) -> (res: policy::ExecGeneralName)
        ensures res.deep_view() =~= Self::spec_from(name@),
    {
        match name {
            GeneralNameValue::DNS(s) =>
                policy::ExecGeneralName::DNSName((*s).to_string()),
            GeneralNameValue::Directory(dir_names) =>
                policy::ExecGeneralName::DirectoryName(policy::DistinguishedName::from(dir_names)),
            GeneralNameValue::IP(addr) => {
                let copied = slice_to_vec(addr);
                assert(copied.deep_view() =~= addr@);
                policy::ExecGeneralName::IPAddr(copied)
            }
            GeneralNameValue::Other(..) => policy::ExecGeneralName::OtherName,
            _ => policy::ExecGeneralName::Unsupported,
        }
    }

    /// Similar to spec_from, but for multiple names
    pub open spec fn spec_from_names(names: SpecGeneralNamesValue) -> Seq<policy::GeneralName>
        decreases names.len()
    {
        if names.len() == 0 {
            seq![]
        } else {
            seq![Self::spec_from(names.first())] +
            Self::spec_from_names(names.drop_first())
        }
    }

    /// Exec version of spec_from_names
    pub fn from_names(names: &GeneralNamesValue<'_>) -> (res: Vec<policy::ExecGeneralName>)
        ensures res.deep_view() =~= Self::spec_from_names(names@),
    {
        let len = names.len();
        let mut gen_names = Vec::with_capacity(len);

        assert(names@.skip(0) == names@);

        for i in 0..len
            invariant
                len == names@.len(),
                Self::spec_from_names(names@) =~= gen_names.deep_view() + Self::spec_from_names(names@.skip(i as int)),
        {
            gen_names.push(Self::from(names.get(i)));
            assert(names@.skip(i + 1) == names@.skip(i as int).drop_first());
        }

        gen_names
    }

    /// Similar to GeneralName::spec_from_names, but for GeneralSubtrees
    /// Convert from GeneralSubtrees to a list of names (all flattened)
    pub open spec fn spec_from_general_subtrees(subtrees: SpecGeneralSubtreesValue) -> Seq<policy::GeneralName>
        decreases subtrees.len()
    {
        if subtrees.len() == 0 {
            seq![]
        } else {
            seq![Self::spec_from(subtrees.first().base)] +
            Self::spec_from_general_subtrees(subtrees.drop_first())
        }
    }

    pub fn from_general_subtrees(subtrees: &GeneralSubtreesValue<'_>) -> (res: Vec<policy::ExecGeneralName>)
        ensures
            res.deep_view() =~= Self::spec_from_general_subtrees(subtrees@)
    {
        let len = subtrees.len();
        let mut names = Vec::with_capacity(len);

        assert(subtrees@.skip(0) == subtrees@);

        for i in 0..len
            invariant
                len == subtrees@.len(),
                Self::spec_from_general_subtrees(subtrees@) =~=
                    names.deep_view() + Self::spec_from_general_subtrees(subtrees@.skip(i as int)),
        {
            names.push(Self::from(&subtrees.get(i).base));
            assert(subtrees@.skip(i + 1) == subtrees@.skip(i as int).drop_first());
        }

        names
    }
}

impl policy::SubjectKey {
    /// Convert SpecPublicKeyInfoValue to the more abstract version
    pub open spec fn spec_from(spki: SpecPublicKeyInfoValue) -> Option<policy::SubjectKey> {
        match spki.alg.param {
            SpecAlgorithmParamValue::DSASignature(Either::Left(param)) => {
                Some(policy::SubjectKey::DSA {
                    p_len: ((param.p.len() - 1) as usize * 8) as usize,
                    q_len: ((param.q.len() - 1) as usize * 8) as usize,
                    g_len: ((param.g.len() - 1) as usize * 8) as usize,
                })
            }

            SpecAlgorithmParamValue::RSAEncryption(..) => {
                // Parse the public key field to get the modulus length
                let pub_key = BitStringValue::spec_bytes(spki.pub_key);

                if_let! {
                    let Ok((_, parsed)) = ASN1(RSAParam).view().spec_parse(pub_key);
                    Some(policy::SubjectKey::RSA {
                        mod_length: ((parsed.modulus.len() - 1) as usize * 8) as usize,
                    })
                }
            }

            _ => Some(policy::SubjectKey::Other),
        }
    }

    /// Exec version of spec_from
    pub fn from(spki: &PublicKeyInfoValue<'_>) -> (res: Result<policy::ExecSubjectKey, ValidationError>)
        ensures
            res matches Ok(res) ==> Some(res.deep_view()) =~= Self::spec_from(spki@),
    {
        match &spki.alg.param {
            AlgorithmParamValue::DSASignature(Either::Left(param)) => {
                let p_len = param.p.byte_len();
                let q_len = param.q.byte_len();
                let g_len = param.g.byte_len();

                if p_len > usize::MAX / 8 ||
                   q_len > usize::MAX / 8 ||
                   g_len > usize::MAX / 8 {
                    return Err(ValidationError::IntegerOverflow);
                }

                Ok(policy::ExecSubjectKey::DSA {
                    p_len: p_len * 8,
                    q_len: q_len * 8,
                    g_len: g_len * 8,
                })
            }

            AlgorithmParamValue::RSAEncryption(..) => {
                let pub_key = spki.pub_key.bytes();
                let parsed = match ASN1(RSAParam).parse(pub_key) {
                    Ok((_, parsed)) => parsed,
                    Err(_) => return Err(ValidationError::RSAPubKeyParseError),
                };

                let mod_len = parsed.modulus.byte_len();

                if mod_len > usize::MAX / 8 {
                    return Err(ValidationError::IntegerOverflow);
                }

                Ok(policy::ExecSubjectKey::RSA {
                    mod_length: mod_len * 8,
                })
            }

            _ => Ok(policy::ExecSubjectKey::Other),
        }
    }
}

/// Directory Name (`Name` in X.509) is essentially `Seq<Seq<{ type, value }>>`
impl policy::DistinguishedName {
    pub closed spec fn spec_from(name: SpecNameValue) -> policy::DistinguishedName {
        policy::DistinguishedName(Self::spec_from_helper(name))
    }

    pub closed spec fn spec_from_helper(name: SpecNameValue) -> Seq<Seq<policy::Attribute>>
        decreases name.len()
    {
        if name.len() == 0 {
            seq![]
        } else {
            seq![Self::spec_from_rdn(name.first())] + Self::spec_from_helper(name.drop_first())
        }
    }

    /// Exec version of spec_from
    pub fn from(name: &NameValue<'_>) -> (res: policy::ExecDistinguishedName)
        ensures res.deep_view() == Self::spec_from(name@),
    {
        let len = name.len();
        let mut dir_names = Vec::with_capacity(len);

        assert(name@.skip(0) == name@);

        for i in 0..len
            invariant
                len == name@.len(),
                Self::spec_from_helper(name@) =~= dir_names.deep_view() + Self::spec_from_helper(name@.skip(i as int)),
        {
            dir_names.push(Self::from_rdn(name.get(i)));
            assert(name@.skip(i + 1) == name@.skip(i as int).drop_first());
        }

        policy::ExecDistinguishedName(dir_names)
    }

    /// Convert each attribute of RDN to a DistinguishedName, ignoring unsupported ones
    pub closed spec fn spec_from_rdn(rdn: SpecRDNValue) -> Seq<policy::Attribute>
        decreases rdn.len()
    {
        if rdn.len() == 0 {
            seq![]
        } else {
            if let Some(dir_name) = Self::spec_from_attr(rdn.first()) {
                seq![dir_name] + Self::spec_from_rdn(rdn.drop_first())
            } else {
                Self::spec_from_rdn(rdn.drop_first())
            }
        }
    }

    /// Exec version of spec_from_rdn
    pub fn from_rdn<'a, 'b>(rdn: &'b RDNValue<'a>) -> (res: Vec<policy::ExecAttribute>)
        ensures res.deep_view() == Self::spec_from_rdn(rdn@),
    {
        let len = rdn.len();
        let mut names = Vec::with_capacity(len);

        assert(rdn@.skip(0) == rdn@);

        for i in 0..len
            invariant
                len == rdn@.len(),
                Self::spec_from_rdn(rdn@) =~= names.deep_view() + Self::spec_from_rdn(rdn@.skip(i as int)),
        {
            if let Some(dir_name) = Self::from_attr(rdn.get(i)) {
                names.push(dir_name);
            }

            assert(rdn@.skip(i + 1) == rdn@.skip(i as int).drop_first());
        }

        names
    }

    pub closed spec fn spec_from_attr(attr: SpecAttributeTypeAndValueValue) -> Option<policy::Attribute> {
        if_let! {
            let Some(value) = Self::spec_dir_string_to_string(attr.value);

            Some(policy::Attribute {
                oid: policy::Certificate::spec_oid_to_string(attr.typ),
                value,
            })
        }
    }

    /// Exec version of spec_from_attr
    pub fn from_attr<'a, 'b>(attr: &'b AttributeTypeAndValueValue<'a>) -> (res: Option<policy::ExecAttribute>)
        ensures res.deep_view() == Self::spec_from_attr(attr@),
    {
        Some(policy::ExecAttribute {
            oid: policy::Certificate::oid_to_string(&attr.typ),
            value: Self::dir_string_to_string(&attr.value)?.to_string(),
        })
    }

    /// Convert a dir string to string
    /// NOTE: DirectoryString refers to a overloaded string type in X.509
    /// DistinguishedName refers to the string attached with an OID used in subject name
    /// TODO: support more dir strings
    pub closed spec fn spec_dir_string_to_string(dir: SpecDirectoryStringValue) -> Option<Seq<char>>
    {
        match dir {
            SpecDirectoryStringValue::PrintableString(s) => Some(s),
            SpecDirectoryStringValue::UTF8String(s) => Some(s),
            SpecDirectoryStringValue::IA5String(s) => Some(s),
            SpecDirectoryStringValue::TeletexString(s) => None,
            SpecDirectoryStringValue::UniversalString(s) => None,
            SpecDirectoryStringValue::BMPString(s) => None,
            SpecDirectoryStringValue::Unreachable => None,
        }
    }

    /// Exec version of spec_dir_string_to_string
    pub fn dir_string_to_string<'a, 'b>(dir: &'b DirectoryStringValue<'a>) -> (res: Option<&'a str>)
        ensures
            res matches Some(res) ==> Self::spec_dir_string_to_string(dir@) == Some(res@),
            res.is_none() ==> Self::spec_dir_string_to_string(dir@).is_none(),
    {
        match dir {
            DirectoryStringValue::PrintableString(s) => Some(s),
            DirectoryStringValue::UTF8String(s) => Some(s),
            DirectoryStringValue::IA5String(s) => Some(s),
            DirectoryStringValue::TeletexString(..) => None,
            DirectoryStringValue::UniversalString(..) => None,
            DirectoryStringValue::BMPString(..) => None,
            DirectoryStringValue::Unreachable => None,
        }
    }
}

}
