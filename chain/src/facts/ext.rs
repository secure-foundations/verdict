use vstd::prelude::*;

use polyfill::*;
use vpl::*;
use parser::{*, x509::*, asn1::*};

use super::facts::*;
use super::cert::*;
use crate::validate::*;

verus! {

broadcast use vpl::lemma_ext_equal_deep;

/// Facts for supported extensions
pub type ExtensionFacts = seq_facts![ ExtBasicConstraintsFacts, ExtKeyUsageFacts, ExtSubjectAltNameFacts, ExtNameConstraintsFacts ];
pub struct ExtBasicConstraintsFacts;
pub struct ExtKeyUsageFacts;
pub struct ExtSubjectAltNameFacts;
pub struct ExtNameConstraintsFacts;

impl<'a, 'b> Facts<CertIndexed<&'b CertificateValue<'a>>> for ExtBasicConstraintsFacts {
    closed spec fn spec_facts(t: CertIndexed<SpecCertificateValue>) -> Option<Seq<SpecRule>> {
        Some(if let OptionDeep::Some(ext) = spec_get_extension(t.x, spec_oid!(2, 5, 29, 19)) {
            if let SpecExtensionParamValue::BasicConstraints(param) = ext.param {
                seq![
                    spec_fact!("basicConstraintsExt", t.spec_cert(), spec_bool!(true)),
                    spec_fact!("basicConstraintsCritical", t.spec_cert(), spec_bool!(ext.critical)),
                    spec_fact!("isCA", t.spec_cert(), spec_bool!(param.is_ca)),

                    if let OptionDeep::Some(path_len) = param.path_len {
                        spec_fact!("pathLimit", t.spec_cert(), spec_int!(path_len as int))
                    } else {
                        spec_fact!("pathLimit", t.spec_cert(), spec_atom!("none".view()))
                    },
                ]
            } else {
                seq![
                    spec_fact!("basicConstraintsExt", t.spec_cert(), spec_bool!(false)),
                ]
            }
        } else {
            seq![
                spec_fact!("basicConstraintsExt", t.spec_cert(), spec_bool!(false)),
            ]
        })
    }

    fn facts(t: &CertIndexed<&'b CertificateValue<'a>>, out: &mut VecDeep<Rule>) -> (res: Result<(), ValidationError>) {
        let oid = oid!(2, 5, 29, 19);
        assert(oid@ == spec_oid!(2, 5, 29, 19));

        if let OptionDeep::Some(ext) = get_extension(t.x, &oid) {
            if let ExtensionParamValue::BasicConstraints(param) = &ext.param {
                out.push(RuleX::fact("basicConstraintsExt", vec![ t.cert(), TermX::bool(true) ]));
                out.push(RuleX::fact("basicConstraintsCritical", vec![ t.cert(), TermX::bool(ext.critical) ]));
                out.push(RuleX::fact("isCA", vec![ t.cert(), TermX::bool(param.is_ca) ]));

                if let OptionDeep::Some(path_len) = param.path_len {
                    out.push(RuleX::fact("pathLimit", vec![ t.cert(), TermX::int(path_len as LiteralInt) ]));
                } else {
                    out.push(RuleX::fact("pathLimit", vec![ t.cert(), TermX::atom("none") ]));
                }

                return Ok(());
            }
        }

        out.push(RuleX::fact("basicConstraintsExt", vec![ t.cert(), TermX::bool(false) ]));
        Ok(())
    }
}

impl ExtKeyUsageFacts {
    /// `usages` is a list of key usage names corresponding to each bit in the key usage bit string
    /// e.g. keyUsage(cert(..), usages[0]) is added if the 0-th bit is set in `param`
    closed spec fn spec_facts_helper(t: CertIndexed<SpecCertificateValue>, usages: Seq<Seq<char>>, param: SpecBitStringValue, i: int) -> Seq<SpecRule>
        decreases i
    {
        if i <= 0 {
            seq![]
        } else if BitStringValue::spec_has_bit(param, i - 1) {
            Self::spec_facts_helper(t, usages, param, i - 1) +
            seq![ spec_fact!("keyUsage", t.spec_cert(), spec_atom!(usages[i - 1])) ]
        } else {
            Self::spec_facts_helper(t, usages, param, i - 1)
        }
    }
}

impl<'a, 'b> Facts<CertIndexed<&'b CertificateValue<'a>>> for ExtKeyUsageFacts {
    closed spec fn spec_facts(t: CertIndexed<SpecCertificateValue>) -> Option<Seq<SpecRule>> {
        Some(if let OptionDeep::Some(ext) = spec_get_extension(t.x, spec_oid!(2, 5, 29, 15)) {
            if let SpecExtensionParamValue::KeyUsage(param) = ext.param {
                let usages = seq![
                    "digitalSignature".view(),
                    "nonRepudiation".view(),
                    "keyEncipherment".view(),
                    "dataEncipherment".view(),
                    "keyAgreement".view(),
                    "keyCertSign".view(),
                    "cRLSign".view(),
                    "encipherOnly".view(),
                    "decipherOnly".view(),
                ];

                seq![
                    spec_fact!("keyUsageExt", t.spec_cert(), spec_bool!(true)),
                    spec_fact!("keyUsageCritical", t.spec_cert(), spec_bool!(ext.critical)),
                ] +
                Self::spec_facts_helper(t, usages, param, usages.len() as int)
            } else {
                seq![
                    spec_fact!("keyUsageExt", t.spec_cert(), spec_bool!(false)),
                ]
            }
        } else {
            seq![
                spec_fact!("keyUsageExt", t.spec_cert(), spec_bool!(false)),
            ]
        })
    }

    fn facts(t: &CertIndexed<&'b CertificateValue<'a>>, out: &mut VecDeep<Rule>) -> (res: Result<(), ValidationError>) {
        let oid = oid!(2, 5, 29, 15);
        assert(oid@ == spec_oid!(2, 5, 29, 15));

        if let OptionDeep::Some(ext) = get_extension(t.x, &oid) {
            if let ExtensionParamValue::KeyUsage(param) = &ext.param {
                let usages = vec_deep![
                    "digitalSignature",
                    "nonRepudiation",
                    "keyEncipherment",
                    "dataEncipherment",
                    "keyAgreement",
                    "keyCertSign",
                    "cRLSign",
                    "encipherOnly",
                    "decipherOnly",
                ];

                out.push(RuleX::fact("keyUsageExt", vec![ t.cert(), TermX::bool(true) ]));
                out.push(RuleX::fact("keyUsageCritical", vec![ t.cert(), TermX::bool(ext.critical) ]));

                // Add fact keyUsage(.., usages[i]) for each i-th bit set in the param
                let ghost prev_out = out@;
                let len = usages.len();
                for i in 0..len
                    invariant
                        len == usages@.len(),
                        out@ =~~= prev_out + Self::spec_facts_helper(t@, usages@, param@, i as int),
                {
                    if param.has_bit(i) {
                        out.push(RuleX::fact("keyUsage", vec![ t.cert(), TermX::atom(usages.get(i)) ]));
                    }
                }

                assert(usages@ =~= seq![
                    "digitalSignature".view(),
                    "nonRepudiation".view(),
                    "keyEncipherment".view(),
                    "dataEncipherment".view(),
                    "keyAgreement".view(),
                    "keyCertSign".view(),
                    "cRLSign".view(),
                    "encipherOnly".view(),
                    "decipherOnly".view(),
                ]);

                return Ok(());
            }
        }

        out.push(RuleX::fact("keyUsageExt", vec![ t.cert(), TermX::bool(false) ]));

        Ok(())
    }
}

impl ExtSubjectAltNameFacts {
    /// Same definition as Hammurabi
    pub closed spec fn spec_oid_to_name(oid: SpecObjectIdentifierValue) -> Seq<char>
    {
        if oid == spec_oid!(2, 5, 4, 6) { "country"@ }
        else if oid == spec_oid!(2, 5, 4, 10) { "organization"@ }
        else if oid == spec_oid!(2, 5, 4, 11) { "organizational unit"@ }
        else if oid == spec_oid!(2, 5, 4, 97) { "organizational identifier"@ }
        else if oid == spec_oid!(2, 5, 4, 3) { "common name"@ }
        else if oid == spec_oid!(2, 5, 4, 4) { "surname"@ }
        else if oid == spec_oid!(2, 5, 4, 8) { "state"@ }
        else if oid == spec_oid!(2, 5, 4, 9) { "street address"@ }
        else if oid == spec_oid!(2, 5, 4, 7) { "locality"@ }
        else if oid == spec_oid!(2, 5, 4, 17) { "postal code"@ }
        else if oid == spec_oid!(2, 5, 4, 42) { "given name"@ }
        else if oid == spec_oid!(0, 9, 2342, 19200300, 100, 1, 25) { "domain component"@ }
        else { "UNKNOWN"@ }
    }

    /// Exec version of spec_oid_to_name
    pub fn oid_to_name(oid: &ObjectIdentifierValue) -> (res: &'static str)
        ensures res@ =~= Self::spec_oid_to_name(oid@)
    {
        let id = oid!(2, 5, 4, 6); assert(id@ == spec_oid!(2, 5, 4, 6));
        let id = oid!(2, 5, 4, 10); assert(id@ == spec_oid!(2, 5, 4, 10));
        let id = oid!(2, 5, 4, 11); assert(id@ == spec_oid!(2, 5, 4, 11));
        let id = oid!(2, 5, 4, 97); assert(id@ == spec_oid!(2, 5, 4, 97));
        let id = oid!(2, 5, 4, 3); assert(id@ == spec_oid!(2, 5, 4, 3));
        let id = oid!(2, 5, 4, 4); assert(id@ == spec_oid!(2, 5, 4, 4));
        let id = oid!(2, 5, 4, 8); assert(id@ == spec_oid!(2, 5, 4, 8));
        let id = oid!(2, 5, 4, 9); assert(id@ == spec_oid!(2, 5, 4, 9));
        let id = oid!(2, 5, 4, 7); assert(id@ == spec_oid!(2, 5, 4, 7));
        let id = oid!(2, 5, 4, 17); assert(id@ == spec_oid!(2, 5, 4, 17));
        let id = oid!(2, 5, 4, 42); assert(id@ == spec_oid!(2, 5, 4, 42));
        let id = oid!(0, 9, 2342, 19200300, 100, 1, 25); assert(id@ == spec_oid!(0, 9, 2342, 19200300, 100, 1, 25));

        if oid.polyfill_eq(&oid!(2, 5, 4, 6)) { "country" }
        else if oid.polyfill_eq(&oid!(2, 5, 4, 10)) { "organization" }
        else if oid.polyfill_eq(&oid!(2, 5, 4, 11)) { "organizational unit" }
        else if oid.polyfill_eq(&oid!(2, 5, 4, 97)) { "organizational identifier" }
        else if oid.polyfill_eq(&oid!(2, 5, 4, 3)) { "common name" }
        else if oid.polyfill_eq(&oid!(2, 5, 4, 4)) { "surname" }
        else if oid.polyfill_eq(&oid!(2, 5, 4, 8)) { "state" }
        else if oid.polyfill_eq(&oid!(2, 5, 4, 9)) { "street address" }
        else if oid.polyfill_eq(&oid!(2, 5, 4, 7)) { "locality" }
        else if oid.polyfill_eq(&oid!(2, 5, 4, 17)) { "postal code" }
        else if oid.polyfill_eq(&oid!(2, 5, 4, 42)) { "given name" }
        else if oid.polyfill_eq(&oid!(0, 9, 2342, 19200300, 100, 1, 25)) { "domain component" }
        else { "UNKNOWN" }
    }

    /// Generate pairs of (typ, str) where typ is the name of the variant
    /// and str is the content of the general name
    pub closed spec fn spec_extract_general_name(name: SpecGeneralNameValue) -> Seq<(Seq<char>, SpecTerm)>
    {
        match name {
            SpecGeneralNameValue::Other(..) => seq![ ("Other"@, spec_atom!("unsupported".view())) ],
            SpecGeneralNameValue::RFC822(s) => seq![ ("RFC822"@, spec_str!(s)) ],
            SpecGeneralNameValue::DNS(s) => seq![ ("DNS"@, spec_str!(s)) ],
            SpecGeneralNameValue::X400(..) => seq![ ("X400"@, spec_atom!("unsupported".view())) ],
            SpecGeneralNameValue::Directory(dir_names) => {
                Seq::new(dir_names.len(), |j| {
                    Seq::new(dir_names[j].len(), |k| {
                        (
                            "Directory/"@ + Self::spec_oid_to_name(dir_names[j][k].typ),

                            match SubjectNameFacts::spec_dir_string_to_string(dir_names[j][k].value) {
                                Some(s) => spec_str!(s),
                                None => spec_atom!("unsupported".view()),
                            }
                        )
                    })
                }).flatten()
            }
            SpecGeneralNameValue::EDIParty(..) => seq![ ("EDIParty"@, spec_atom!("unsupported".view())) ],
            SpecGeneralNameValue::URI(s) => seq![ ("URI"@, spec_str!(s)) ],
            SpecGeneralNameValue::IP(..) => seq![ ("IP"@, spec_atom!("unsupported".view())) ],
            SpecGeneralNameValue::RegisteredID(..) => seq![ ("RegisteredID"@, spec_atom!("unsupported".view())) ],
            SpecGeneralNameValue::Unreachable => seq![],
        }
    }

    /// Exec version of spec_extract_general_name
    pub fn extract_general_name(name: &GeneralNameValue) -> (res: VecDeep<(String, Term)>)
        ensures res@ =~~= Self::spec_extract_general_name(name@)
    {
        match name {
            GeneralNameValue::Other(..) => vec_deep![("Other".to_string(), TermX::atom("unsupported"))],
            GeneralNameValue::RFC822(s) => vec_deep![("RFC822".to_string(), TermX::str(s))],
            GeneralNameValue::DNS(s) => vec_deep![("DNS".to_string(), TermX::str(s))],
            GeneralNameValue::X400(..) => vec_deep![("X400".to_string(), TermX::atom("unsupported"))],
            GeneralNameValue::Directory(dir_names) => {
                let mut dir_name_pairs = vec_deep![];

                let len = dir_names.len();
                for j in 0..len
                    invariant
                        len == dir_names@.len(),
                        dir_name_pairs@ =~~= Seq::new(j as nat, |j| {
                            Seq::new(dir_names@[j].len(), |k| {
                                (
                                    "Directory/"@ + Self::spec_oid_to_name(dir_names@[j][k].typ),
                                    match SubjectNameFacts::spec_dir_string_to_string(dir_names@[j][k].value) {
                                        Some(s) => spec_str!(s),
                                        None => spec_atom!("unsupported".view()),
                                    }
                                )
                            })
                        })
                {
                    let mut rdn_pairs = vec_deep![];

                    // Read each RDN, and convert it to a pair of (type, value)
                    let len = dir_names.get(j).len();
                    for k in 0..len
                        invariant
                            0 <= j < dir_names@.len(),
                            len == dir_names@[j as int].len(),
                            rdn_pairs@ =~~= Seq::new(k as nat, |k| {
                                (
                                    "Directory/"@ + Self::spec_oid_to_name(dir_names@[j as int][k].typ),
                                    match SubjectNameFacts::spec_dir_string_to_string(dir_names@[j as int][k].value) {
                                        Some(s) => spec_str!(s),
                                        None => spec_atom!("unsupported".view()),
                                    }
                                )
                            })
                    {
                        let attr = dir_names.get(j).get(k);
                        let typ = "Directory/".to_string().concat(Self::oid_to_name(&attr.typ));
                        let val = match SubjectNameFacts::dir_string_to_string(&attr.value) {
                            Some(s) => TermX::str(s),
                            None => TermX::atom("unsupported"),
                        };

                        rdn_pairs.push((typ, val));
                    }

                    dir_name_pairs.push(rdn_pairs);
                }

                VecDeep::flatten(dir_name_pairs)
            }
            GeneralNameValue::EDIParty(..) => vec_deep![("EDIParty".to_string(), TermX::atom("unsupported"))],
            GeneralNameValue::URI(s) => vec_deep![("URI".to_string(), TermX::str(s))],
            GeneralNameValue::IP(..) => vec_deep![("IP".to_string(), TermX::atom("unsupported"))],
            GeneralNameValue::RegisteredID(..) => vec_deep![("RegisteredID".to_string(), TermX::atom("unsupported"))],
            GeneralNameValue::Unreachable => vec_deep![],
        }
    }

    /// Extract all general names along with a string denoting their variant
    /// For directoryName, expand each RDN to a string
    pub closed spec fn spec_extract_general_names(names: Seq<SpecGeneralNameValue>) -> Seq<(Seq<char>, SpecTerm)>
    {
        Seq::new(names.len(), |i| Self::spec_extract_general_name(names[i])).flatten()
    }

    /// Exec version of spec_extract_general_names
    pub fn extract_general_names(names: &VecDeep<GeneralNameValue>) -> (res: VecDeep<(String, Term)>)
        ensures res@ =~~= Self::spec_extract_general_names(names@)
    {
        let mut typ_names = vec_deep![];

        let len = names.len();

        for i in 0..len
            invariant
                len == names@.len(),
                typ_names@ =~~= Seq::new(i as nat, |i| Self::spec_extract_general_name(names@[i as int])),
        {
            typ_names.push(Self::extract_general_name(names.get(i)));
        }

        VecDeep::flatten(typ_names)
    }
}

impl<'a, 'b> Facts<CertIndexed<&'b CertificateValue<'a>>> for ExtSubjectAltNameFacts {
    closed spec fn spec_facts(t: CertIndexed<SpecCertificateValue>) -> Option<Seq<SpecRule>> {
        Some(if let OptionDeep::Some(ext) = spec_get_extension(t.x, spec_oid!(2, 5, 29, 17)) {
            if let SpecExtensionParamValue::SubjectAltName(names) = ext.param {
                seq![
                    spec_fact!("sanExt", t.spec_cert(), spec_bool!(true)),
                    spec_fact!("sanCritical", t.spec_cert(), spec_bool!(ext.critical)),
                ] +
                Self::spec_extract_general_names(names).map_values(|v: (Seq<char>, SpecTerm)| spec_fact!("san", t.spec_cert(), v.1))
            } else {
                seq![
                    spec_fact!("sanExt", t.spec_cert(), spec_bool!(false)),
                ]
            }
        } else {
            seq![
                spec_fact!("sanExt", t.spec_cert(), spec_bool!(false)),
            ]
        })
    }

    fn facts(t: &CertIndexed<&'b CertificateValue<'a>>, out: &mut VecDeep<Rule>) -> (res: Result<(), ValidationError>) {
        let oid = oid!(2, 5, 29, 17);
        assert(oid@ == spec_oid!(2, 5, 29, 17));

        if let OptionDeep::Some(ext) = get_extension(t.x, &oid) {
            if let ExtensionParamValue::SubjectAltName(names) = &ext.param {
                out.push(RuleX::fact("sanExt", vec![ t.cert(), TermX::bool(true) ]));
                out.push(RuleX::fact("sanCritical", vec![ t.cert(), TermX::bool(ext.critical) ]));

                let typ_names = Self::extract_general_names(names);

                // Push all subject alt names as facts
                let ghost prev_out = out@;
                let len = typ_names.len();
                for i in 0..len
                    invariant
                        len == typ_names@.len(),
                        typ_names@ == Self::spec_extract_general_names(names@),
                        out@ =~~= prev_out + Self::spec_extract_general_names(names@)
                            .map_values(|v: (Seq<char>, SpecTerm)| spec_fact!("san", t.view().spec_cert(), v.1)).take(i as int),
                {
                    out.push(RuleX::fact("san", vec![ t.cert(), rc_clone(&typ_names.get(i).1) ]));
                }

                return Ok(());
            }
        }

        out.push(RuleX::fact("sanExt", vec![ t.cert(), TermX::bool(false) ]));
        Ok(())
    }
}

impl ExtNameConstraintsFacts {
    /// Generate nameConstraintsPermited and nameConstraintsExcluded facts
    pub closed spec fn spec_gen_general_subtree_facts(
        t: CertIndexed<SpecCertificateValue>,
        subtrees: Seq<SpecGeneralSubtreeValue>,
        fact_name: &str,
    ) -> Seq<Seq<SpecRule>>
    {
        Seq::new(subtrees.len(), |j| {
            let typ_names = ExtSubjectAltNameFacts::spec_extract_general_name(subtrees[j].base);

            Seq::new(typ_names.len(), |k| spec_fact!(fact_name, t.spec_cert(), spec_str!(typ_names[k].0), typ_names[k].1))
        })
    }

    /// Exec version of spec_gen_general_subtree_facts
    #[verifier::loop_isolation(false)]
    pub fn gen_general_subtree_facts<'a, 'b>(
        t: &CertIndexed<&'b CertificateValue<'a>>,
        subtrees: &VecDeep<GeneralSubtreeValue>,
        fact_name: &str,
    ) -> (res: VecDeep<VecDeep<Rule>>)
        ensures res@ =~~= Self::spec_gen_general_subtree_facts(t@, subtrees@, fact_name)
    {
        let mut facts = vec_deep![];

        // Iterate through each subtree
        let len = subtrees.len();
        for j in 0..len
            invariant
                len == subtrees@.len(),
                facts@ =~~= Self::spec_gen_general_subtree_facts(t@, subtrees@, fact_name).take(j as int),
        {
            let typ_names = ExtSubjectAltNameFacts::extract_general_name(&subtrees.get(j).base);
            let len = typ_names.len();

            let mut subtree_facts = vec_deep![];

            // Iterate through each general name in the subtree.base
            for k in 0..len
                invariant
                    len == typ_names@.len(),
                    0 <= j < subtrees@.len(),
                    typ_names@ == ExtSubjectAltNameFacts::spec_extract_general_name(subtrees@[j as int].base),
                    subtree_facts@ =~~= Self::spec_gen_general_subtree_facts(t@, subtrees@, fact_name)[j as int].take(k as int),
            {
                // nameConstraintsPermited/nameConstraintsExcluded(cert(..), <variant>, <general name>)
                subtree_facts.push(RuleX::fact(
                    fact_name,
                    vec![
                        t.cert(),
                        TermX::str(typ_names.get(k).0.as_str()),
                        rc_clone(&typ_names.get(k).1),
                    ],
                ));
            }

            facts.push(subtree_facts);
        }

        facts
    }
}

impl<'a, 'b> Facts<CertIndexed<&'b CertificateValue<'a>>> for ExtNameConstraintsFacts {
    /// TODO: avoid flatten() here
    closed spec fn spec_facts(t: CertIndexed<SpecCertificateValue>) -> Option<Seq<SpecRule>> {
        Some(if let OptionDeep::Some(ext) = spec_get_extension(t.x, spec_oid!(2, 5, 29, 30)) {
            if let SpecExtensionParamValue::NameConstraints(param) = ext.param {
                seq![
                    spec_fact!("nameConstraintsExt", t.spec_cert(), spec_bool!(true)),
                    spec_fact!("nameConstraintsCritical", t.spec_cert(), spec_bool!(ext.critical)),
                ] +

                if let OptionDeep::Some(permitted) = param.permitted {
                    Self::spec_gen_general_subtree_facts(t, permitted, "nameConstraintsPermited").flatten()
                } else {
                    seq![]
                } +

                if let OptionDeep::Some(excluded) = param.excluded {
                    Self::spec_gen_general_subtree_facts(t, excluded, "nameConstraintsExcluded").flatten()
                } else {
                    seq![]
                }
            } else {
                seq![ spec_fact!("nameConstraintsExt", t.spec_cert(), spec_bool!(false)) ]
            }
        } else {
            seq![ spec_fact!("nameConstraintsExt", t.spec_cert(), spec_bool!(false)) ]
        })
    }

    fn facts(t: &CertIndexed<&'b CertificateValue<'a>>, out: &mut VecDeep<Rule>) -> (res: Result<(), ValidationError>) {
        let oid = oid!(2, 5, 29, 30);
        assert(oid@ == spec_oid!(2, 5, 29, 30));

        if let OptionDeep::Some(ext) = get_extension(t.x, &oid) {
            if let ExtensionParamValue::NameConstraints(param) = &ext.param {
                out.push(RuleX::fact("nameConstraintsExt", vec![ t.cert(), TermX::bool(true) ]));
                out.push(RuleX::fact("nameConstraintsCritical", vec![ t.cert(), TermX::bool(ext.critical) ]));

                if let OptionDeep::Some(permitted) = &param.permitted {
                    let permitted_facts = ExtNameConstraintsFacts::gen_general_subtree_facts(t, permitted, "nameConstraintsPermited");
                    let permitted_facts = VecDeep::flatten(permitted_facts);
                    out.append_owned(permitted_facts);
                }

                if let OptionDeep::Some(excluded) = &param.excluded {
                    let excluded_facts = ExtNameConstraintsFacts::gen_general_subtree_facts(t, excluded, "nameConstraintsExcluded");
                    let excluded_facts = VecDeep::flatten(excluded_facts);
                    out.append_owned(excluded_facts);
                }

                return Ok(());
            }
        }

        out.push(RuleX::fact("nameConstraintsExt", vec![ t.cert(), TermX::bool(false) ]));
        Ok(())
    }
}

}
