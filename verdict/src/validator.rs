/// High-level specs and impls of chain building and validation

use vstd::prelude::*;

#[allow(unused_imports)]
use verdict_parser::{*, x509::*, asn1::BitStringValue};
#[allow(unused_imports)]
use verdict_polyfill::*;

use crate::policy::{self,Policy, Task, ExecTask};
use crate::signature::*;
use crate::issue::*;
use crate::error::*;

verus! {

/// Top-level spec for X509 validation
/// from certificates encoded in Base64
pub open spec fn spec_validate_x509_base64<P: Policy>(
    // Base64 encodings of trusted roots
    roots_base64: Seq<Seq<u8>>,

    // Base64 encodings of certificate chain
    // consisting of a leaf certificate (`chain[0`])
    // and intermediate certificates (`chain[1..]`)
    chain_base64: Seq<Seq<u8>>,

    policy: P,
    task: Task,
) -> bool
    recommends chain_base64.len() != 0
{
    let roots = roots_base64.map_values(|base64| spec_parse_x509_base64(base64).unwrap());
    let chain = chain_base64.map_values(|base64| spec_parse_x509_base64(base64).unwrap());

    Query {
        policy: policy,
        roots: roots,
        bundle: chain,
        task: task,
    }.valid()
}

/// An implementation for `spec_validate_x509_base64`
/// Note that it's recommended to cache the result of creating
/// a `RootStore` and `Validator` for better performance without
/// processing roots every time.
pub fn validate_x509_base64<P: Policy>(
    roots_base64: &Vec<Vec<u8>>,
    chain_base64: &Vec<Vec<u8>>,

    policy: P,
    task: &ExecTask,
) -> (res: Result<bool, ValidationError>)
    requires chain_base64@.len() != 0
    ensures
        res matches Ok(res) ==> res == spec_validate_x509_base64(
            roots_base64.deep_view(),
            chain_base64.deep_view(),
            policy,
            task.deep_view(),
        ),
{
    let store = RootStore::from_base64(roots_base64)?;
    let validator = Validator::from_root_store(policy, &store)?;
    let res = validator.validate_base64(chain_base64, task)?;

    // Some conversions from deep_view and view
    assert(roots_base64.deep_view() =~~= roots_base64@.map_values(|base64: Vec<u8>| base64@));
    assert(chain_base64.deep_view() =~~= chain_base64@.map_values(|base64: Vec<u8>| base64@));

    assert(validator.roots@ =~= roots_base64.deep_view().map_values(|base64: Seq<u8>| spec_parse_x509_base64(base64).unwrap()));
    assert(
        chain_base64@.map_values(|base64: Vec<u8>| spec_parse_x509_base64(base64@).unwrap())
        =~~=
        chain_base64.deep_view().map_values(|base64| spec_parse_x509_base64(base64).unwrap())
    );

    Ok(res)
}

pub struct Query<P: Policy> {
    pub policy: P,
    pub roots: Seq<SpecCertificateValue>,

    /// `bundle[0]` is the leaf certificate
    pub bundle: Seq<SpecCertificateValue>,

    /// Hostname validation, chain validation, etc.
    pub task: Task,
}

/// High-level specifications for when a query is valid
impl<P: Policy> Query<P> {
    /// Path builder considers certificate C1 an issuer of C2
    /// iff the policy considers so, and the signature verifies
    #[verifier(opaque)]
    pub open spec fn issued(policy: P, issuer: SpecCertificateValue, subject: SpecCertificateValue) -> bool {
        &&& policy.spec_likely_issued(
            policy::Certificate::spec_from(issuer).unwrap(),
            policy::Certificate::spec_from(subject).unwrap(),
        )
        &&& spec_verify_signature(issuer, subject)
    }

    pub open spec fn is_simple_path(self, path: Seq<usize>) -> bool {
        &&& path.len() != 0
        &&& path[0] == 0 // starts from the leaf (i.e. `bundle[0]`)

        // `path` contains unique indices into `self.bundle`
        &&& forall |i| 0 <= i < path.len() ==> 0 <= #[trigger] path[i] < self.bundle.len()
        &&& forall |i, j| 0 <= i < path.len() && 0 <= j < path.len() && i != j ==> path[i] != path[j]

        // `path` = bundle[path[0]] -> ... -> bundle[path.last()]
        &&& forall |i: int| #![trigger path[i]] 0 <= i < path.len() - 1
            ==> Self::issued(self.policy, self.bundle[path[i + 1] as int], self.bundle[path[i] as int])
    }

    /// `path` is a valid simple path from `path[0]` to reach a root certificate
    pub open spec fn is_simple_path_to_root(self, path: Seq<usize>, root_idx: usize) -> bool {
        &&& 0 <= root_idx < self.roots.len()
        &&& self.is_simple_path(path)
        &&& Self::issued(self.policy, self.roots[root_idx as int], self.bundle[path.last() as int])
    }

    /// Check if the candidate chain satisfies the policy constraints
    pub open spec fn path_satisfies_policy(self, path: Seq<usize>, root_idx: usize) -> bool {
        let candidate = path.map_values(|i| self.bundle[i as int]) + seq![self.roots[root_idx as int]];
        let abstract_candidate = candidate.map_values(|cert| policy::Certificate::spec_from(cert).unwrap());
        self.policy.spec_valid_chain(abstract_candidate, self.task)
    }

    pub open spec fn valid(self) -> bool {
        &&& self.bundle.len() != 0
        &&& exists |path: Seq<usize>, root_idx: usize| {
            &&& self.is_simple_path_to_root(path, root_idx)
            &&& self.path_satisfies_policy(path, root_idx)
        }
    }
}

pub struct Validator<'a, P: Policy> {
    pub policy: P,
    pub roots: VecDeep<CertificateValue<'a>>,

    /// Cached RSA public keys of each root certificate
    pub roots_rsa_cache: Vec<Option<rsa::RSAPublicKeyInternal>>,

    /// Abstract representation of each root certificate
    pub roots_abs_cache: Vec<policy::ExecCertificate>,
}

/// Caches within a particular validation job
struct ValidatorCache<'a, 'b, 'c> {
    bundle: &'a VecDeep<CertificateValue<'b>>,
    task: &'c ExecTask,

    /// Cached abstract representation of each certificate
    bundle_abs_cache: Vec<policy::ExecCertificate>,

    /// Cached root issuers of each intermediate certificate
    root_issuers: Vec<Vec<usize>>,
}

impl<'a, 'b, 'c> ValidatorCache<'a, 'b, 'c> {
    closed spec fn wf<P: Policy>(&self, validator: &Validator<'_, P>) -> bool {
        &&& Validator::<P>::is_abs_cache(self.bundle@, self.bundle_abs_cache.deep_view())

        // Valid `root_issuers` cache
        &&& self.root_issuers@.len() == self.bundle@.len()
        &&& forall |i| 0 <= i < self.bundle@.len()
            ==> validator.spec_root_issuers(self.bundle@[i], #[trigger] self.root_issuers@[i]@)
    }

    closed spec fn get_query<P: Policy>(&self, validator: &Validator<'_, P>) -> Query<P> {
        Query {
            policy: validator.policy,
            roots: validator.roots@,
            bundle: self.bundle@,
            task: self.task.deep_view(),
        }
    }
}

impl<'a, P: Policy> Validator<'a, P> {
    /// Initialize a validator struct from parsed root certificates
    #[verifier::loop_isolation(false)]
    pub fn from_parsed_roots(policy: P, roots: VecDeep<CertificateValue<'a>>) -> (res: Result<Self, ValidationError>)
        ensures
            res matches Ok(res) ==> {
                &&& res.wf()
                &&& res.policy == policy
                &&& res.roots == roots
            }
    {
        let roots_len = roots.len();
        let mut roots_rsa_cache = Vec::with_capacity(roots_len);

        // Initialize the RSA key cache by parsing
        // the RSA public key of each root certificate
        for i in 0..roots_len
            invariant
                i == roots_rsa_cache@.len(),
                forall |i| 0 <= i < roots_rsa_cache@.len() ==>
                    (#[trigger] roots_rsa_cache@[i] matches Some(key) ==> {
                        let subject_key = roots@[i].cert.subject_key;
                        &&& subject_key.alg.param is RSAEncryption
                        &&& rsa::spec_pkcs1_v1_5_load_pub_key(BitStringValue::spec_bytes(subject_key.pub_key)) == Some(key)
                    })
        {
            let root = roots.get(i);

            roots_rsa_cache.push(if let AlgorithmParamValue::RSAEncryption(..) = &root.get().cert.get().subject_key.alg.param {
                let pub_key = root.get().cert.get().subject_key.pub_key.bytes();

                match rsa::pkcs1_v1_5_load_pub_key(pub_key) {
                    Ok(pub_key) => Some(pub_key),

                    // NOTE: skip if the pub key of a root certificate fail to parse
                    Err(..) => None,
                }
            } else {
                None
            });
        }

        let roots_abs_cache = Self::get_abs_cache(&roots)?;

        Ok(Validator { policy, roots, roots_rsa_cache, roots_abs_cache })
    }

    /// Initialize a validator from a root store
    pub fn from_root_store(policy: P, store: &'a RootStore) -> (res: Result<Self, ValidationError>)
        ensures
            res matches Ok(res) ==> {
                &&& res.wf()
                &&& res.policy == policy
                &&& res.roots@ =~= store.roots_der@.map_values(|der: Vec<u8>| spec_parse_x509_der(der@).unwrap())
            }
    {
        let roots_len = store.roots_der.len();
        let mut roots = VecDeep::with_capacity(roots_len);

        for i in 0..roots_len
            invariant
                roots_len == store.roots_der@.len(),
                i == roots@.len(),
                forall |i| 0 <= i < roots@.len() ==>
                    spec_parse_x509_der(store.roots_der@[i]@) == Some(#[trigger] roots@[i]),
        {
            roots.push(parse_x509_der(store.roots_der[i].as_slice())?);
        }

        Self::from_parsed_roots(policy, roots)
    }

    pub closed spec fn wf(self) -> bool {
        // RSA public key cache is valid
        &&& self.roots_rsa_cache@.len() == self.roots@.len()
        &&& forall |i| 0 <= i < self.roots@.len() ==>
            (#[trigger] self.roots_rsa_cache@[i] matches Some(key) ==> {
                let subject_key = self.roots@[i].cert.subject_key;

                &&& subject_key.alg.param is RSAEncryption
                &&& rsa::spec_pkcs1_v1_5_load_pub_key(BitStringValue::spec_bytes(subject_key.pub_key)) == Some(key)
            })

        // Abstract representation cache is valid
        &&& Self::is_abs_cache(self.roots@, self.roots_abs_cache.deep_view())
    }

    closed spec fn is_abs_cache(certs: Seq<SpecCertificateValue>, cache: Seq<policy::Certificate>) -> bool
    {
        &&& cache.len() == certs.len()
        &&& forall |i| 0 <= i < certs.len()
            ==> Some(#[trigger] cache[i]) == policy::Certificate::spec_from(certs[i])
    }

    /// Convert each certificate in a list to the abstract representation
    fn get_abs_cache(certs: &VecDeep<CertificateValue<'_>>) -> (res: Result<Vec<policy::ExecCertificate>, ValidationError>)
        ensures
            res matches Ok(res) ==> Self::is_abs_cache(certs@, res.deep_view()),
    {
        let certs_len = certs.len();
        let mut cache = Vec::with_capacity(certs_len);

        for i in 0..certs_len
            invariant
                certs_len == certs@.len(),
                i == cache@.len(),
                forall |j| 0 <= j < i
                    ==> Some(#[trigger] cache.deep_view()[j]) == policy::Certificate::spec_from(certs@[j]),
        {
            let ghost old_cache = cache.deep_view();

            cache.push(policy::Certificate::from(certs.get(i))?);

            assert forall |j| 0 <= j < i + 1 implies
                Some(#[trigger] cache.deep_view()[j]) == policy::Certificate::spec_from(certs@[j])
            by {
                if j < i {
                    assert(cache.deep_view()[j] == old_cache[j]);
                }
            }
        }

        Ok(cache)
    }

    fn check_interm_likely_issued(
        &self,
        cache: &ValidatorCache<'_, '_, '_>,
        issuer_idx: usize,
        subject_idx: usize,
    ) -> (res: bool)
        requires
            cache.wf(self),
            0 <= issuer_idx < cache.bundle@.len(),
            0 <= subject_idx < cache.bundle@.len(),

        ensures
            res == Query::issued(self.policy, cache.bundle@[issuer_idx as int], cache.bundle@[subject_idx as int]),
    {
        reveal(Query::issued);
        let ghost _ = cache.bundle_abs_cache.deep_view()[issuer_idx as int];
        let ghost _ = cache.bundle_abs_cache.deep_view()[subject_idx as int];

        self.policy.likely_issued(&cache.bundle_abs_cache[issuer_idx], &cache.bundle_abs_cache[subject_idx]) &&
        verify_signature(cache.bundle.get(issuer_idx), cache.bundle.get(subject_idx))
    }

    /// A specialized version of `likely_issued`
    /// that uses RSA public key cache of root certs
    fn check_root_likely_issued(
        &self,
        bundle: &VecDeep<CertificateValue<'_>>,
        bundle_abs_cache: &Vec<policy::ExecCertificate>,

        root_idx: usize,
        subject_idx: usize,
    ) -> (res: bool)
        requires
            self.wf(),
            Self::is_abs_cache(bundle@, bundle_abs_cache.deep_view()),
            0 <= root_idx < self.roots@.len(),
            0 <= subject_idx < bundle@.len(),

        ensures res == Query::issued(self.policy, self.roots@[root_idx as int], bundle@[subject_idx as int])
    {
        let root = self.roots.get(root_idx);
        let subject = bundle.get(subject_idx);

        reveal(Query::issued);
        let ghost _ = self.roots_abs_cache.deep_view()[root_idx as int];
        let ghost _ = bundle_abs_cache.deep_view()[subject_idx as int];

        if !self.policy.likely_issued(&self.roots_abs_cache[root_idx], &bundle_abs_cache[subject_idx]) {
            return false;
        }

        // If we have the RSA public key cache for the root certificate, use it instead
        if let Some(pub_key) = &self.roots_rsa_cache[root_idx] {
            // Mostly the same as the RSA branch of `verify_signature`
            let tbs_cert = subject.get().cert.serialize();
            let sig_alg = &subject.get().sig_alg.get();
            let sig = subject.get().sig.bytes();

            if sig_alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA224)) ||
               sig_alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA256)) ||
               sig_alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA384)) ||
               sig_alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA512)) {
                return rsa::pkcs1_v1_5_verify(sig_alg, &pub_key, sig, tbs_cert).is_ok();
            }

            return false;
        }

        verify_signature(root, subject)
    }

    /// Check if a candidate path satisfies the policy
    #[verifier::loop_isolation(false)]
    fn check_chain_policy(
        &self,
        cache: &ValidatorCache<'_, '_, '_>,
        path: &Vec<usize>,
        root_idx: usize,
    ) -> (res: Result<bool, ValidationError>)
        requires
            self.wf(),
            cache.wf(self),
            cache.get_query(self).is_simple_path_to_root(path@, root_idx),

        ensures
            res matches Ok(res) ==>
                res == cache.get_query(self).path_satisfies_policy(path@, root_idx),
    {
        let path_len = path.len();
        if path_len == usize::MAX {
            return Err(ValidationError::IntegerOverflow);
        }

        let mut candidate: Vec<&policy::ExecCertificate> = Vec::with_capacity(path_len + 1);

        // Convert the entire path to `ExecCertificate`
        for i in 0..path_len
            invariant
                path_len == path@.len(),
                cache.get_query(self).is_simple_path_to_root(path@, root_idx),

                candidate@.len() == i,
                forall |j| #![trigger candidate@[j]] 0 <= j < i ==>
                    Some(candidate.deep_view()[j]) == policy::Certificate::spec_from(cache.bundle@[path@[j] as int]),
        {
            let ghost _ = cache.bundle_abs_cache.deep_view()[path@[i as int] as int];
            candidate.push(&cache.bundle_abs_cache[path[i]]);
        }

        // Append the root certificate
        let ghost _ = self.roots_abs_cache.deep_view()[root_idx as int];
        candidate.push(&self.roots_abs_cache[root_idx]);

        assert(candidate.deep_view() =~=
            (path@.map_values(|i| cache.bundle@[i as int]) + seq![self.roots@[root_idx as int]])
                .map_values(|cert| policy::Certificate::spec_from(cert).unwrap()));

        Ok(self.policy.valid_chain(&candidate, &cache.task))
    }

    /// Given a simple path through the bundle certificates
    /// and all root issuers of the last certificate in the path,
    /// check if the entire path satisfies the policy
    #[verifier::loop_isolation(false)]
    #[allow(unexpected_cfgs)]
    fn check_simple_path(
        &self,
        cache: &ValidatorCache<'_, '_, '_>,
        path: &Vec<usize>,
    ) -> (res: Result<bool, ValidationError>)
        requires
            self.wf(),
            cache.wf(self),
            cache.get_query(self).is_simple_path(path@),

        ensures
            res matches Ok(res) ==>
                res == exists |root_idx: usize|
                    #[trigger] cache.get_query(self).is_simple_path_to_root(path@, root_idx) &&
                    cache.get_query(self).path_satisfies_policy(path@, root_idx)
    {
        reveal(Validator::spec_root_issuers);

        let last = path[path.len() - 1];

        let root_issuers = &cache.root_issuers[last];
        let root_issuers_len = root_issuers.len();
        let ghost query = cache.get_query(self);

        for i in 0..root_issuers_len
            invariant
                forall |j| 0 <= j < i ==>
                    !query.path_satisfies_policy(path@, #[trigger] root_issuers@[j]),
        {
            #[cfg(feature = "trace")]
            eprintln_join!("checking path: ", format_dbg(path), " w/ root ", root_issuers[i]);

            if self.check_chain_policy(cache, &path, root_issuers[i])? {
                // Found a valid chain
                return Ok(true);
            }
        }

        assert forall |root_idx: usize|
            #[trigger] query.is_simple_path_to_root(path@, root_idx) implies
            !query.path_satisfies_policy(path@, root_idx)
        by {
            assert(root_issuers@.contains(root_idx));
        }

        Ok(false)
    }

    #[verifier::opaque]
    closed spec fn spec_root_issuers(self, cert: SpecCertificateValue, indices: Seq<usize>) -> bool {
        // All in-bound
        &&& forall |i| 0 <= i < indices.len() ==> 0 <= #[trigger] indices[i] < self.roots@.len()

        // Contains all likely root issuers
        &&& forall |i| 0 <= i < self.roots@.len() &&
            Query::issued(self.policy, self.roots@[i as int], cert) ==>
            #[trigger] indices.contains(i)

        // Only contains likely root issuers
        &&& forall |i| 0 <= i < indices.len() ==>
            Query::issued(self.policy, self.roots@[#[trigger] indices[i] as int], cert)
    }

    /// Get indices of root certificates that likely issued the given certificate
    #[verifier::loop_isolation(false)]
    fn get_root_issuer(
        &self,
        bundle: &VecDeep<CertificateValue<'_>>,
        bundle_abs_cache: &Vec<policy::ExecCertificate>,
        idx: usize,
    ) -> (res: Vec<usize>)
        requires
            self.wf(),
            Self::is_abs_cache(bundle@, bundle_abs_cache.deep_view()),
            0 <= idx < bundle@.len(),

        ensures self.spec_root_issuers(bundle@[idx as int], res@)
    {
        let mut res = Vec::with_capacity(1); // usually there is only 1 root issuer
        let roots_len = self.roots.len();

        let ghost root_indices = Seq::new(self.roots@.len() as nat, |i| i as usize);
        let ghost pred = |j: usize| Query::issued(self.policy, self.roots@[j as int], bundle@[idx as int]);

        for i in 0..roots_len
            invariant
                forall |i| 0 <= i < res.len() ==> 0 <= #[trigger] res[i] < self.roots@.len(),
                res@ =~= root_indices.take(i as int).filter(pred),
        {
            reveal_with_fuel(Seq::<_>::filter, 1);

            if self.check_root_likely_issued(bundle, bundle_abs_cache, i, idx) {
                res.push(i);
            }

            assert(root_indices.take(i + 1).drop_last() =~= root_indices.take(i as int));
        }

        assert(root_indices.take(roots_len as int) == root_indices);

        assert forall |i|
            0 <= i < self.roots@.len() &&
            Query::issued(self.policy, self.roots@[i as int], bundle@[idx as int])
            implies #[trigger] res@.contains(i)
        by {
            assert(root_indices[i as int] == i);
            assert(pred(root_indices[i as int]));
        }

        reveal(Validator::spec_root_issuers);

        res
    }

    /// Initialize a validator cache for later validation
    #[verifier::loop_isolation(false)]
    fn new_cache<'b, 'c, 'd>(
        &self,
        bundle: &'b VecDeep<CertificateValue<'c>>,
        task: &'d policy::ExecTask,
    ) -> (res: Result<ValidatorCache<'b, 'c, 'd>, ValidationError>)
        requires self.wf(),
        ensures
            res matches Ok(res) ==> {
                &&& res.wf(self)
                &&& res.bundle == bundle
                &&& res.task == task
            },
    {
        let bundle_len = bundle.len();

        // Cache abstract representation of each certificate
        let bundle_abs_cache = Self::get_abs_cache(bundle)?;

        // root_issuers[i] are the indices of root certificates that likely issued bundle[i]
        let mut root_issuers: Vec<Vec<usize>> = Vec::with_capacity(bundle_len);

        // Collect all root issuers for each certificate in the bundle
        for i in 0..bundle_len
            invariant
                root_issuers@.len() == i,
                forall |j| 0 <= j < i ==>
                    self.spec_root_issuers(bundle@[j], #[trigger] root_issuers@[j]@),
        {
            root_issuers.push(self.get_root_issuer(bundle, &bundle_abs_cache, i));
        }

        Ok(ValidatorCache {
            bundle: bundle,
            task: task,
            bundle_abs_cache: bundle_abs_cache,
            root_issuers: root_issuers,
        })
    }

    /// Validate a leaf certificate (bundle[0]) against
    /// a task and try to build a valid chain through
    /// the `bundle` of intermediate certificates
    #[verifier::loop_isolation(false)]
    #[verifier::exec_allows_no_decreases_clause]
    pub fn validate(
        &self,
        bundle: &VecDeep<CertificateValue<'_>>,
        task: &policy::ExecTask,
    ) -> (res: Result<bool, ValidationError>)
        requires self.wf()
        ensures
            // Soundness & completeness (modulo ValidationError)
            res matches Ok(res) ==> res == (Query {
                policy: self.policy,
                roots: self.roots@,
                bundle: bundle@,
                task: task.deep_view(),
            }).valid(),
    {
        if bundle.len() == 0 {
            return Err(ValidationError::EmptyChain);
        }

        let cache = self.new_cache(bundle, task)?;

        let bundle_len = bundle.len();
        let ghost query = cache.get_query(self);

        // DFS from bundle[0] to try to reach a root
        // Stack of path prefices to explore
        let mut stack: Vec<Vec<usize>> = vec![ vec![ 0 ] ];

        // For triggering quantifiers associated with the leaf
        let ghost _ = stack@[0]@;

        loop
            invariant
                forall |i| 0 <= i < stack.len() ==> query.is_simple_path(#[trigger] stack@[i]@),

                // For completeness: any simple path not prefixed by elements in
                // the current stack should be already confirmed as invalid
                forall |path: Seq<usize>, root_idx: usize|
                    #[trigger] query.is_simple_path_to_root(path, root_idx) &&
                    (forall |i| 0 <= i < stack.len() ==>
                        !is_prefix_of(#[trigger] stack@[i]@, path))
                    ==>
                    !query.path_satisfies_policy(path, root_idx),
        {
            let ghost prev_stack = stack@;

            if let Some(cur_path) = stack.pop() {
                let last = cur_path[cur_path.len() - 1];

                if self.check_simple_path(&cache, &cur_path)? {
                    return Ok(true);
                }

                // Push any extension of `path` that is still a simple path
                for i in 0..bundle_len
                    invariant
                        stack@.len() >= prev_stack.len() - 1,
                        forall |i| 0 <= i < prev_stack.len() - 1 ==>
                            stack@[i] == #[trigger] prev_stack[i],

                        // For any other `path` prefixed by `cur_path` (and longer than it)
                        // either `path` is prefixed by some path in the stack
                        // or `path`'s next node >= i
                        forall |path: Seq<usize>|
                            #[trigger] is_prefix_of(cur_path@, path) &&
                            query.is_simple_path(path) &&
                            path.len() > cur_path@.len() &&
                            path[cur_path@.len() as int] < i
                            ==>
                            exists |j| 0 <= j < stack@.len() && is_prefix_of(#[trigger] stack@[j]@, path),

                        // Stack invariant: all paths in the stack are simple paths
                        forall |i| 0 <= i < stack.len() ==> query.is_simple_path(#[trigger] stack@[i]@),
                {
                    let ghost prev_stack = stack@;

                    if !vec_contains(&cur_path, &i) && self.check_interm_likely_issued(&cache, i, last) {
                        let mut next_path = Clone::clone(&cur_path);
                        next_path.push(i);
                        stack.push(next_path);
                    }

                    assert forall |path: Seq<usize>|
                        #[trigger] is_prefix_of(cur_path@, path) &&
                        query.is_simple_path(path) &&
                        path.len() > cur_path@.len() &&
                        path[cur_path@.len() as int] < i + 1
                        implies
                        exists |j| 0 <= j < stack@.len() && is_prefix_of(#[trigger] stack@[j]@, path)
                    by {
                        if path[cur_path@.len() as int] == i {
                            if cur_path@.contains(i) {
                                // Not a simple path
                                let k = choose |k| 0 <= k < cur_path@.len() && cur_path@[k] == i;
                                assert(path[k] == i);
                            } else if !Query::issued(self.policy, cache.bundle@[i as int], cache.bundle@[last as int]) {
                                // Not a path
                                assert(path[cur_path@.len() - 1] == i);
                            } else {
                                // Path was just added
                                assert(is_prefix_of(stack@[stack@.len() - 1]@, path));
                            }
                        } else {
                            // By loop invariant
                            let k = choose |k| 0 <= k < prev_stack.len() && is_prefix_of(#[trigger] prev_stack[k]@, path);
                            assert(stack@[k] == prev_stack[k]);
                        }
                    }
                }

                // Check the completeness invariant
                // For any path starting `bundle[0]`
                // that does NOT have any of the stack
                // elements as prefix, should not have
                // a simple valid path to a root
                assert forall |path: Seq<usize>, root_idx: usize|
                    #[trigger] query.is_simple_path_to_root(path, root_idx) &&
                    (forall |i| 0 <= i < stack.len() ==>
                        !is_prefix_of(#[trigger] stack@[i]@, path))
                    implies
                    // No valid simple path to root
                    !query.path_satisfies_policy(path, root_idx)
                by {
                    if !is_prefix_of(cur_path@, path) {
                        assert(forall |i| 0 <= i < prev_stack.len()
                            ==> !is_prefix_of(#[trigger] prev_stack[i]@, path));
                    } else {
                        if path.len() <= cur_path@.len() {
                            assert(path =~= cur_path@);
                            // By post-condition of check_simple_path
                        } // else by LI of the inner loop
                    }
                }

            } else {
                // assert(forall |path: Seq<usize>, root_idx: usize|
                //     #[trigger] query.is_simple_path_to_root(path, root_idx) ==>
                //     !query.path_satisfies_policy(path, root_idx));
                // assert(!query.valid());
                return Ok(false);
            }
        }
    }

    /// Same as `validate`, but parses certificates from DER
    pub fn validate_der(&self, bundle: &Vec<Vec<u8>>, task: &policy::ExecTask) -> (res: Result<bool, ValidationError>)
        requires
            self.wf(),
            bundle@.len() != 0,

        ensures
            // Soundness & completeness (modulo ValidationError)
            res matches Ok(res) ==>
                res == (Query {
                    policy: self.policy,
                    roots: self.roots@,
                    bundle: bundle@.map_values(|der: Vec<u8>| spec_parse_x509_der(der@).unwrap()),
                    task: task.deep_view(),
                }).valid(),
    {
        let bundle_len = bundle.len();
        let mut bundle_parsed: VecDeep<CertificateValue<'_>> = VecDeep::with_capacity(bundle_len);

        for i in 0..bundle_len
            invariant
                bundle_len == bundle@.len(),
                bundle_parsed@.len() == i,
                forall |j| 0 <= j < i ==> spec_parse_x509_der(bundle@[j]@) == Some(#[trigger] bundle_parsed@[j]),
        {
            bundle_parsed.push(parse_x509_der(bundle[i].as_slice())?);
        }
        assert(bundle_parsed@ =~= bundle@.map_values(|der: Vec<u8>| spec_parse_x509_der(der@).unwrap()));

        self.validate(&bundle_parsed, task)
    }

    /// Same as `validate`, but parses certificates from Base64
    pub fn validate_base64(&self, bundle: &Vec<Vec<u8>>, task: &policy::ExecTask) -> (res: Result<bool, ValidationError>)
        requires
            self.wf(),
            bundle@.len() != 0,

        ensures
            // Soundness & completeness (modulo ValidationError)
            res matches Ok(res) ==>
                res == (Query {
                    policy: self.policy,
                    roots: self.roots@,
                    bundle: bundle@.map_values(|base64: Vec<u8>| spec_parse_x509_base64(base64@).unwrap()),
                    task: task.deep_view(),
                }).valid(),
    {
        let bundle_len = bundle.len();
        let mut bundle_der: Vec<Vec<u8>> = Vec::with_capacity(bundle_len);

        for i in 0..bundle_len
            invariant
                bundle_len == bundle@.len(),
                bundle_der@.len() == i,
                forall |j| 0 <= j < i ==> spec_decode_base64(bundle@[j]@) == Some(#[trigger] bundle_der@[j]@),
        {
            bundle_der.push(decode_base64(bundle[i].as_slice())?);
        }

        assert(
            bundle_der@.map_values(|der: Vec<u8>| spec_parse_x509_der(der@).unwrap())
            =~=
            bundle@.map_values(|base64: Vec<u8>| spec_parse_x509_base64(base64@).unwrap())
        );

        self.validate_der(&bundle_der, task)
    }
}

pub struct RootStore {
    /// DER encodings of all root certificates
    pub roots_der: Vec<Vec<u8>>,
}

impl RootStore {
    pub fn from_owned_der(roots_der: Vec<Vec<u8>>) -> RootStore {
        RootStore { roots_der }
    }

    /// Creates a root store from base64 encodings of root certificates
    pub fn from_base64(roots_base64: &Vec<Vec<u8>>) -> (res: Result<RootStore, ParseError>)
        ensures
            res matches Ok(res) ==> {
                &&& res.roots_der@.len() == roots_base64.len()
                &&& forall |i| 0 <= i < roots_base64@.len() ==>
                        spec_decode_base64(#[trigger] roots_base64@[i]@) == Some(res.roots_der@[i]@)
            },
            res is Err ==>
                exists |i| 0 <= i < roots_base64.len() &&
                    spec_decode_base64(#[trigger] roots_base64@[i]@) is None,
    {
        let mut roots_der: Vec<Vec<u8>> = Vec::with_capacity(roots_base64.len());
        let len = roots_base64.len();

        for i in 0..len
            invariant
                len == roots_base64@.len(),
                roots_der@.len() == i,
                forall |j| 0 <= j < i ==>
                    spec_decode_base64(#[trigger] roots_base64@[j]@) == Some(roots_der@[j]@),
        {
            roots_der.push(decode_base64(roots_base64[i].as_slice())?);
        }

        Ok(RootStore { roots_der })
    }
}

}

impl<'a, P: Policy> Validator<'a, P> {
    /// Debug utility to print some information about the chain being validated
    pub fn print_debug_info(&self, chain_base64: &Vec<Vec<u8>>, task: &ExecTask)
        -> Result<(), ValidationError> {
        eprintln!("=================== task info ===================");
        // Print some general information about the certs
        eprintln!("{} root certificate(s)", self.roots.len());
        eprintln!("{} chain certificate(s)", chain_base64.len());

        let chain_der = chain_base64.iter().map(|base64| decode_base64(base64)).collect::<Result<Vec<_>, _>>()?;
        let chain = chain_der.iter().map(|der| parse_x509_der(der)).collect::<Result<Vec<_>, _>>()?;
        let chain_abs = chain.iter().map(|cert| policy::Certificate::from(cert)).collect::<Result<Vec<_>, _>>()?;

        // Check that for each i, cert[i + 1] issued cert[i]
        for i in 0..chain.len() {
            for j in 0..chain.len() {
                if self.policy.likely_issued(&chain_abs[i], &chain_abs[j]) {
                    eprintln!("cert {} issued cert {}", i, j);
                }
            }
        }

        let mut used_roots = Vec::new();

        // Check if root cert issued any of the chain certs
        for (i, root) in self.roots_abs_cache.iter().enumerate() {
            let mut used = false;

            for (j, chain_cert) in chain_abs.iter().enumerate() {
                if self.policy.likely_issued(root, chain_cert) {
                    used = true;
                    eprintln!("root cert {} issued cert {}", i, j);
                }
            }

            if used {
                used_roots.push(i);
            }
        }

        let print_cert = |cert: &x509::CertificateValue<'_>| {
            eprintln!("  subject: {}", cert.get().cert.get().subject);
            eprintln!("  issued by: {}", cert.get().cert.get().issuer);
            eprintln!("  signed with: {:?}", cert.get().sig_alg);
            eprintln!("  subject key: {:?}", cert.get().cert.get().subject_key.alg);
            eprintln!("  from: {:?}", cert.get().cert.get().validity.not_before);
            eprintln!("  to: {:?}", cert.get().cert.get().validity.not_after);
        };

        for (i, cert) in chain.iter().enumerate() {
            eprintln!("cert {}:", i);
            print_cert(cert);
        }

        for i in used_roots.iter() {
            eprintln!("root cert {}:", i);
            print_cert(self.roots.get(*i));
        }

        eprintln!("task: {:?}", task);

        // eprintln!("timestamp: {} ({})", now, match DateTime::<Utc>::from_timestamp(now as i64, 0) {
        //     Some(dt) => dt.to_string(),
        //     None => "invalid".to_string(),
        // });

        for (i, cert) in chain_abs.iter().enumerate() {
            eprintln!("abstract cert {}:", i);
            eprintln!("  {:?}", cert);
        }

        for i in used_roots.iter() {
            eprintln!("abstract root cert {}:", i);
            eprintln!("  {:?}", &self.roots_abs_cache[*i]);
        }

        eprintln!("=================== end task info ===================");

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use policy::{ChromePolicy, ExecPurpose, FirefoxPolicy, OpenSSLPolicy};

    use super::*;

    /// Extract a list of base64 encoded certificates from a PEM-encoded string
    fn pem_to_base64(pem: &str) -> Vec<Vec<u8>> {
        const BEGIN: &'static str = "-----BEGIN CERTIFICATE-----";
        const END: &'static str = "-----END CERTIFICATE-----";

        pem.split(BEGIN)
            .skip(1)
            .filter_map(|part|
                // Remove suffix
                part.split(END).next().map(|cert|
                    // Remove whitespaces
                    cert.chars()
                        .filter(|c| !c.is_whitespace())
                        .collect::<String>()
                        .into_bytes()))
            .collect()
    }

    const TESTS: &[(&str, &str, u64, bool)] = &[
        (include_str!("../tests/chains/github.pem"), "github.com", 1725029869, true),
        (include_str!("../tests/chains/google.pem"), "google.com", 1725029869, true),
        (include_str!("../tests/chains/outlook.pem"), "outlook.com", 1725029869, true),
        (include_str!("../tests/chains/slack.pem"), "slack.com", 1725029869, true),
        (include_str!("../tests/chains/verus.pem"), "verus.rs", 1725029869, true),
    ];

    macro_rules! test_policy {
        ($policy:expr) => {
            let roots_base64 = pem_to_base64(include_str!("../tests/roots.pem"));

            for (pem, hostname, now, expected) in TESTS {
                let chain_base64 = pem_to_base64(pem);

                let res = validate_x509_base64(
                    &roots_base64,
                    &chain_base64,
                    $policy,
                    &ExecTask {
                        hostname: Some(hostname.to_string()),
                        purpose: ExecPurpose::ServerAuth,
                        now: *now,
                    }
                );

                assert!(res.is_ok());
                assert_eq!(res.unwrap(), *expected);
            }
        }
    }

    #[test]
    fn test_well_known_sites_chrome() {
        test_policy!(ChromePolicy::default());
    }

    #[test]
    fn test_well_known_sites_firefox() {
        test_policy!(FirefoxPolicy::default());
    }

    #[test]
    fn test_well_known_sites_openssl() {
        test_policy!(OpenSSLPolicy::default());
    }
}
