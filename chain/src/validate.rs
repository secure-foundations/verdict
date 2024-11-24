/// The high-level spec and impl of chain validation

use vstd::prelude::*;

use parser::{*, x509::*};

use crate::policy;
use crate::issue::*;
use crate::error::*;

verus! {

pub struct Query {
    pub policy: policy::Policy,
    pub roots: Seq<SpecCertificateValue>,

    /// `bundle[0]` is the leaf certificate
    pub bundle: Seq<SpecCertificateValue>,

    /// Hostname validation, chain validation, etc.
    pub task: policy::Task,
}

/// High-level specifications for when a query is valid
impl Query {
    pub open spec fn is_simple_path(self, path: Seq<usize>) -> bool {
        &&& path.len() != 0
        &&& path[0] == 0 // starts from the leaf (i.e. `bundle[0]`)

        // `path` contains unique indices into `self.bundle`
        &&& forall |i| 0 <= i < path.len() ==> 0 <= #[trigger] path[i] < self.bundle.len()
        &&& forall |i, j| 0 <= i < path.len() && 0 <= j < path.len() && i != j ==> path[i] != path[j]

        // `path` = bundle[path[0]] -> ... -> bundle[path.last()]
        &&& forall |i: int| #![trigger path[i]] 0 <= i < path.len() - 1 ==>
            spec_likely_issued(self.bundle[path[i + 1] as int], self.bundle[path[i] as int])
    }

    /// `path` is a valid simple path from `path[0]` to reach a root certificate
    pub open spec fn is_simple_path_to_root(self, path: Seq<usize>, root_idx: usize) -> bool {
        &&& 0 <= root_idx < self.roots.len()
        &&& self.is_simple_path(path)
        &&& spec_likely_issued(self.roots[root_idx as int], self.bundle[path.last() as int])
    }

    /// Check if the candidate chain satisfies the policy constraints
    pub open spec fn path_satisfies_policy(self, path: Seq<usize>, root_idx: usize) -> bool {
        let candidate = path.map_values(|i| self.bundle[i as int]) + seq![self.roots[root_idx as int]];
        let abstract_candidate = candidate.map_values(|cert| policy::Certificate::spec_from(cert).unwrap());
        policy::valid_chain(&self.policy, &abstract_candidate, &self.task) == policy::PolicyResult::Valid
    }

    pub open spec fn valid(self) -> bool {
        &&& self.bundle.len() != 0
        &&& exists |path: Seq<usize>, root_idx: usize| {
            &&& self.is_simple_path_to_root(path, root_idx)
            &&& self.path_satisfies_policy(path, root_idx)
        }
    }
}

pub struct Validator<'a> {
    pub policy: policy::ExecPolicy,
    pub roots: VecDeep<CertificateValue<'a>>,
}

impl<'a> Validator<'a> {
    pub fn new(policy: policy::ExecPolicy, roots: VecDeep<CertificateValue<'a>>) -> (res: Validator<'a>)
        ensures
            res.policy == policy,
            res.roots == roots,
    {
        Validator { policy, roots }
    }

    closed spec fn is_prefix_of<T>(s1: Seq<T>, s2: Seq<T>) -> bool {
        &&& s1.len() <= s2.len()
        &&& forall |i| 0 <= i < s1.len() ==> #[trigger] s1[i] == #[trigger] s2[i]
    }

    fn has_node(path: &Vec<usize>, node: usize) -> (res: bool)
        ensures res == path@.contains(node)
    {
        let path_len = path.len();

        for i in 0..path_len
            invariant
                path_len == path@.len(),
                forall |j| 0 <= j < i ==> path@[j] != node,
        {
            if path[i] == node {
                return true;
            }
        }

        return false;
    }

    pub open spec fn get_query(
        &self,
        bundle: Seq<SpecCertificateValue>,
        task: policy::Task,
    ) -> Query {
        Query {
            policy: self.policy.deep_view(),
            roots: self.roots@,
            bundle: bundle,
            task: task,
        }
    }

    /// Check if a candidate path satisfies the policy
    /// TODO: cache `policy::Certificate::from` results
    fn check_chain_policy(
        &self,
        bundle: &VecDeep<CertificateValue>,
        task: &policy::ExecTask,
        path: &Vec<usize>,
        root_idx: usize,
    ) -> (res: Result<bool, ValidationError>)
        requires
            self.get_query(bundle@, task.deep_view()).is_simple_path_to_root(path@, root_idx),

        ensures
            res matches Ok(res) ==>
                res == self.get_query(bundle@, task.deep_view()).path_satisfies_policy(path@, root_idx),
    {
        let mut candidate: Vec<policy::ExecCertificate> = Vec::new();
        let path_len = path.len();

        // Convert the entire path to `ExecCertificate`
        for i in 0..path_len
            invariant
                path_len == path@.len(),
                self.get_query(bundle@, task.deep_view()).is_simple_path_to_root(path@, root_idx),

                candidate@.len() == i,
                forall |j| #![trigger candidate@[j]] 0 <= j < i ==>
                    Some(candidate@[j].deep_view()) == policy::Certificate::spec_from(bundle@[path@[j] as int]),
        {
            candidate.push(policy::Certificate::from(bundle.get(path[i]))?);
        }

        // Append the root certificate
        candidate.push(policy::Certificate::from(self.roots.get(root_idx))?);

        assert(candidate.deep_view() =~=
            (path@.map_values(|i| bundle@[i as int]) + seq![self.roots@[root_idx as int]])
                .map_values(|cert| policy::Certificate::spec_from(cert).unwrap()));

        match policy::exec_valid_chain(&self.policy, &candidate, task) {
            policy::ExecPolicyResult::Valid => Ok(true),
            policy::ExecPolicyResult::Invalid => Ok(false),
            policy::ExecPolicyResult::UnsupportedTask => Err(ValidationError::UnsupportedTask),
        }
    }

    /// Given a simple path through the bundle certificates
    /// and all root issuers of the last certificate in the path,
    /// check if the entire path satisfies the policy
    fn check_simple_path(
        &self,
        bundle: &VecDeep<CertificateValue>,
        task: &policy::ExecTask,

        path: &Vec<usize>,
        root_issuers: &Vec<usize>,
    ) -> (res: Result<bool, ValidationError>)
        requires
            self.get_query(bundle@, task.deep_view()).is_simple_path(path@),
            self.spec_root_issuers(bundle@[path@.last() as int], root_issuers@),

        ensures
            res matches Ok(res) ==>
                res == exists |root_idx: usize|
                    #[trigger] self.get_query(bundle@, task.deep_view()).is_simple_path_to_root(path@, root_idx) &&
                    self.get_query(bundle@, task.deep_view()).path_satisfies_policy(path@, root_idx)
    {
        reveal(Validator::spec_root_issuers);

        let root_issuers_len = root_issuers.len();
        let ghost query = self.get_query(bundle@, task.deep_view());

        #[verifier::loop_isolation(false)]
        for i in 0..root_issuers_len
            invariant
                forall |j| 0 <= j < i ==>
                    !query.path_satisfies_policy(path@, #[trigger] root_issuers@[j]),
        {
            if self.check_chain_policy(bundle, task, &path, root_issuers[i])? {
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

    closed spec fn get_root_indices(self) -> Seq<usize> {
        Seq::new(self.roots@.len() as nat, |i| i as usize)
    }

    #[verifier::opaque]
    closed spec fn spec_root_issuers(self, cert: SpecCertificateValue, indices: Seq<usize>) -> bool {
        // All in-bound
        &&& forall |i| 0 <= i < indices.len() ==> 0 <= #[trigger] indices[i] < self.roots@.len()

        // Contains all likely root issuers
        &&& forall |i| 0 <= i < self.roots@.len() &&
            spec_likely_issued(self.roots@[i as int], cert) ==>
            #[trigger] indices.contains(i)

        // Only contains likely root issuers
        &&& forall |i| 0 <= i < indices.len() ==>
            spec_likely_issued(self.roots@[#[trigger] indices[i] as int], cert)
    }

    /// Get indices of root certificates that likely issued the given certificate
    fn get_root_issuer(&self, cert: &CertificateValue) -> (res: Vec<usize>)
        ensures self.spec_root_issuers(cert@, res@)
    {
        let mut res = Vec::new();
        let roots_len = self.roots.len();

        let ghost pred = |j: usize| spec_likely_issued(self.roots@[j as int], cert@);

        #[verifier::loop_isolation(false)]
        for i in 0..roots_len
            invariant
                forall |i| 0 <= i < res.len() ==> 0 <= #[trigger] res[i] < self.roots@.len(),
                res@ =~= self.get_root_indices().take(i as int).filter(pred),
        {
            reveal_with_fuel(Seq::<_>::filter, 1);

            if likely_issued(self.roots.get(i), cert) {
                res.push(i);
            }

            assert(self.get_root_indices().take(i + 1).drop_last() =~= self.get_root_indices().take(i as int));
        }

        assert(self.get_root_indices().take(roots_len as int) == self.get_root_indices());

        assert forall |i|
            0 <= i < self.roots@.len() &&
            spec_likely_issued(self.roots@[i as int], cert@)
            implies #[trigger] res@.contains(i)
        by {
            assert(self.get_root_indices()[i as int] == i);
            assert(pred(self.get_root_indices()[i as int]));
        }

        reveal(Validator::spec_root_issuers);

        res
    }

    /// Validate a leaf certificate (bundle[0]) against
    /// a task and try to build a valid chain through
    /// the `bundle` of intermediate certificates
    #[verifier::loop_isolation(false)]
    pub fn validate(
        &self,
        bundle: &VecDeep<CertificateValue>,
        task: &policy::ExecTask,
    ) -> (res: Result<bool, ValidationError>)
        requires bundle@.len() != 0,

        ensures
            // Soundness & completeness (modulo ValidationError)
            res matches Ok(res) ==> res == self.get_query(bundle@, task.deep_view()).valid(),
    {
        let bundle_len = bundle.len();
        let roots_len = self.roots.len();

        // root_issuers[i] are the indices of root certificates that likely issued bundle[i]
        let mut root_issuers: Vec<Vec<usize>> = Vec::new();

        // Collect all root issuers for each certificate in the bundle
        for i in 0..bundle_len
            invariant
                root_issuers@.len() == i,
                forall |j| 0 <= j < i ==>
                    self.spec_root_issuers(bundle@[j], #[trigger] root_issuers@[j]@),
        {
            root_issuers.push(self.get_root_issuer(bundle.get(i)));
        }

        let ghost query = self.get_query(bundle@, task.deep_view());

        // DFS from bundle[0] to try to reach a root
        // Stack of path prefices to explore
        let mut stack: Vec<Vec<usize>> = Vec::new();
        stack.push(vec![ 0 ]);

        let ghost _ = stack@[0]@;

        loop
            invariant
                forall |i| 0 <= i < stack.len() ==> query.is_simple_path(#[trigger] stack@[i]@),

                // For completeness: any simple path not prefixed by elements in
                // the current stack should be already confirmed as invalid
                forall |path: Seq<usize>, root_idx: usize|
                    #[trigger] query.is_simple_path_to_root(path, root_idx) &&
                    (forall |i| 0 <= i < stack.len() ==>
                        !Self::is_prefix_of(#[trigger] stack@[i]@, path))
                    ==>
                    !query.path_satisfies_policy(path, root_idx),
        {
            let ghost prev_stack = stack@;

            if let Some(cur_path) = stack.pop() {
                let last = cur_path[cur_path.len() - 1];

                if self.check_simple_path(bundle, task, &cur_path, &root_issuers[last])? {
                    return Ok(true);
                }

                // Push any extension of `path` that is still a simple path
                #[verifier::loop_isolation(false)]
                for i in 0..bundle_len
                    invariant
                        stack@.len() >= prev_stack.len() - 1,
                        forall |i| 0 <= i < prev_stack.len() - 1 ==>
                            stack@[i] == #[trigger] prev_stack[i],

                        // For any other `path` prefixed by `cur_path` (and longer than it)
                        // either `path` is prefixed by some path in the stack
                        // or `path`'s next node >= i
                        forall |path: Seq<usize>|
                            #[trigger] Self::is_prefix_of(cur_path@, path) &&
                            query.is_simple_path(path) &&
                            path.len() > cur_path@.len() &&
                            path[cur_path@.len() as int] < i
                            ==>
                            exists |j| 0 <= j < stack@.len() && Self::is_prefix_of(#[trigger] stack@[j]@, path),

                        // Stack invariant: all paths in the stack are simple paths
                        forall |i| 0 <= i < stack.len() ==> query.is_simple_path(#[trigger] stack@[i]@),
                {
                    let ghost prev_stack = stack@;

                    if !Self::has_node(&cur_path, i) && likely_issued(bundle.get(i), bundle.get(last)) {
                        let mut next_path = Clone::clone(&cur_path);
                        next_path.push(i);
                        stack.push(next_path);
                    }

                    assert forall |path: Seq<usize>|
                        #[trigger] Self::is_prefix_of(cur_path@, path) &&
                        query.is_simple_path(path) &&
                        path.len() > cur_path@.len() &&
                        path[cur_path@.len() as int] < i + 1
                        implies
                        exists |j| 0 <= j < stack@.len() && Self::is_prefix_of(#[trigger] stack@[j]@, path)
                    by {
                        if path[cur_path@.len() as int] == i {
                            if cur_path@.contains(i) {
                                // Not a simple path
                                let k = choose |k| 0 <= k < cur_path@.len() && cur_path@[k] == i;
                                assert(path[k] == i);
                            } else if !spec_likely_issued(bundle@[i as int], bundle@[last as int]) {
                                // Not a path
                                assert(path[cur_path@.len() - 1] == i);
                            } else {
                                // Path was just added
                                assert(Self::is_prefix_of(stack@[stack@.len() - 1]@, path));
                            }
                        } else {
                            // By loop invariant
                            let k = choose |k| 0 <= k < prev_stack.len() && Self::is_prefix_of(#[trigger] prev_stack[k]@, path);
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
                        !Self::is_prefix_of(#[trigger] stack@[i]@, path))
                    implies
                    // No valid simple path to root
                    !query.path_satisfies_policy(path, root_idx)
                by {
                    if !Self::is_prefix_of(cur_path@, path) {
                        assert(forall |i| 0 <= i < prev_stack.len()
                            ==> !Self::is_prefix_of(#[trigger] prev_stack[i]@, path));
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

    pub fn validate_hostname(&self, bundle: &VecDeep<CertificateValue>, domain: &str) -> (res: Result<bool, ValidationError>)
        requires bundle@.len() != 0,

        ensures
            res matches Ok(res) ==> res == self.get_query(bundle@, policy::Task::DomainValidation(domain@)).valid(),
    {
        self.validate(bundle, &policy::ExecTask::DomainValidation(domain.to_string()))
    }

    pub fn validate_purpose(&self, bundle: &VecDeep<CertificateValue>, purpose: policy::ExecPurpose) -> (res: Result<bool, ValidationError>)
        requires bundle@.len() != 0,

        ensures
            res matches Ok(res) ==> res == self.get_query(bundle@, policy::Task::ChainValidation(purpose.deep_view())).valid(),
    {
        self.validate(bundle, &policy::ExecTask::ChainValidation(purpose))
    }

    pub fn get_validation_time(&self) -> u64
    {
        match &self.policy {
            policy::ExecPolicy::Chrome(env) => env.time,
            policy::ExecPolicy::Firefox(env) => env.time,
            policy::ExecPolicy::OpenSSL(env) => env.time,
        }
    }
}

/// Some helper functions to generate different policies
impl policy::ExecPolicy {
    #[verifier::external_body]
    fn strs_to_strings(strs: &[&str]) -> (res: Vec<String>)
        ensures res.deep_view() == strs.deep_view()
    {
        strs.iter().map(|s| s.to_string()).collect()
    }

    /// Chrome policy in Hammurabi
    pub fn chrome_hammurabi(time: u64) -> policy::ExecPolicy {
        policy::ExecPolicy::Chrome(policy::ExecChromeEnvironment {
            time,

            public_suffix: Self::strs_to_strings(&["uk", "ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "nhs.uk", "org.uk", "plc.uk", "police.uk", "ch.uk", "us", "dni.us", "fed.us", "isa.us", "kids.us", "nsn.us", "ak.us", "al.us", "ar.us", "as.us", "az.us", "ca.us", "co.us", "ct.us", "dc.us", "de.us", "fl.us", "ga.us", "gu.us", "hi.us", "ia.us", "id.us", "il.us", "in.us", "ks.us", "ky.us", "la.us", "ma.us", "md.us", "me.us", "mi.us", "mn.us", "mo.us", "ms.us", "mt.us", "nc.us", "nd.us", "ne.us", "nh.us", "nj.us", "nm.us", "nv.us", "ny.us", "oh.us", "ok.us", "or.us", "pa.us", "pr.us", "ri.us", "sc.us", "sd.us", "tn.us", "tx.us", "ut.us", "vi.us", "vt.us", "va.us", "wa.us", "wi.us", "wv.us", "wy.us", "k12.ak.us", "k12.al.us", "k12.ar.us", "k12.as.us", "k12.az.us", "k12.ca.us", "k12.co.us", "k12.ct.us", "k12.dc.us", "k12.de.us", "k12.fl.us", "k12.ga.us", "k12.gu.us", "k12.ia.us", "k12.id.us", "k12.il.us", "k12.in.us", "k12.ks.us", "k12.ky.us", "k12.la.us", "k12.ma.us", "k12.md.us", "k12.me.us", "k12.mi.us", "k12.mn.us", "k12.mo.us", "k12.ms.us", "k12.mt.us", "k12.nc.us", "k12.ne.us", "k12.nh.us", "k12.nj.us", "k12.nm.us", "k12.nv.us", "k12.ny.us", "k12.oh.us", "k12.ok.us", "k12.or.us", "k12.pa.us", "k12.pr.us", "k12.sc.us", "k12.tn.us", "k12.tx.us", "k12.ut.us", "k12.vi.us", "k12.vt.us", "k12.va.us", "k12.wa.us", "k12.wi.us", "k12.wy.us", "cc.ak.us", "cc.al.us", "cc.ar.us", "cc.as.us", "cc.az.us", "cc.ca.us", "cc.co.us", "cc.ct.us", "cc.dc.us", "cc.de.us", "cc.fl.us", "cc.ga.us", "cc.gu.us", "cc.hi.us", "cc.ia.us", "cc.id.us", "cc.il.us", "cc.in.us", "cc.ks.us", "cc.ky.us", "cc.la.us", "cc.ma.us", "cc.md.us", "cc.me.us", "cc.mi.us", "cc.mn.us", "cc.mo.us", "cc.ms.us", "cc.mt.us", "cc.nc.us", "cc.nd.us", "cc.ne.us", "cc.nh.us", "cc.nj.us", "cc.nm.us", "cc.nv.us", "cc.ny.us", "cc.oh.us", "cc.ok.us", "cc.or.us", "cc.pa.us", "cc.pr.us", "cc.ri.us", "cc.sc.us", "cc.sd.us", "cc.tn.us", "cc.tx.us", "cc.ut.us", "cc.vi.us", "cc.vt.us", "cc.va.us", "cc.wa.us", "cc.wi.us", "cc.wv.us", "cc.wy.us", "lib.ak.us", "lib.al.us", "lib.ar.us", "lib.as.us", "lib.az.us", "lib.ca.us", "lib.co.us", "lib.ct.us", "lib.dc.us", "lib.fl.us", "lib.ga.us", "lib.gu.us", "lib.hi.us", "lib.ia.us", "lib.id.us", "lib.il.us", "lib.in.us", "lib.ks.us", "lib.ky.us", "lib.la.us", "lib.ma.us", "lib.md.us", "lib.me.us", "lib.mi.us", "lib.mn.us", "lib.mo.us", "lib.ms.us", "lib.mt.us", "lib.nc.us", "lib.nd.us", "lib.ne.us", "lib.nh.us", "lib.nj.us", "lib.nm.us", "lib.nv.us", "lib.ny.us", "lib.oh.us", "lib.ok.us", "lib.or.us", "lib.pa.us", "lib.pr.us", "lib.ri.us", "lib.sc.us", "lib.sd.us", "lib.tn.us", "lib.tx.us", "lib.ut.us", "lib.vi.us", "lib.vt.us", "lib.va.us", "lib.wa.us", "lib.wi.us", "lib.wy.us", "pvt.k12.ma.us", "chtr.k12.ma.us", "paroch.k12.ma.us", "ann-arbor.mi.us", "cog.mi.us", "dst.mi.us", "eaton.mi.us", "gen.mi.us", "mus.mi.us", "tec.mi.us", "washtenaw.mi.us"]),
            crl: Self::strs_to_strings(&["006CB226A772C7182D7772383E373F0F229E7DFE3444810A8D6E50905D20D661", "026F0A8E207F05F1F172DB713DC22D0F43C8FF0D69724AA6FAC6A8393DF62508", "03CB44B933D7E14551E52DDBFC335A4D57BF65A703667B57AC961DE31E3A106D", "049432F226A2C54FF0FDB50BD59C0100FBD242C19FA64069531C373798BC784F", "051CF9FA95E40E9B83EDAEDA6961F6168C7879C4660172479CDD51AB03CEA62B", "07E854F26A7CBD389927AA041BFEF1B6CD21DD143818AD947DC655A9E587FE88", "08B3A6335FCE5EF48F8F0E543986C07FD18A3B1226129F61864BBD5BDD1F1CC9", "0B1EDD5F16124A9B948C6A469540EEF5824E4B22FE0F3A6CC7C1781D2A73A8B8", "0C7ACAA710226720BBC940349EE2E6148652A89DBF406A232C895F6DC78EBB9A", "0CEFA30C4603621AADCE0EFB22F16D8E2E86DA257188BEC048C3D057B13C6E13", "0DC4F77C58851615880980F62CCBD500AC4CBA5F0926F07BC5F75A47B6887386", "0DDB66CBA3DAFA98A36F57E0647AC406B46E8CDC1C1FDDB4FB9B9C3A11C6E325", "10BA3485CA8BB6880AB9531A4063E4001555561C7F2E055165F49B2D74FC5F6B", "1134FD81561A2818ECCFFFC2E440A0CEF9A40E2926C08299804D738B0A97F63D", "116258D835845DEDBB7F2B2D4D56BED1C1D4986762EA281101ECB13939601436", "1255CABE8152FA64DF942F7A47417E29F96C1CE11BF8C84ECBE2815CC1280810", "149F2EE63B9A5E5803240A770DC991FC2E3445E62831C245A49BC4F1F738FF9C", "1746D63DE90F202F7F9E4800243EC43DAC1D492601C3D06FDDF3467531F506B8", "176A861DC6B05292EB14CDC16A4BEFD472CDB12BA16770235AFC0593F7EC5254", "1A4B50727F6085D9626F9B6F6791C3469EDF87FDD120BABD4E78C7F246E1BD51", "1A78742AD34833991481FEEED6BE710206B05888FB3DBA9C681326551C70A53B", "1A7A3A1A68DD2361E3F3BB855F3B26FCD88B197D8DD4DE06CF1B362AC89EC13B", "1AD937AF57AF941AECD211B77E6DD5A0CD7D75A1DEC4358FFFF38299E78CAF93", "1C75AC70747E99745E30A0516710AFA8483AC03BFA1C06CFCCA37B3652EFAB87", "1EA3C5E43ED66C2DA2983A42A4A79B1E906786CE9F1B58621419A00463A87D38", "1F4224CEC84FC99CED881FF6FCFD3E21F8C519C547AA6A5DD3DE247302CE50D1", "1FFA0959E9484719FD3E002E870BB77D37E1ADFED8BD296E7ED68A7C1C5C7363", "2021917E98263945C859C43F1D73CB4139053C414FA03CA3BC7EE88614298F3B", "22076E5AEF44BB9A416A28B7D1C44322D7059F60FEFFA5CAF6C5BE8447891303", "234D8FFC7EF8023C818BF19F47894186D7B2E75643280D96F9F39965289DE15E", "23F2EDFF3EDE90259A9E30F40AF8F912A5E5B3694E6938440341F6060E014FFA", "2596904DC4D699AE20C2CEF4DCE47F285937D77464AC370746F52DEA76BA0C28", "25B41B506E4930952823A6EB9F1D31DEF645EA38A5C6C6A96D71957E384DF058", "25D4913CF587097414D29D26F6C1B1942CD6D64EAF45D0FCF81526ADBA96D324", "29E7FDDA489E46EE486EFD75ACC48F251932DC9DA1872B31753CD64719567AA5", "2A8BED32AE680D2D187B9A7AFD171D83FD0B935EAF9E2C1B43E80278D2063E39", "2BCEE858158CF5465FC9D76F0DFA312FEF25A4DCA8501DA9B46B67D1FBFA1B64", "2FC5667A4B9A2678ED6AC6AD25465FCBF6094BFCD9504097C7A8FA47ADE5E888", "3219B09114FF495A3EB6EB00C2EFEAB34002AE5F0A56C7679EA087A3FA037E4F", "3329BFA13B6007AB5FC3713F0ACB289426E2FBC99CC5C110A914B139571600B6", "3380709AF3B096BE3CC2A40548142C0A520028DB09E2CB77AE2206616AB6CBB4", "348767CDAD3BDD28B2B8DD5351AEC30C68CEC5CD69D276DF3827DBC4F5806464", "3499F93FD394523BFB1EC4C3AD4DFB310131FBE9EE5476BDE6295DE808D5DD8F", "36ECC61FC7E5F1923D167E67DFDE34608549B34A63C7C6E60FFD5C1840381F5C", "37837317BCDB1D42C5922DC24BC3CE8559D456F9C434EB3B7103BFFEF1AC5772", "384B464714D464FF584CE1CF85EFA57ADA20F35C2122778C82B76FBC75C5E5B0", "3A260FD9DC3A62299DCD7BFF74D9415DD3EDF840BA25F25BD31AE71D0B144AEA", "3B0D73B4BE4A854ADC3E51D7EF9FA48AEFBB2CDD824D67BDC7D7D09A2ABC2D43", "4001E969257575115D7106854466555CA4145FB390F95632E8DA957A3407D4B2", "40FCFC28875DCCBFEBCBDF6CD7433312DA63C4EFCF3BD7B1B505C22020AE0274", "4179EDD981EF747477B49626408AF43DAA2CA7AB7F9E082C1060F84096774348", "495A96BA6BAD782407BD521A00BACE657BB355555E4BB7F8146C71BBA57E7ACE", "4A49EDBD2F8F8230BD5592B313573FE1C172A45FA98011CC1EDDBB36ADE3FCE5", "4E2FE7B57BFFD5BB2E3382487B3938E85F78EB195DBD4832A2B2598B98057450", "4E4E373CB7AC45D8331CC08D248A8E99E251F2ED58C609BC8209E09E7A882DFC", "4F7162B974491C98585EC28FE759AA00C330D0B465190A896CC4B616231831FC", "50CC86BA96DB3263C79A43EAD07553D9F56659E6907E72D8C026637A1CDC85DC", "510D20E5C47F63CF666B20F61AF62BC099A42AC824FFA443A2DA7C90B1808A91", "5192438EC369D7EE0CE71F5C6DB75F941EFBF72E58441715E99EAB04C2C8ACEE", "53F97DA3E2E0D8D3A007EECC2C95336736D5AEA6AD23F962908138E0289A87A3", "55F77DE41C03792428F8D518C55104225BE43A5598D926A528AD653E1CCEC7BF", "56174D3AD971A8944964B189811F3008493A6A90422E3C5804EC838D4F94F622", "563B3CAF8CFEF34C2335CAF560A7A95906E8488462EB75AC59784830DF9E5B2B", "56DC6C39B963E6ADB0E9E6131B5786916F65043EC02E4A1E1A9C73C50781DFA6", "57E8B2FAD01E317F650DE76C8A224BFFC759C4FCFE78BD6CD7D439A14D5DD558", "58DD61FEB36EA7D258724371709149CB121337864CACB2D0999AD20739D06477", "5955AE291574A931342CF7450E16652EDE1E0FB3097E1571DFAC11C915601564", "5A804CCFF6C860C72D48F6796618DEFFF7A2935DD3781C8748AE335D8604B004", "5A889647220E54D6BD8A16817224520BB5C78E58984BD570506388B9DE0F075F", "5AD75DDF06906F02697A488DAD99B070605CB9441FEEE98AD28EB0D1EFA84960", "5B6B96F18CB18F6A62A9C7B9728E9E5587CD4E568D92F380F8AF6E224E21D319", "5C41A73AB2C35DFCD771F6FD6E3E8FAC9B469D386CADDA56A95B646EB48CCA34", "6106C0E3A0A299831875127BD7D3CC1859803D511CAC11EB6E0840DD166FC10E", "616167201433AEA6C8E5E3070AFCAF6749188F814BD1ABB179AE8DAD3ABF26EC", "6241005B14DECA4865543AABE8C6A46290185233571A069534708F263C3CC652", "62554C17005543B237215F04268DCD2FD1C470240AD3C8660E25AE2C59630F55", "63D9AF9B47B1064D49A10E7B7FD566DBC8CAA399459BFC2829C571AD8C6EF34A", "682747F8BA621B87CDD3BC295ED5CABCE722A1C0C0363D1D68B38928D2787F1E", "68897BF383723F09DE663559BA2E60504E773DA59C8717D7E0FEF16C77D6CADF", "6A379372C3E96F12AF3198BFB709E278372B3184EAF3C862BC98409A5CBC0779", "6B1A505E0246F2F60C490FF0C097A7BE27210CBB7500237F88B0CD48298BC9B8", "6BCFC86C8DDC2AF2E6A1180A2DDABB37B7EA3755316B64B9B8951BF0CA351F06", "6C464B9A5B233A5E874DA765C26F045010D2DDCFF45794F0B4C7E4AAFA501495", "6D083573D455381897D30B39ED16F3AD07EA1DADE93757483F61EE31EBC17FD4", "6D6F0C340971A218A31D10330EA9AE7C7A6550534C6EEFEDDD2118E114DB473E", "6DBFAE00D37B9CD73F8FB47DE65917AF00E0DDDF42DBCEAC20C17C0275EE2095", "7006A38311E58FB193484233218210C66125A0E4A826AED539AC561DFBFBD903", "702116CCD8BF23E16466F0E0DBA0ED6A239A9C1CD6A8F5A66B39AF3595020385", "706BB1017C855C59169BAD5C1781CF597F12D2CAD2F63D1A4AA37493800FFB80", "7662FD887DAA8DCEFD0FF74CFA9DC639230A36820187E0067E020682081DBCBF", "76EE8590374C715437BBCA6BBA6028EADDE2DC6DBBB8C3F610E851F11D1AB7F5", "77290717614B25F12964EBDB38B5F83CAADC0F6C36B0777F880FC6DEE1D339CC", "797C92CC2B0158321F986174D5CC0326074076DF078FB0F8DBDAA02F668DFB35", "7A768D45397AD44B29AEEB9C13BF08462EB6DA5A461A1BD4EE2B86173E53D80A", "7AFE4B071A2F1F46F8BA944A26D584D5960B92FB48C3BA1B7CAB84905F32AACD", "7CD67C248F69D83FC2F9BB01DCB1F7AD67A363D046043796D0984C3A231F6BB0", "7E0EAD76BB6819DC2F54511A84354F6E8B307B9DD82058EA6C004F01D9DDA5DF", "7E8782C150CE3952F802E636023A5D3E95BB5D68E33E85ADB2BA178125CEBF15", "7F1D907A368940C73379B8CB7286C71EF3816C1A62AFD5F1417A4748731A4E94", "7F1DEC8B0319548A056DE5BB521BD93EB74E6A76F28DFFB75B45A53B775AF7AB", "82B5F84DAF47A59C7AB521E4982AEFA40A53406A3AEC26039EFA6B2E0E7244C1", "84AAC093E08C49DBFFF8E560759248DBE67135B372B23D2A881D5F99CBB191E8", "85D26BE90D934FCCDB4FF7B38D8C79CA7652B816D6A52446CA8428A6B85DC57C", "86A68F050034126A540D39DB2C5F917EF66A94FB9619FA1ECD827CEA46BA0CB0", "871A9194F4EED5B312FF40C84C1D524AED2F778BBFF25F138CF81F680A7ADC67", "87AF34D66FB3F2FDF36E09111E9ABA2F6F44B207F3863F3D0B54B25023909AA5", "89DB8DCC534AA70619DEC7BF5D5FA15DC6D4A2794BC34F503DAE80614C29BB83", "8A27B5557B4BEC7CC0305FBF3D53D1F71CD3F34910C5D65E27ECDDB82077BA3D", "8A2AFFBD1A1C5D1BDCCBB7F548BA995F966806B3FD0C3A00FAE2E52F3C853989", "8A903B600A080B38DFE20DFB6ACD23122F64620E5808B9FC8688952FC1A3559C", "8BB593A93BE1D0E8A822BB887C547890C3E706AAD2DAB76254F97FB36B82FC26", "8C46A4188D63382F4CEEDD69EDBFDCA7B38EB85B76A2F469A20456AD157142DF", "8D767764B3CBDA08929D072A22A561F4DCDD1BC57D3CBDDC948C47D2B47F9122", "8E8046EC4CAC015A507CE0D2D0154A4B40E8E42B3165CFA546571435112D17E5", "8E8B56F5918A25BD85DCE76663FD94CC23690F10EA9586613171C6F8378890D5", "8FD112C3C8370F147D5CCD3A7D865EB8DD540783BAC69FC60088E3743FF33378", "8FDE27B96D4C4FAF039A063BC966B90ADE2AB2F2260FF3D4EAA9A0B2FF00ECC4", "918591F1E16D7BE0DB051967F7793DDDFFCFB9AB89D4CA35719DAF2231F0723B", "927A1B8562280576D048C50321ADA43D8703D2D9521A18C28B8C46CC6AAE4EFD", "92C46879626EF2CC1ECEA50C72FB5E385844095F21CBF3B283CB82E6B9FC6A58", "9318226F8C83AFE47F5F47C24F59CE12DBA8C73B181BEE6B2EA1F40A06BC1869", "94072AD3F58F70F93098E5A5F6C04C96C710BD849D83184919AE90EB890AE400", "951EE046FA83316E6786C08C44F13B4CA2EAD2D2644D63314391C0CC70887D0D", "952C2039C0243EB515DD73D83FC3643184874FEB0862A9837731ED9B4742E17A", "9612500BB176AED81058869906DE333973B813D3FCD9BB1BE3BB848A323EA5C3", "967B0CD93FCEF7F27CE2C245767AE9B05A776B0649F9965B6290968469686872", "9736AC3B25D16C45A45418A964578156480A8CC434541DDC5DD59233229868DE", "9847E5653E5E9E847516E5CB818606AA7544A19BE67FD7366D506988E8D84347", "9CF4704F3EE5A59894B16BF00CFE73D588DAE269F51DE66A4BA77446EE2BD1F7", "9E5A34B08929BC0A581C8936AAFD6AB7517BB15188B4F6FC02C45906F71595B0", "A320F4D534D7BE97C1AE8DD0499735BC895C323ADD2D388BFCCF662C23D7F99A", "A51A2F3A050E838A5050696578DBBEDAAC1A107EE2D9D48FAE505D18D0DA5CF8", "A6E11FF15EC326A5E3F18AD33A056694DC84C699766D028A5AD0EFE1A8E53AC7", "A72EAE212A827C0A3FD2F19DD1C744D4579B913D34A762539464931A5A45C894", "A81293445DB196A2030F9E455FE3C74A9A4F8317B02B01406027A8708174434C", "AA2630A7B617B04D0A294BAB7A8CAAA5016E6DBE604837A83A85719FAB667EB5", "AB98495276ADF1ECAFF28F35C53048781E5C1718DAB9C8E67A504F4F6A51328F", "AC499048C7DD00C021B371E34AA7599EE6DE94076008ADAE0FABA298C83359E2", "AC50B5FB738AED6CB781CC35FBFFF7786F77109ADA7C08867C04A573FD5CF9EE", "AE7F962CB9E6A7DBF7B833FB18FA9B71A89175DF949C232B6A9EF7CB3DF2BBFC", "AF207C61FD9C7CF92C2AFE8154282DC3F2CBF32F75CD172814C52B03B7EBC258", "AF22737CDB0F52D6578A2D3DE912053396947270CC9318D0805E9512ECE77AE3", "AFE67C4786A4C7EC6268847467CE478688C946778F15FABD9519EC7A32554727", "B03D87B056D08CC9D4E675EF19CA83AB53532168A8258598BE72E6D85C7DD7C1", "B21D2A743318712BA16F39919D961A4BAFBA3BCA9A43A75B1FCFE22C5D70CABA", "B26B1A7CC7F59B56FEDCD37F8ECB25DD130A1D7A24F8610B59636D1BDBD91260", "B489CCB224B9A6B81DD274CEAF5209C252998C9A76AF48E4F4C50A0728461825", "B4D31633D83B3105CD26915F7C0E6BF8A0E38959A65EB6D83DD42F56D391A48E", "B5EC35BAAB538884CFA8DD97376B102F03E53B482C64100C250722AE9B042CBC", "B6FD04C1D307DE3CAEF051C509E2E9C5B3E69726A4A8932517DA4285BA1307DD", "B70045B526AE7E6B9FBD4BAE7456CF1171903247C306262E1B533E0395BF1846", "B89BCBB8ACD474C1BEA7DAD65037F48DCECC9DFAA0612C3C2445956419DF32FE", "B94C198300CEC5C057AD0727B70BBE91816992256439A7B32F4598119DDA9C97", "BACC592E8B8AD411B959FD808B740089DDAF06C165A0A7123947879588F97EFA", "BB3DCDDE1BE98974119A5EBAC4BF3C5D85D5C5A3AB349D7FBAE9B94152FD4579", "BB4128EC9620F2D2A49CE8E2C4E257AEBAD93A0F11C56B5FA4B00E23759FA39D", "BB52086D0639E8DB332775AC8F4E8435D92CEB00F4E24F28FC0EABE240772E80", "BB5685059377E908AAB9A3B07A0AC76214C29A074B4FCEBE21DC36671FBDB420", "BCFB44AAB9AD021015706B4121EA761C81C9E88967590F6F94AE744DC88B78FB", "BE3DB7B79BFE579DCF9B07CA4CAD75AFF16975568E5B45CFCAE4D61FB63175A8", "BFE82909872E4434F115C51A56168019594D0E03DCA363D9F3B4839D0BABCDE5", "C16C0FAF9985FE65A0A491119C8E508E4DC5AA9BEB08194CB2BB7CEFD6B9D053", "C2B3C31A4A29850AA8F3CF472A1169FF71B416579F6A4482EC7744B83DF988AC", "C63D68C648A18B77641C427A669D61C9768A55F4FCD0322EAC96C57700299CF1", "C784333D20BCD742B9FDC3236F4E509B8937070E73067E254DD3BF9C45BF4DDE", "C7F43B4CF5B71568294F822B53762605F6DDD15CADECE739E9E2C3CBA61E9D67", "C84005B7024EAF3D3E8451FBE9231F02047D28DC13F01676638097377B9A6811", "CB6E91711AD6D55C8906F379CB071FB5C47933654A7415612EEE6629F26FBCD7", "CE24EB0626DEFD8168C96A7701F09301600FE5DD0DBCE58E9C97B830AF02EF28", "CEA8A2C66A03230FC998C2022E9B5DC4550B3D33E15612DB516D6ED5938F61CA", "CED43902AB5FB57B442322DC0E172A4FB55F7178B808F94E780A6FD6CC6BD818", "CF0B474ACE8469FABA402F02EEBDF9E1700D9CBE8BE4E4348407B69DD3196E94", "D1C45377EBDCD618CD1651DC2E02C21D751E5AA9FCD1B3431FF6ECF6A31348FA", "D2F91A04E3A61D4EAD7848C8D43B5E1152D885727489BC65738B67C0A22785A7", "DD5ED1C090F9F448061BAA94A6BB11017544E9EEFAA20CC714CE6C633F5DC629", "E04A022CE32F4CCF2C7F6046287B828A32A909F5E751447F83FD2C71F6FD8173", "E5CA37BC7B6C361979BC6B123CA9A1DB019046D7FF5F57DFB854B19D10B0682F", "E63BAD30738064605B71361B9755F5438775E34BD789ABC4901E9E772BC2B923", "E69D11239A7ADFDB53A8DA4BD0E05A20EA0FDA98B5DB78099F993B8A8EB7C13E", "E768343DED4537E5FC91E85736C8B4835B45E320BDC7B9623A76E3DFB9AEE1A3", "EA87F462DEEFFFBD7775AA2A4B7E0FCB91C22EEE6DF69ED90100CCC73B311476", "EAAD41CECA70BF6A222D160EA4A9AA757E1A56AEB395A22DD2A8A9BAF74BE1BE", "F19A47AC01B579021066739E627FA9F44EEDAAAFF27357E269269E291D416362", "F1C6BA670CFC88E4DF52973CAE420F0A089DD474144FE5806C420064E1591229", "F2BA87A14A428ED667214F44AB0B33F0867025C24C8E0E7DDE6C0904F1B7D832", "F3438E23B3CE532522FACF307923F58FD18608E9BA7ADDC30E952B43C49616C3", "F463C54D9F1A047AED52656AC785E07EBEC528E0207BFD3F55D893237668F6AE", "F48BADD7DF6A06690D0AE31373B12855F8DEDB14517F362A313101CC98CC6B35", "FA1B0F9AC7627B9BA86AFD1563A3DADD7E94DDF8115B0E70A83A3E227EA43A5A", "FB58E7F2D17FC366957E93F9F2939F73FE7D09E708865BCDA290DF733FEDC8E3", "FDE8999A5E427319835C89A17D64A2DCD13A851C0916C4C547B6D8F7A6437D94", "FEA2B7D645FBA73D753C1EC9A7870C40E1F7B0C561E927B985BF711866E36F22"]),
            // trusted: Self::strs_to_strings(&["5A2FC03F0C83B090BBFA40604B0988446C7636183DF9846E17101A447FB8EFD6", "125609AA301DA0A249B97A8239CB6A34216F44DCAC9F3954B14292F2E8C8608F", "BC4D809B15189D78DB3E1D8CF4F9726A795DA1643CA5F1358E1DDB0EDC0D7EB3", "86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B", "9A6EC012E1A7DA9DBE34194D478AD7C0DB1822FB071DF12981496ED104384113", "55926084EC963A64B96E2ABE01CE0BA86A64FBFEBCC7AAB5AFC155B37FD76066", "0376AB1D54C5F9803CE4B2E201A0EE7EEF7B57B636E8A93C9B8D4860C96F5FA7", "0A81EC5A929777F145904AF38D5D509F66B5E2C58FCDB531058B0E17F3F0B41B", "70A73F7F376B60074248904534B11482D5BF0E698ECC498DF52577EBF2E93B9A", "BD71FDF6DA97E4CF62D1647ADD2581B07D79ADF8397EB4ECBA9C5E8488821423", "F356BEA244B7A91EB35D53CA9AD7864ACE018E2D35D5F8F96DDF68A6F41AA474", "04048028BF1F2864D48F9AD4D83294366A828856553F3B14303F90147F5D40EF", "16AF57A9F676B0AB126095AA5EBADEF22AB31119D644AC95CD4B93DBF3F26AEB", "9A114025197C5BB95D94E63D55CD43790847B646B23CDF11ADA4A00EFF15FB48", "EDF7EBBCA27A2A384D387B7D4010C666E2EDB4843E4C29B4AE1D5B9332E6B24D", "E23D4A036D7B70E9F595B1422079D2B91EDFBB1FB651A0633EAA8A9DC5F80703", "E3B6A2DB2ED7CE48842F7AC53241C7B71D54144BFB40C11F3F1D0B42F5EEA12D", "2A99F5BC1174B73CBB1D620884E01C34E51CCB3978DA125F0E33268883BF4158", "0F993C8AEF97BAAF5687140ED59AD1821BB4AFACF0AA9A58B5D57A338A3AFBCB", "EAA962C4FA4A6BAFEBE415196D351CCD888D4F53F3FA8AE6D7C466A94E6042BB", "5C58468D55F58E497E743982D2B50010B6D165374ACF83A7D4A32DB768C4408E", "5CC3D78E4E1D5E45547A04E6873E64F90CF9536D1CCC2EF800F355C4C5FD70FD", "063E4AFAC491DFD332F3089B8542E94617D893D7FE944E10A7937EE29D9693C0", "D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4", "0C2CD63DF7806FA399EDE809116B575BF87989F06518F9808C860503178BAF66", "1793927A0614549789ADCE2F8F34F7F0B66D0F3AE3A3B84D21EC15DBBA4FADC7", "52F0E1C4E58EC629291B60317F074671B85D7EA80D5B07273463534B32B40234", "960ADF0063E96356750C2965DD0A0867DA0B9CBD6E77714AEAFB2349AB393DA3", "B6191A50D0C3977F7DA99BCDAAC86A227DAEB9679EC70BA3B0C9D92271C170D3", "3E9099B5015E8F486C00BCEA9D111EE721FABA355A89BCF1DF69561E3DC6325C", "7D05EBB682339F8C9451EE094EEBFEFA7953A114EDB2F44949452FAB7D2FC185", "7E37CB8B4C47090CAB36551BA6F45DB840680FBA166A952DB100717F43053FC2", "4348A0E9444C78CB265E058D5E8944B4D84F9662BD26DB257F8934A443C70161", "CB3CCBB76031E5E0138F8DD39A23F9DE47FFC35E43C1144CEA27D46A5AB1CB5F", "31AD6648F8104138C738F39EA4320133393E3A18CC02296EF97C2AC9EF6731D0", "7431E5F4C3C1CE4690774F0B61E05440883BA9A01ED00BA6ABD7806ED3B118CF", "552F7BDCF1A7AF9E6CE672017F4F12ABF77240C78E761AC203D1D9D20AC89988", "0687260331A72403D909F105E69BCF0D32E1BD2493FFC6D9206D11BCD6770739", "49E7A442ACF0EA6287050054B52564B650E4F49E42E348D6AA38E039E957B1C1", "EEC5496B988CE98625B934092EEC2908BED0B0F316C2D4730C84EAF1F3D34881", "88497F01602F3154246AE28C4D5AEF10F1D87EBB76626F4AE0B7F95BA7968799", "3E84BA4342908516E77573C0992F0979CA084E4685681FF195CCBA8A229B8A76", "6DC47172E01CBCB0BF62580D895FE2B8AC9AD4F873801E0C10B9C837D21EB177", "73C176434F1BC6D5ADF45B0E76E727287C8DE57616C1E6E6141A2B2CBC7D8E4C", "02ED0EB28C14DA45165C566791700D6451D7FB56F0B2AB1D3B8EB070E56EDFF5", "43DF5774B03E7FEF5FE40D931A7BEDF1BB2E6B42738C4E6D3841103D3AA7F339", "C0A6F4DC63A24BFDCF54EF2A6A082A0A72DE35803E2FF5FF527AE5D87206DFD5", "B0BFD52BB0D7D9BD92BF5D4DC13DA255C02C542F378365EA893911F55E55F23C", "FF856A2D251DCD88D36656F450126798CFABAADE40799C722DE4D2B5DB36A73A", "37D51006C512EAAB626421F1EC8C92013FC5F82AE98EE533EB4619B8DEB4D06C", "5EDB7AC43B82A06A8761E8D7BE4979EBF2611F7DD79BF91C1C6B566A219ED766", "B478B812250DF878635C2AA7EC7D155EAA625EE82916E2CD294361886CD1FBD4", "A0234F3BC8527CA5628EEC81AD5D69895DA5680DC91D1CB8477F33F878B95B0B", "A0459B9F63B22559F5FA5D4C6DB3F9F72FF19342033578F073BF1D1B46CBB912", "136335439334A7698016A0D324DE72284E079D7B5220BB8FBD747816EEBEBACA", "BEC94911C2955676DB6C0A550986D76E3BA005667C442C9762B4FBB773DE228C", "179FBC148A3DD00FD24EA13458CC43BFA7F59C8182D783A513F6EBEC100C8924", "EBD41040E4BB3EC742C9E381D31EF2A41A48B6685C96E7CEF3C1DF6CD4331C99", "CA42DD41745FD0B81EB902362CF9D8BF719DA1BD1B1EFC946F5B4C99F42C1B9E", "CBB522D7B7F127AD6A0113865BDF1CD4102E7D0759AF635A7CF4720DC963C53B", "C3846BF24B9E93CA64274C0EC67C1ECC5E024FFCACD2D74019350E81FE546AE4", "45140B3247EB9CC8C5B4F0D7B53091F73292089E6E5A63E2749DD3ACA9198EDA", "BC104F15A48BE709DCA542A7E1D4B9DF6F054527E802EAA92D595444258AFE71", "F9E67D336C51002AC054C632022D66DDA2E7E3FFF10AD061ED31D8BBB410CFB2", "5D56499BE4D2E08BCFCAD08A3E38723D50503BDE706948E42F55603019E528AE", "30D0895A9A448A262091635522D1F52010B5867ACAE12C78EF958FD4F4389F2F", "2530CC8E98321502BAD96F9B1FBA1B099E2D299E0F4548BB914F363BC0D4531F", "3C5F81FEA5FAB82C64BFA2EAECAFCDE8E077FC8620A7CAE537163DF36EDBF378", "6C61DAC3A2DEF031506BE036D2A6FE401994FBD13DF9C8D466599274C446EC98", "15F0BA00A3AC7AF3AC884C072B1011A077BD77C097F40164B2F8598ABD83860C", "41C923866AB4CAD6B7AD578081582E020797A6CBDF4FFF78CE8396B38937D7F5", "6B9C08E86EB0F767CFAD65CD98B62149E5494A67F5845E7BD1ED019F27B86BD6", "8A866FD1B276B57E578E921C65828A2BED58E9F2F288054134B7F1F4BFC9CC74", "85A0DD7DD720ADB7FF05F83D542B209DC7FF4528F7D677B18389FEA5E5C49E86", "8FE4FB0AF93A4D0D67DB0BEBB23E37C71BF325DCBCDD240EA04DAF58B47E1840", "18F1FC7F205DF8ADDDEB7FE007DD57E3AF375A9C4D8D73546BF4F1FED1E18D35", "88EF81DE202EB018452E43F864725CEA5FBD1FC2D9D205730709C5D8B8690F46", "A45EDE3BBBF09C8AE15C72EFC07268D693A21C996FD51E67CA079460FD6D8873", "4200F5043AC8590EBB527D209ED1503029FBCBD41CA1B506EC27F15ADE7DAC69", "BF0FEEFB9E3A581AD5F9E9DB7589985743D261085C4D314F6F5D7259AA421612", "F1C1B50AE5A20DD8030EC9F6BC24823DD367B5255759B4E71B61FCE9F7375D73", "513B2CECB810D4CDE5DD85391ADFC6C2DD60D87BB736D2B521484AA47A0EBEF6", "E75E72ED9F560EEC6EB4800073A43FC3AD19195A392282017895974A99026B6C", "7908B40314C138100B518D0735807FFBFCF8518A0095337105BA386B153DD927", "4D2491414CFE956746EC4CEFA6CF6F72E28A1329432F9D8A907AC4CB5DADC15A", "668C83947DA63B724BECE1743C31A0E6AED0DB8EC5B31BE377BB784F91B6716F", "3C4FB0B95AB8B30032F432B86F535FE172C185D0FD39865837CF36187FA6F428", "1465FA205397B876FAA6F0A9958E5590E40FCC7FAA4FB7C2C8677521FB5FB658", "2CE1CB0BF9D2F9E102993FBE215152C3B2DD0CABDE1C68E5319B839154DBB7F5", "568D6905A2C88708A4B3025190EDCFEDB1974A606A13C6E5290FCB2AE63EDAB5", "62DD0BE9B9F50A163EA0F8E75C053B1ECA57EA55C8688F647C6881F2C8357B95", "BE6C4DA2BBB9BA59B6F3939768374246C3C005993FA98F020D1DEDBED48A81D5", "7600295EEFE85B9E1FD624DB76062AAAAE59818A54D2774CD4C0B2C01131E1B3", "DD6936FE21F8F077C123A1A521C12224F72255B73E03A7260693E8A24B0FA389", "8D722F81A9C113C0791DF136A2966DB26C950A971DB46B4199F4EA54B78BFB9F", "A4310D50AF18A6447190372A86AFAF8B951FFB431D837F1E5688B45971ED1557", "4B03F45807AD70F21BFC2CAE71C9FDE4604C064CF5FFB686BAE5DBAAD7FDD34C", "C1B48299ABA5208FE9630ACE55CA68A03EDA5A519C8802A0D3A673BE8F8E557D", "91E2F5788D5810EBA7BA58737DE1548A8ECACD014598BC0B143E041B17052552", "FD73DAD31C644FF1B43BEF0CCDDA96710B9CD9875ECA7E31707AF3E96D522BBD", "59769007F7685D0FCD50872F9F95D5755A5B2B457D81F3692B610A98672F0E1B", "BFD88FE1101C41AE3E801BF8BE56350EE9BAD1A6B9BD515EDC5C6D5B8711AC44", "4FF460D54B9C86DABFBCFC5712E0400D2BED3FBC4D4FBDAA86E06ADCD2A9AD7A", "E793C9B02FD8AA13E21C31228ACCB08119643B749C898964B1746D46C3D4CBD2", "EB04CF5EB1F39AFA762F2BB120F296CBA520C1B97DB1589565B81CB9A17B7244", "69DDD7EA90BB57C93E135DC85EA6FCD5480B603239BDC454FC758B2A26CF7F79", "9ACFAB7E43C8D880D06B262A94DEEEE4B4659989C3D0CAF19BAF6405E41AB7DF", "2399561127A57125DE8CEFEA610DDF2FA078B5C8067F4E828290BFB860E84B3C", "CECDDC905099D8DADFC5B1D209B737CBE2C18CFB2C10C0FF0BCF0D3286FC1AA2", "EBC5570C29018C4D67B1AA127BAF12F703B4611EBC17B7DAB5573894179B93FA", "8ECDE6884F3D87B1125BA31AC3FCB13D7016DE7F57CC904FE1CB97C6AE98196E", "1BA5B2AA8C65401A82960118F80BEC4F62304D83CEC4713A19C39C011EA46DB4", "18CE6CFE7BF14E60B2E347B8DFE868CB31D02EBB3ADA271569F50343B46DB3A4", "E35D28419ED02025CFA69038CD623962458DA5C695FBDEA3C22B0BFB25897092", "B676F2EDDAE8775CD36CB0F63CD1D4603961F49E6265BA013A2F0307B6D0B804", "44B545AA8A25E65A73CA15DC27FC36D24C1CB9953A066539B11582DC487B4833", "A040929A02CE53B4ACF4F2FFC6981CE4496F755E6D45FE0B2A692BCD52523F36", "96BCEC06264976F37460779ACF28C5A7CFE8A3C0AAE11A8FFCEE05C0BDDF08C6", "54455F7129C20B1447C418F997168F24C58FC5023BF5DA5BE2EB6E1DD8902ED5", "A1339D33281A0B56E557D3D32B1CE7F9367EB094BD5FA72A7E5004C8DED7CAFE", "46EDC3689046D53A453FB3104AB80DCAEC658B2660EA1629DD7E867990648716", "BFFF8FD04433487D6A8AA60C1A29767A9FC2BBB05E420F713A13B992891D3893", "22A2C1F7BDED704CC1E701B5F408C310880FE956B5DE2A4A44F99C873A25A7C8", "2E7BF16CC22485A7BBE2AA8696750761B0AE39BE3B2FE9D0CC6D4EF73491425C", "3417BB06CC6007DA1B961C920B8AB4CE3FAD820E4AA30B9ACBC4A74EBDCEBC65", "85666A562EE0BE5CE925C1D8890A6F76A87EC16D4D7D5F29EA7419CF20123B69", "5A885DB19C01D912C5759388938CAFBBDF031AB2D48E91EE15589B42971D039C", "D40E9C86CD8FE468C1776959F49EA774FA548684B6C406F3909261F4DCE2575C", "0753E940378C1BD5E3836E395DAEA5CB839E5046F1BD0EAE1951CF10FEC7C965", "2CABEAFE37D06CA22ABA7391C0033D25982952C453647349763A3AB5AD6CCF69", "8560F91C3624DABA9570B5FEA0DBE36FF11A8323BE9486854FB3F34A5571198D"]),

            symantec_roots: Self::strs_to_strings(&["9ACFAB7E43C8D880D06B262A94DEEEE4B4659989C3D0CAF19BAF6405E41AB7DF", "FF856A2D251DCD88D36656F450126798CFABAADE40799C722DE4D2B5DB36A73A", "5EDB7AC43B82A06A8761E8D7BE4979EBF2611F7DD79BF91C1C6B566A219ED766", "023C81CCE8E7C64FA942D3C15048707D35D9BB5B87F4F544C5BF1BC5643AF2FA", "0999BF900BD5C297865E21E1AADE6CF6BB3A94D11AE5EA798442A4E2F813241F", "0BDD5ABE940CAAABE8B2BBA88348FB6F4AA4CC84436F880BECE66B48BDA913D8", "16A9E012D32329F282B10BBF57C7C0B42AE80F6AC9542EB409BC1C2CDE50D322", "17755A5C295F3D2D72E6F031A1F07F400C588B9E582B22F17EAE31A1590D1185", "1906C6124DBB438578D00E066D5054C6C37F0FA6028C05545E0994EDDAEC8629", "1916F3508EC3FAD795F8DC4BD316F9C6085A64DE3C4153AC6D62D5EA19515D39", "1D75D0831B9E0885394D32C7A1BFDB3DBC1C28E2B0E8391FB135981DBC5BA936", "22076E5AEF44BB9A416A28B7D1C44322D7059F60FEFFA5CAF6C5BE8447891303", "25B41B506E4930952823A6EB9F1D31DEF645EA38A5C6C6A96D71957E384DF058", "26C18DC6EEA6F632F676BCEBA1D8C2B48352F29C2D5FCDA878E09DCB832DD6E5", "2DC9470BE63EF4ACF1BD828609402BB7B87BD99638A643934E88682D1BE8C308", "2DEE5171596AB8F3CD3C7635FEA8E6C3006AA9E31DB39D03A7480DDB2428A33E", "3027A298FA57314DC0E3DD1019411B8F404C43C3F934CE3BDF856512C80AA15C", "31512680233F5F2A1F29437F56D4988CF0AFC41CC6C5DA6275928E9C0BEADE27", "43B3107D7342165D406CF975CD79B36ED1645048F05D7FF6EA0096E427B7DB84", "463DBB9B0A26ED2616397B643125FBD29B66CF3A46FDB4384B209E78237A1AFF", "479D130BF3FC61DC2F1D508D239A13276AE7B3C9841011A02C1402C7E677BD5F", "4905466623AB4178BE92AC5CBD6584F7A1E17F27652D5A85AF89504EA239AAAA", "495A96BA6BAD782407BD521A00BACE657BB355555E4BB7F8146C71BBA57E7ACE", "4BA6031CA305B09E53BDE3705145481D0332B651FE30370DD5254CC4D2CB32F3", "5192438EC369D7EE0CE71F5C6DB75F941EFBF72E58441715E99EAB04C2C8ACEE", "567B8211FD20D3D283EE0CD7CE0672CB9D99BC5B487A58C9D54EC67F77D4A8F5", "5C4F285388F38336269A55C7C12C0B3CA73FEF2A5A4DF82B89141E841A6C4DE4", "67DC4F32FA10E7D01A79A073AA0C9E0212EC2FFC3D779E0AA7F9C0F0E1C2C893", "6B86DE96A658A56820A4F35D90DB6C3EFDD574CE94B909CB0D7FF17C3C189D83", "7006A38311E58FB193484233218210C66125A0E4A826AED539AC561DFBFBD903", "781F1C3A6A42E3E915222DB4967702A2E577AEB017075FA3C159851FDDD0535E", "7CAA03465124590C601E567E52148E952C0CFFE89000530FE0D95B6D50EAAE41", "809F2BAAE35AFB4F36BD6476CE75C2001077901B6AF5C4DAB82E188C6B95C1A1", "81A98FC788C35F557645A95224E50CD1DAC8FFB209DC1E5688AA29205F132218", "860A7F19210D5EAD057A78532B80951453CB2907315F3BA7AA47B69897D70F3F", "87AF34D66FB3F2FDF36E09111E9ABA2F6F44B207F3863F3D0B54B25023909AA5", "95735473BD67A3B95A8D5F90C5A21ACE1E0D7947320674D4AB847972B91544D2", "967B0CD93FCEF7F27CE2C245767AE9B05A776B0649F9965B6290968469686872", "9699225C5DE52E56CDD32DF2E96D1CFEA5AA3CA0BB52CD8933C23B5C27443820", "9C6F6A123CBAA4EE34DBECEEE24C97D738878CB423F3C2273903424F5D1F6DD5", "A6F1F9BF8A0A9DDC080FB49B1EFC3D1A1C2C32DC0E136A5B00C97316F2A3DC11", "AB3876C3DA5DE0C9CF6736868EE5B88BF9BA1DFF9C9D72D2FE5A8D2F78302166", "AB39A4B025955691A40269F353FA1D5CB94EAF6C7EA9808484BBBB62FD9F68F3", "AB5CDB3356397356D6E691973C25B8618B65D76A90486EA7A8A5C17767F4673A", "AB98495276ADF1ECAFF28F35C53048781E5C1718DAB9C8E67A504F4F6A51328F", "ACF65E1D62CB58A2BAFD6FFAB40FB88699C47397CF5CB483D42D69CAD34CD48B", "AF207C61FD9C7CF92C2AFE8154282DC3F2CBF32F75CD172814C52B03B7EBC258", "B1124142A5A1A5A28819C735340EFF8C9E2F8168FEE3BA187F253BC1A392D7E2", "B2DEF5362AD3FACD04BD29047A43844F767034EA4892F80E56BEE690243E2502", "BCFB44AAB9AD021015706B4121EA761C81C9E88967590F6F94AE744DC88B78FB", "C07135F6B452398264A4776DBD0A6A307C60A36F967BD26321DCB817B5C0C481", "CAB482CD3E820C5CE72AA3B6FDBE988BB8A4F0407ECAFD8C926E36824EAB92DD", "D2F91A04E3A61D4EAD7848C8D43B5E1152D885727489BC65738B67C0A22785A7", "D3A25DA80DB7BAB129A066AB41503DDDFFA02C768C0589F99FD71193E69916B6", "D4AF6C0A482310BD7C54BB7AB121916F86C0C07CD52FCAC32D3844C26005115F", "DA800B80B2A87D399E66FA19D72FDF49983B47D8CF322C7C79503A0C7E28FEAF", "F15F1D323ED9CA98E9EA95B33EC5DDA47EA4C329F952C16F65AD419E64520476", "F2E9365EA121DF5EEBD8DE2468FDC171DC0A9E46DADC1AB41D52790BA980A7C2", "F53C22059817DD96F400651639D2F857E21070A59ABED9079400D9F695506900", "F6B59C8E2789A1FD5D5B253742FEADC6925CB93EDC345E53166E12C52BA2A601", "FF5680CD73A5703DA04817A075FD462506A73506C4B81A1583EF549478D26476"]),
            symantec_exceptions: Self::strs_to_strings(&["17F96609AC6AD0A2D6AB0A21B2D1B5B2946BD04DBF120703D1DEF6FB62F4B661", "3DB76D1DD7D3A759DCCC3F8FA7F68675C080CB095E4881063A6B850FDD68B8BC", "6115F06A338A649E61585210E76F2ECE3989BCA65A62B066040CD7C5F408EDD0", "904FB5A437754B1B32B80EBAE7416DB63D05F56A9939720B7C8E3DCC54F6A3D1", "AC2B922ECFD5E01711772FEA8ED372DE9D1E2245FCE3F57A9CDBEC77296A424B", "A4FE7C7F15155F3F0AEF7AAA83CF6E06DEB97CA3F909DF920AC1490882D488ED", "8BB593A93BE1D0E8A822BB887C547890C3E706AAD2DAB76254F97FB36B82FC26", "B94C198300CEC5C057AD0727B70BBE91816992256439A7B32F4598119DDA9C97", "C3F697A92A293D86F9A3EE7CCB970E20E0050B8728CC83ED1B996CE9005D4C36", "7CAC9A0FF315387750BA8BAFDB1C2BC29B3F0BBA16362CA93A90F84DA2DF5F3E", "AC50B5FB738AED6CB781CC35FBFFF7786F77109ADA7C08867C04A573FD5CF9EE"]),

            india_trusted: Self::strs_to_strings(&["F375E2F77A108BACC4234894A9AF308EDECA1ACD8FBDE0E7AAA9634E9DAF7E1C", "2D66A702AE81BA03AF8CFF55AB318AFA919039D9F31B4D64388680F81311B65A", "60109BC6C38328598A112C7A25E38B0F23E5A7511CB815FB64E0C4FF05DB7DF7"]),
            india_domains: Self::strs_to_strings(&["*.gov.in", "*.nic.in", "*.ac.in", "*.rbi.org.in", "*.bankofindia.co.in", "*.ncode.in", "*.tcs.co.in"]),

            anssi_trusted: Self::strs_to_strings(&["B9BEA7860A962EA3611DAB97AB6DA3E21C1068B97D55575ED0E11279C11C8932"]),
            anssi_domains: Self::strs_to_strings(&["*.fr", "*.gp", "*.gf", "*.mq", "*.re", "*.yt", "*.pm", "*.bl", "*.mf", "*.wf", "*.pf", "*.nc", "*.tf"]),
        })
    }

    /// Firefox policy in Hammurabi
    pub fn firefox_hammurabi(time: u64) -> policy::ExecPolicy {
        policy::ExecPolicy::Firefox(policy::ExecFirefoxEnvironment {
            time,
            crl: Self::strs_to_strings(&["006CB226A772C7182D7772383E373F0F229E7DFE3444810A8D6E50905D20D661", "026F0A8E207F05F1F172DB713DC22D0F43C8FF0D69724AA6FAC6A8393DF62508", "03CB44B933D7E14551E52DDBFC335A4D57BF65A703667B57AC961DE31E3A106D", "049432F226A2C54FF0FDB50BD59C0100FBD242C19FA64069531C373798BC784F", "051CF9FA95E40E9B83EDAEDA6961F6168C7879C4660172479CDD51AB03CEA62B", "07E854F26A7CBD389927AA041BFEF1B6CD21DD143818AD947DC655A9E587FE88", "08B3A6335FCE5EF48F8F0E543986C07FD18A3B1226129F61864BBD5BDD1F1CC9", "0B1EDD5F16124A9B948C6A469540EEF5824E4B22FE0F3A6CC7C1781D2A73A8B8", "0C7ACAA710226720BBC940349EE2E6148652A89DBF406A232C895F6DC78EBB9A", "0CEFA30C4603621AADCE0EFB22F16D8E2E86DA257188BEC048C3D057B13C6E13", "0DC4F77C58851615880980F62CCBD500AC4CBA5F0926F07BC5F75A47B6887386", "0DDB66CBA3DAFA98A36F57E0647AC406B46E8CDC1C1FDDB4FB9B9C3A11C6E325", "10BA3485CA8BB6880AB9531A4063E4001555561C7F2E055165F49B2D74FC5F6B", "1134FD81561A2818ECCFFFC2E440A0CEF9A40E2926C08299804D738B0A97F63D", "116258D835845DEDBB7F2B2D4D56BED1C1D4986762EA281101ECB13939601436", "1255CABE8152FA64DF942F7A47417E29F96C1CE11BF8C84ECBE2815CC1280810", "149F2EE63B9A5E5803240A770DC991FC2E3445E62831C245A49BC4F1F738FF9C", "1746D63DE90F202F7F9E4800243EC43DAC1D492601C3D06FDDF3467531F506B8", "176A861DC6B05292EB14CDC16A4BEFD472CDB12BA16770235AFC0593F7EC5254", "1A4B50727F6085D9626F9B6F6791C3469EDF87FDD120BABD4E78C7F246E1BD51", "1A78742AD34833991481FEEED6BE710206B05888FB3DBA9C681326551C70A53B", "1A7A3A1A68DD2361E3F3BB855F3B26FCD88B197D8DD4DE06CF1B362AC89EC13B", "1AD937AF57AF941AECD211B77E6DD5A0CD7D75A1DEC4358FFFF38299E78CAF93", "1C75AC70747E99745E30A0516710AFA8483AC03BFA1C06CFCCA37B3652EFAB87", "1EA3C5E43ED66C2DA2983A42A4A79B1E906786CE9F1B58621419A00463A87D38", "1F4224CEC84FC99CED881FF6FCFD3E21F8C519C547AA6A5DD3DE247302CE50D1", "1FFA0959E9484719FD3E002E870BB77D37E1ADFED8BD296E7ED68A7C1C5C7363", "2021917E98263945C859C43F1D73CB4139053C414FA03CA3BC7EE88614298F3B", "22076E5AEF44BB9A416A28B7D1C44322D7059F60FEFFA5CAF6C5BE8447891303", "234D8FFC7EF8023C818BF19F47894186D7B2E75643280D96F9F39965289DE15E", "23F2EDFF3EDE90259A9E30F40AF8F912A5E5B3694E6938440341F6060E014FFA", "2596904DC4D699AE20C2CEF4DCE47F285937D77464AC370746F52DEA76BA0C28", "25B41B506E4930952823A6EB9F1D31DEF645EA38A5C6C6A96D71957E384DF058", "25D4913CF587097414D29D26F6C1B1942CD6D64EAF45D0FCF81526ADBA96D324", "29E7FDDA489E46EE486EFD75ACC48F251932DC9DA1872B31753CD64719567AA5", "2A8BED32AE680D2D187B9A7AFD171D83FD0B935EAF9E2C1B43E80278D2063E39", "2BCEE858158CF5465FC9D76F0DFA312FEF25A4DCA8501DA9B46B67D1FBFA1B64", "2FC5667A4B9A2678ED6AC6AD25465FCBF6094BFCD9504097C7A8FA47ADE5E888", "3219B09114FF495A3EB6EB00C2EFEAB34002AE5F0A56C7679EA087A3FA037E4F", "3329BFA13B6007AB5FC3713F0ACB289426E2FBC99CC5C110A914B139571600B6", "3380709AF3B096BE3CC2A40548142C0A520028DB09E2CB77AE2206616AB6CBB4", "348767CDAD3BDD28B2B8DD5351AEC30C68CEC5CD69D276DF3827DBC4F5806464", "3499F93FD394523BFB1EC4C3AD4DFB310131FBE9EE5476BDE6295DE808D5DD8F", "36ECC61FC7E5F1923D167E67DFDE34608549B34A63C7C6E60FFD5C1840381F5C", "37837317BCDB1D42C5922DC24BC3CE8559D456F9C434EB3B7103BFFEF1AC5772", "384B464714D464FF584CE1CF85EFA57ADA20F35C2122778C82B76FBC75C5E5B0", "3A260FD9DC3A62299DCD7BFF74D9415DD3EDF840BA25F25BD31AE71D0B144AEA", "3B0D73B4BE4A854ADC3E51D7EF9FA48AEFBB2CDD824D67BDC7D7D09A2ABC2D43", "4001E969257575115D7106854466555CA4145FB390F95632E8DA957A3407D4B2", "40FCFC28875DCCBFEBCBDF6CD7433312DA63C4EFCF3BD7B1B505C22020AE0274", "4179EDD981EF747477B49626408AF43DAA2CA7AB7F9E082C1060F84096774348", "495A96BA6BAD782407BD521A00BACE657BB355555E4BB7F8146C71BBA57E7ACE", "4A49EDBD2F8F8230BD5592B313573FE1C172A45FA98011CC1EDDBB36ADE3FCE5", "4E2FE7B57BFFD5BB2E3382487B3938E85F78EB195DBD4832A2B2598B98057450", "4E4E373CB7AC45D8331CC08D248A8E99E251F2ED58C609BC8209E09E7A882DFC", "4F7162B974491C98585EC28FE759AA00C330D0B465190A896CC4B616231831FC", "50CC86BA96DB3263C79A43EAD07553D9F56659E6907E72D8C026637A1CDC85DC", "510D20E5C47F63CF666B20F61AF62BC099A42AC824FFA443A2DA7C90B1808A91", "5192438EC369D7EE0CE71F5C6DB75F941EFBF72E58441715E99EAB04C2C8ACEE", "53F97DA3E2E0D8D3A007EECC2C95336736D5AEA6AD23F962908138E0289A87A3", "55F77DE41C03792428F8D518C55104225BE43A5598D926A528AD653E1CCEC7BF", "56174D3AD971A8944964B189811F3008493A6A90422E3C5804EC838D4F94F622", "563B3CAF8CFEF34C2335CAF560A7A95906E8488462EB75AC59784830DF9E5B2B", "56DC6C39B963E6ADB0E9E6131B5786916F65043EC02E4A1E1A9C73C50781DFA6", "57E8B2FAD01E317F650DE76C8A224BFFC759C4FCFE78BD6CD7D439A14D5DD558", "58DD61FEB36EA7D258724371709149CB121337864CACB2D0999AD20739D06477", "5955AE291574A931342CF7450E16652EDE1E0FB3097E1571DFAC11C915601564", "5A804CCFF6C860C72D48F6796618DEFFF7A2935DD3781C8748AE335D8604B004", "5A889647220E54D6BD8A16817224520BB5C78E58984BD570506388B9DE0F075F", "5AD75DDF06906F02697A488DAD99B070605CB9441FEEE98AD28EB0D1EFA84960", "5B6B96F18CB18F6A62A9C7B9728E9E5587CD4E568D92F380F8AF6E224E21D319", "5C41A73AB2C35DFCD771F6FD6E3E8FAC9B469D386CADDA56A95B646EB48CCA34", "6106C0E3A0A299831875127BD7D3CC1859803D511CAC11EB6E0840DD166FC10E", "616167201433AEA6C8E5E3070AFCAF6749188F814BD1ABB179AE8DAD3ABF26EC", "6241005B14DECA4865543AABE8C6A46290185233571A069534708F263C3CC652", "62554C17005543B237215F04268DCD2FD1C470240AD3C8660E25AE2C59630F55", "63D9AF9B47B1064D49A10E7B7FD566DBC8CAA399459BFC2829C571AD8C6EF34A", "682747F8BA621B87CDD3BC295ED5CABCE722A1C0C0363D1D68B38928D2787F1E", "68897BF383723F09DE663559BA2E60504E773DA59C8717D7E0FEF16C77D6CADF", "6A379372C3E96F12AF3198BFB709E278372B3184EAF3C862BC98409A5CBC0779", "6B1A505E0246F2F60C490FF0C097A7BE27210CBB7500237F88B0CD48298BC9B8", "6BCFC86C8DDC2AF2E6A1180A2DDABB37B7EA3755316B64B9B8951BF0CA351F06", "6C464B9A5B233A5E874DA765C26F045010D2DDCFF45794F0B4C7E4AAFA501495", "6D083573D455381897D30B39ED16F3AD07EA1DADE93757483F61EE31EBC17FD4", "6D6F0C340971A218A31D10330EA9AE7C7A6550534C6EEFEDDD2118E114DB473E", "6DBFAE00D37B9CD73F8FB47DE65917AF00E0DDDF42DBCEAC20C17C0275EE2095", "7006A38311E58FB193484233218210C66125A0E4A826AED539AC561DFBFBD903", "702116CCD8BF23E16466F0E0DBA0ED6A239A9C1CD6A8F5A66B39AF3595020385", "706BB1017C855C59169BAD5C1781CF597F12D2CAD2F63D1A4AA37493800FFB80", "7662FD887DAA8DCEFD0FF74CFA9DC639230A36820187E0067E020682081DBCBF", "76EE8590374C715437BBCA6BBA6028EADDE2DC6DBBB8C3F610E851F11D1AB7F5", "77290717614B25F12964EBDB38B5F83CAADC0F6C36B0777F880FC6DEE1D339CC", "797C92CC2B0158321F986174D5CC0326074076DF078FB0F8DBDAA02F668DFB35", "7A768D45397AD44B29AEEB9C13BF08462EB6DA5A461A1BD4EE2B86173E53D80A", "7AFE4B071A2F1F46F8BA944A26D584D5960B92FB48C3BA1B7CAB84905F32AACD", "7CD67C248F69D83FC2F9BB01DCB1F7AD67A363D046043796D0984C3A231F6BB0", "7E0EAD76BB6819DC2F54511A84354F6E8B307B9DD82058EA6C004F01D9DDA5DF", "7E8782C150CE3952F802E636023A5D3E95BB5D68E33E85ADB2BA178125CEBF15", "7F1D907A368940C73379B8CB7286C71EF3816C1A62AFD5F1417A4748731A4E94", "7F1DEC8B0319548A056DE5BB521BD93EB74E6A76F28DFFB75B45A53B775AF7AB", "82B5F84DAF47A59C7AB521E4982AEFA40A53406A3AEC26039EFA6B2E0E7244C1", "84AAC093E08C49DBFFF8E560759248DBE67135B372B23D2A881D5F99CBB191E8", "85D26BE90D934FCCDB4FF7B38D8C79CA7652B816D6A52446CA8428A6B85DC57C", "86A68F050034126A540D39DB2C5F917EF66A94FB9619FA1ECD827CEA46BA0CB0", "871A9194F4EED5B312FF40C84C1D524AED2F778BBFF25F138CF81F680A7ADC67", "87AF34D66FB3F2FDF36E09111E9ABA2F6F44B207F3863F3D0B54B25023909AA5", "89DB8DCC534AA70619DEC7BF5D5FA15DC6D4A2794BC34F503DAE80614C29BB83", "8A27B5557B4BEC7CC0305FBF3D53D1F71CD3F34910C5D65E27ECDDB82077BA3D", "8A2AFFBD1A1C5D1BDCCBB7F548BA995F966806B3FD0C3A00FAE2E52F3C853989", "8A903B600A080B38DFE20DFB6ACD23122F64620E5808B9FC8688952FC1A3559C", "8BB593A93BE1D0E8A822BB887C547890C3E706AAD2DAB76254F97FB36B82FC26", "8C46A4188D63382F4CEEDD69EDBFDCA7B38EB85B76A2F469A20456AD157142DF", "8D767764B3CBDA08929D072A22A561F4DCDD1BC57D3CBDDC948C47D2B47F9122", "8E8046EC4CAC015A507CE0D2D0154A4B40E8E42B3165CFA546571435112D17E5", "8E8B56F5918A25BD85DCE76663FD94CC23690F10EA9586613171C6F8378890D5", "8FD112C3C8370F147D5CCD3A7D865EB8DD540783BAC69FC60088E3743FF33378", "8FDE27B96D4C4FAF039A063BC966B90ADE2AB2F2260FF3D4EAA9A0B2FF00ECC4", "918591F1E16D7BE0DB051967F7793DDDFFCFB9AB89D4CA35719DAF2231F0723B", "927A1B8562280576D048C50321ADA43D8703D2D9521A18C28B8C46CC6AAE4EFD", "92C46879626EF2CC1ECEA50C72FB5E385844095F21CBF3B283CB82E6B9FC6A58", "9318226F8C83AFE47F5F47C24F59CE12DBA8C73B181BEE6B2EA1F40A06BC1869", "94072AD3F58F70F93098E5A5F6C04C96C710BD849D83184919AE90EB890AE400", "951EE046FA83316E6786C08C44F13B4CA2EAD2D2644D63314391C0CC70887D0D", "952C2039C0243EB515DD73D83FC3643184874FEB0862A9837731ED9B4742E17A", "9612500BB176AED81058869906DE333973B813D3FCD9BB1BE3BB848A323EA5C3", "967B0CD93FCEF7F27CE2C245767AE9B05A776B0649F9965B6290968469686872", "9736AC3B25D16C45A45418A964578156480A8CC434541DDC5DD59233229868DE", "9847E5653E5E9E847516E5CB818606AA7544A19BE67FD7366D506988E8D84347", "9CF4704F3EE5A59894B16BF00CFE73D588DAE269F51DE66A4BA77446EE2BD1F7", "9E5A34B08929BC0A581C8936AAFD6AB7517BB15188B4F6FC02C45906F71595B0", "A320F4D534D7BE97C1AE8DD0499735BC895C323ADD2D388BFCCF662C23D7F99A", "A51A2F3A050E838A5050696578DBBEDAAC1A107EE2D9D48FAE505D18D0DA5CF8", "A6E11FF15EC326A5E3F18AD33A056694DC84C699766D028A5AD0EFE1A8E53AC7", "A72EAE212A827C0A3FD2F19DD1C744D4579B913D34A762539464931A5A45C894", "A81293445DB196A2030F9E455FE3C74A9A4F8317B02B01406027A8708174434C", "AA2630A7B617B04D0A294BAB7A8CAAA5016E6DBE604837A83A85719FAB667EB5", "AB98495276ADF1ECAFF28F35C53048781E5C1718DAB9C8E67A504F4F6A51328F", "AC499048C7DD00C021B371E34AA7599EE6DE94076008ADAE0FABA298C83359E2", "AC50B5FB738AED6CB781CC35FBFFF7786F77109ADA7C08867C04A573FD5CF9EE", "AE7F962CB9E6A7DBF7B833FB18FA9B71A89175DF949C232B6A9EF7CB3DF2BBFC", "AF207C61FD9C7CF92C2AFE8154282DC3F2CBF32F75CD172814C52B03B7EBC258", "AF22737CDB0F52D6578A2D3DE912053396947270CC9318D0805E9512ECE77AE3", "AFE67C4786A4C7EC6268847467CE478688C946778F15FABD9519EC7A32554727", "B03D87B056D08CC9D4E675EF19CA83AB53532168A8258598BE72E6D85C7DD7C1", "B21D2A743318712BA16F39919D961A4BAFBA3BCA9A43A75B1FCFE22C5D70CABA", "B26B1A7CC7F59B56FEDCD37F8ECB25DD130A1D7A24F8610B59636D1BDBD91260", "B489CCB224B9A6B81DD274CEAF5209C252998C9A76AF48E4F4C50A0728461825", "B4D31633D83B3105CD26915F7C0E6BF8A0E38959A65EB6D83DD42F56D391A48E", "B5EC35BAAB538884CFA8DD97376B102F03E53B482C64100C250722AE9B042CBC", "B6FD04C1D307DE3CAEF051C509E2E9C5B3E69726A4A8932517DA4285BA1307DD", "B70045B526AE7E6B9FBD4BAE7456CF1171903247C306262E1B533E0395BF1846", "B89BCBB8ACD474C1BEA7DAD65037F48DCECC9DFAA0612C3C2445956419DF32FE", "B94C198300CEC5C057AD0727B70BBE91816992256439A7B32F4598119DDA9C97", "BACC592E8B8AD411B959FD808B740089DDAF06C165A0A7123947879588F97EFA", "BB3DCDDE1BE98974119A5EBAC4BF3C5D85D5C5A3AB349D7FBAE9B94152FD4579", "BB4128EC9620F2D2A49CE8E2C4E257AEBAD93A0F11C56B5FA4B00E23759FA39D", "BB52086D0639E8DB332775AC8F4E8435D92CEB00F4E24F28FC0EABE240772E80", "BB5685059377E908AAB9A3B07A0AC76214C29A074B4FCEBE21DC36671FBDB420", "BCFB44AAB9AD021015706B4121EA761C81C9E88967590F6F94AE744DC88B78FB", "BE3DB7B79BFE579DCF9B07CA4CAD75AFF16975568E5B45CFCAE4D61FB63175A8", "BFE82909872E4434F115C51A56168019594D0E03DCA363D9F3B4839D0BABCDE5", "C16C0FAF9985FE65A0A491119C8E508E4DC5AA9BEB08194CB2BB7CEFD6B9D053", "C2B3C31A4A29850AA8F3CF472A1169FF71B416579F6A4482EC7744B83DF988AC", "C63D68C648A18B77641C427A669D61C9768A55F4FCD0322EAC96C57700299CF1", "C784333D20BCD742B9FDC3236F4E509B8937070E73067E254DD3BF9C45BF4DDE", "C7F43B4CF5B71568294F822B53762605F6DDD15CADECE739E9E2C3CBA61E9D67", "C84005B7024EAF3D3E8451FBE9231F02047D28DC13F01676638097377B9A6811", "CB6E91711AD6D55C8906F379CB071FB5C47933654A7415612EEE6629F26FBCD7", "CE24EB0626DEFD8168C96A7701F09301600FE5DD0DBCE58E9C97B830AF02EF28", "CEA8A2C66A03230FC998C2022E9B5DC4550B3D33E15612DB516D6ED5938F61CA", "CED43902AB5FB57B442322DC0E172A4FB55F7178B808F94E780A6FD6CC6BD818", "CF0B474ACE8469FABA402F02EEBDF9E1700D9CBE8BE4E4348407B69DD3196E94", "D1C45377EBDCD618CD1651DC2E02C21D751E5AA9FCD1B3431FF6ECF6A31348FA", "D2F91A04E3A61D4EAD7848C8D43B5E1152D885727489BC65738B67C0A22785A7", "DD5ED1C090F9F448061BAA94A6BB11017544E9EEFAA20CC714CE6C633F5DC629", "E04A022CE32F4CCF2C7F6046287B828A32A909F5E751447F83FD2C71F6FD8173", "E5CA37BC7B6C361979BC6B123CA9A1DB019046D7FF5F57DFB854B19D10B0682F", "E63BAD30738064605B71361B9755F5438775E34BD789ABC4901E9E772BC2B923", "E69D11239A7ADFDB53A8DA4BD0E05A20EA0FDA98B5DB78099F993B8A8EB7C13E", "E768343DED4537E5FC91E85736C8B4835B45E320BDC7B9623A76E3DFB9AEE1A3", "EA87F462DEEFFFBD7775AA2A4B7E0FCB91C22EEE6DF69ED90100CCC73B311476", "EAAD41CECA70BF6A222D160EA4A9AA757E1A56AEB395A22DD2A8A9BAF74BE1BE", "F19A47AC01B579021066739E627FA9F44EEDAAAFF27357E269269E291D416362", "F1C6BA670CFC88E4DF52973CAE420F0A089DD474144FE5806C420064E1591229", "F2BA87A14A428ED667214F44AB0B33F0867025C24C8E0E7DDE6C0904F1B7D832", "F3438E23B3CE532522FACF307923F58FD18608E9BA7ADDC30E952B43C49616C3", "F463C54D9F1A047AED52656AC785E07EBEC528E0207BFD3F55D893237668F6AE", "F48BADD7DF6A06690D0AE31373B12855F8DEDB14517F362A313101CC98CC6B35", "FA1B0F9AC7627B9BA86AFD1563A3DADD7E94DDF8115B0E70A83A3E227EA43A5A", "FB58E7F2D17FC366957E93F9F2939F73FE7D09E708865BCDA290DF733FEDC8E3", "FDE8999A5E427319835C89A17D64A2DCD13A851C0916C4C547B6D8F7A6437D94", "FEA2B7D645FBA73D753C1EC9A7870C40E1F7B0C561E927B985BF711866E36F22"]),
            // trusted: Self::strs_to_strings(&["02ED0EB28C14DA45165C566791700D6451D7FB56F0B2AB1D3B8EB070E56EDFF5", "0376AB1D54C5F9803CE4B2E201A0EE7EEF7B57B636E8A93C9B8D4860C96F5FA7", "04048028BF1F2864D48F9AD4D83294366A828856553F3B14303F90147F5D40EF", "063E4AFAC491DFD332F3089B8542E94617D893D7FE944E10A7937EE29D9693C0", "0687260331A72403D909F105E69BCF0D32E1BD2493FFC6D9206D11BCD6770739", "0753E940378C1BD5E3836E395DAEA5CB839E5046F1BD0EAE1951CF10FEC7C965", "0A81EC5A929777F145904AF38D5D509F66B5E2C58FCDB531058B0E17F3F0B41B", "0C2CD63DF7806FA399EDE809116B575BF87989F06518F9808C860503178BAF66", "125609AA301DA0A249B97A8239CB6A34216F44DCAC9F3954B14292F2E8C8608F", "136335439334A7698016A0D324DE72284E079D7B5220BB8FBD747816EEBEBACA", "1465FA205397B876FAA6F0A9958E5590E40FCC7FAA4FB7C2C8677521FB5FB658", "15D5B8774619EA7D54CE1CA6D0B0C403E037A917F131E8A04E1E6B7A71BABCE5", "15F0BA00A3AC7AF3AC884C072B1011A077BD77C097F40164B2F8598ABD83860C", "16AF57A9F676B0AB126095AA5EBADEF22AB31119D644AC95CD4B93DBF3F26AEB", "1793927A0614549789ADCE2F8F34F7F0B66D0F3AE3A3B84D21EC15DBBA4FADC7", "179FBC148A3DD00FD24EA13458CC43BFA7F59C8182D783A513F6EBEC100C8924", "18CE6CFE7BF14E60B2E347B8DFE868CB31D02EBB3ADA271569F50343B46DB3A4", "18F1FC7F205DF8ADDDEB7FE007DD57E3AF375A9C4D8D73546BF4F1FED1E18D35", "1BA5B2AA8C65401A82960118F80BEC4F62304D83CEC4713A19C39C011EA46DB4", "22A2C1F7BDED704CC1E701B5F408C310880FE956B5DE2A4A44F99C873A25A7C8", "2399561127A57125DE8CEFEA610DDF2FA078B5C8067F4E828290BFB860E84B3C", "2530CC8E98321502BAD96F9B1FBA1B099E2D299E0F4548BB914F363BC0D4531F", "2A575471E31340BC21581CBD2CF13E158463203ECE94BCF9D3CC196BF09A5472", "2CABEAFE37D06CA22ABA7391C0033D25982952C453647349763A3AB5AD6CCF69", "2CE1CB0BF9D2F9E102993FBE215152C3B2DD0CABDE1C68E5319B839154DBB7F5", "2E7BF16CC22485A7BBE2AA8696750761B0AE39BE3B2FE9D0CC6D4EF73491425C", "30D0895A9A448A262091635522D1F52010B5867ACAE12C78EF958FD4F4389F2F", "31AD6648F8104138C738F39EA4320133393E3A18CC02296EF97C2AC9EF6731D0", "3417BB06CC6007DA1B961C920B8AB4CE3FAD820E4AA30B9ACBC4A74EBDCEBC65", "37D51006C512EAAB626421F1EC8C92013FC5F82AE98EE533EB4619B8DEB4D06C", "3C4FB0B95AB8B30032F432B86F535FE172C185D0FD39865837CF36187FA6F428", "3C5F81FEA5FAB82C64BFA2EAECAFCDE8E077FC8620A7CAE537163DF36EDBF378", "3E84BA4342908516E77573C0992F0979CA084E4685681FF195CCBA8A229B8A76", "3E9099B5015E8F486C00BCEA9D111EE721FABA355A89BCF1DF69561E3DC6325C", "40F6AF0346A99AA1CD1D555A4E9CCE62C7F9634603EE406615833DC8C8D00367", "41C923866AB4CAD6B7AD578081582E020797A6CBDF4FFF78CE8396B38937D7F5", "4200F5043AC8590EBB527D209ED1503029FBCBD41CA1B506EC27F15ADE7DAC69", "4348A0E9444C78CB265E058D5E8944B4D84F9662BD26DB257F8934A443C70161", "43DF5774B03E7FEF5FE40D931A7BEDF1BB2E6B42738C4E6D3841103D3AA7F339", "44B545AA8A25E65A73CA15DC27FC36D24C1CB9953A066539B11582DC487B4833", "45140B3247EB9CC8C5B4F0D7B53091F73292089E6E5A63E2749DD3ACA9198EDA", "46EDC3689046D53A453FB3104AB80DCAEC658B2660EA1629DD7E867990648716", "49E7A442ACF0EA6287050054B52564B650E4F49E42E348D6AA38E039E957B1C1", "4B03F45807AD70F21BFC2CAE71C9FDE4604C064CF5FFB686BAE5DBAAD7FDD34C", "4D2491414CFE956746EC4CEFA6CF6F72E28A1329432F9D8A907AC4CB5DADC15A", "4FF460D54B9C86DABFBCFC5712E0400D2BED3FBC4D4FBDAA86E06ADCD2A9AD7A", "513B2CECB810D4CDE5DD85391ADFC6C2DD60D87BB736D2B521484AA47A0EBEF6", "52F0E1C4E58EC629291B60317F074671B85D7EA80D5B07273463534B32B40234", "54455F7129C20B1447C418F997168F24C58FC5023BF5DA5BE2EB6E1DD8902ED5", "552F7BDCF1A7AF9E6CE672017F4F12ABF77240C78E761AC203D1D9D20AC89988", "55926084EC963A64B96E2ABE01CE0BA86A64FBFEBCC7AAB5AFC155B37FD76066", "568D6905A2C88708A4B3025190EDCFEDB1974A606A13C6E5290FCB2AE63EDAB5", "59769007F7685D0FCD50872F9F95D5755A5B2B457D81F3692B610A98672F0E1B", "5A2FC03F0C83B090BBFA40604B0988446C7636183DF9846E17101A447FB8EFD6", "5A885DB19C01D912C5759388938CAFBBDF031AB2D48E91EE15589B42971D039C", "5C58468D55F58E497E743982D2B50010B6D165374ACF83A7D4A32DB768C4408E", "5CC3D78E4E1D5E45547A04E6873E64F90CF9536D1CCC2EF800F355C4C5FD70FD", "5D56499BE4D2E08BCFCAD08A3E38723D50503BDE706948E42F55603019E528AE", "5EDB7AC43B82A06A8761E8D7BE4979EBF2611F7DD79BF91C1C6B566A219ED766", "62DD0BE9B9F50A163EA0F8E75C053B1ECA57EA55C8688F647C6881F2C8357B95", "668C83947DA63B724BECE1743C31A0E6AED0DB8EC5B31BE377BB784F91B6716F", "687FA451382278FFF0C8B11F8D43D576671C6EB2BCEAB413FB83D965D06D2FF2", "69DDD7EA90BB57C93E135DC85EA6FCD5480B603239BDC454FC758B2A26CF7F79", "6B9C08E86EB0F767CFAD65CD98B62149E5494A67F5845E7BD1ED019F27B86BD6", "6C61DAC3A2DEF031506BE036D2A6FE401994FBD13DF9C8D466599274C446EC98", "6DC47172E01CBCB0BF62580D895FE2B8AC9AD4F873801E0C10B9C837D21EB177", "70A73F7F376B60074248904534B11482D5BF0E698ECC498DF52577EBF2E93B9A", "71CCA5391F9E794B04802530B363E121DA8A3043BB26662FEA4DCA7FC951A4BD", "73C176434F1BC6D5ADF45B0E76E727287C8DE57616C1E6E6141A2B2CBC7D8E4C", "7431E5F4C3C1CE4690774F0B61E05440883BA9A01ED00BA6ABD7806ED3B118CF", "7600295EEFE85B9E1FD624DB76062AAAAE59818A54D2774CD4C0B2C01131E1B3", "7908B40314C138100B518D0735807FFBFCF8518A0095337105BA386B153DD927", "7D05EBB682339F8C9451EE094EEBFEFA7953A114EDB2F44949452FAB7D2FC185", "7E37CB8B4C47090CAB36551BA6F45DB840680FBA166A952DB100717F43053FC2", "8560F91C3624DABA9570B5FEA0DBE36FF11A8323BE9486854FB3F34A5571198D", "85666A562EE0BE5CE925C1D8890A6F76A87EC16D4D7D5F29EA7419CF20123B69", "85A0DD7DD720ADB7FF05F83D542B209DC7FF4528F7D677B18389FEA5E5C49E86", "86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B", "88497F01602F3154246AE28C4D5AEF10F1D87EBB76626F4AE0B7F95BA7968799", "88EF81DE202EB018452E43F864725CEA5FBD1FC2D9D205730709C5D8B8690F46", "8A866FD1B276B57E578E921C65828A2BED58E9F2F288054134B7F1F4BFC9CC74", "8D722F81A9C113C0791DF136A2966DB26C950A971DB46B4199F4EA54B78BFB9F", "8ECDE6884F3D87B1125BA31AC3FCB13D7016DE7F57CC904FE1CB97C6AE98196E", "8FE4FB0AF93A4D0D67DB0BEBB23E37C71BF325DCBCDD240EA04DAF58B47E1840", "91E2F5788D5810EBA7BA58737DE1548A8ECACD014598BC0B143E041B17052552", "960ADF0063E96356750C2965DD0A0867DA0B9CBD6E77714AEAFB2349AB393DA3", "96BCEC06264976F37460779ACF28C5A7CFE8A3C0AAE11A8FFCEE05C0BDDF08C6", "9A114025197C5BB95D94E63D55CD43790847B646B23CDF11ADA4A00EFF15FB48", "9A6EC012E1A7DA9DBE34194D478AD7C0DB1822FB071DF12981496ED104384113", "9ACFAB7E43C8D880D06B262A94DEEEE4B4659989C3D0CAF19BAF6405E41AB7DF", "9BEA11C976FE014764C1BE56A6F914B5A560317ABD9988393382E5161AA0493C", "A0234F3BC8527CA5628EEC81AD5D69895DA5680DC91D1CB8477F33F878B95B0B", "A040929A02CE53B4ACF4F2FFC6981CE4496F755E6D45FE0B2A692BCD52523F36", "A0459B9F63B22559F5FA5D4C6DB3F9F72FF19342033578F073BF1D1B46CBB912", "A1339D33281A0B56E557D3D32B1CE7F9367EB094BD5FA72A7E5004C8DED7CAFE", "A4310D50AF18A6447190372A86AFAF8B951FFB431D837F1E5688B45971ED1557", "A45EDE3BBBF09C8AE15C72EFC07268D693A21C996FD51E67CA079460FD6D8873", "B0BFD52BB0D7D9BD92BF5D4DC13DA255C02C542F378365EA893911F55E55F23C", "B478B812250DF878635C2AA7EC7D155EAA625EE82916E2CD294361886CD1FBD4", "B676F2EDDAE8775CD36CB0F63CD1D4603961F49E6265BA013A2F0307B6D0B804", "BC104F15A48BE709DCA542A7E1D4B9DF6F054527E802EAA92D595444258AFE71", "BC4D809B15189D78DB3E1D8CF4F9726A795DA1643CA5F1358E1DDB0EDC0D7EB3", "BD71FDF6DA97E4CF62D1647ADD2581B07D79ADF8397EB4ECBA9C5E8488821423", "BE6C4DA2BBB9BA59B6F3939768374246C3C005993FA98F020D1DEDBED48A81D5", "BEC94911C2955676DB6C0A550986D76E3BA005667C442C9762B4FBB773DE228C", "BF0FEEFB9E3A581AD5F9E9DB7589985743D261085C4D314F6F5D7259AA421612", "BFD88FE1101C41AE3E801BF8BE56350EE9BAD1A6B9BD515EDC5C6D5B8711AC44", "BFFF8FD04433487D6A8AA60C1A29767A9FC2BBB05E420F713A13B992891D3893", "C0A6F4DC63A24BFDCF54EF2A6A082A0A72DE35803E2FF5FF527AE5D87206DFD5", "C1B48299ABA5208FE9630ACE55CA68A03EDA5A519C8802A0D3A673BE8F8E557D", "C3846BF24B9E93CA64274C0EC67C1ECC5E024FFCACD2D74019350E81FE546AE4", "C45D7BB08E6D67E62E4235110B564E5F78FD92EF058C840AEA4E6455D7585C60", "CA42DD41745FD0B81EB902362CF9D8BF719DA1BD1B1EFC946F5B4C99F42C1B9E", "CB3CCBB76031E5E0138F8DD39A23F9DE47FFC35E43C1144CEA27D46A5AB1CB5F", "CBB522D7B7F127AD6A0113865BDF1CD4102E7D0759AF635A7CF4720DC963C53B", "CECDDC905099D8DADFC5B1D209B737CBE2C18CFB2C10C0FF0BCF0D3286FC1AA2", "D40E9C86CD8FE468C1776959F49EA774FA548684B6C406F3909261F4DCE2575C", "D43AF9B35473755C9684FC06D7D8CB70EE5C28E773FB294EB41EE71722924D24", "D48D3D23EEDB50A459E55197601C27774B9D7B18C94D5A059511A10250B93168", "D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4", "DB3517D1F6732A2D5AB97C533EC70779EE3270A62FB4AC4238372460E6F01E88", "DD6936FE21F8F077C123A1A521C12224F72255B73E03A7260693E8A24B0FA389", "E23D4A036D7B70E9F595B1422079D2B91EDFBB1FB651A0633EAA8A9DC5F80703", "E35D28419ED02025CFA69038CD623962458DA5C695FBDEA3C22B0BFB25897092", "E3B6A2DB2ED7CE48842F7AC53241C7B71D54144BFB40C11F3F1D0B42F5EEA12D", "E75E72ED9F560EEC6EB4800073A43FC3AD19195A392282017895974A99026B6C", "E793C9B02FD8AA13E21C31228ACCB08119643B749C898964B1746D46C3D4CBD2", "EAA962C4FA4A6BAFEBE415196D351CCD888D4F53F3FA8AE6D7C466A94E6042BB", "EB04CF5EB1F39AFA762F2BB120F296CBA520C1B97DB1589565B81CB9A17B7244", "EBC5570C29018C4D67B1AA127BAF12F703B4611EBC17B7DAB5573894179B93FA", "EBD41040E4BB3EC742C9E381D31EF2A41A48B6685C96E7CEF3C1DF6CD4331C99", "EDF7EBBCA27A2A384D387B7D4010C666E2EDB4843E4C29B4AE1D5B9332E6B24D", "EEC5496B988CE98625B934092EEC2908BED0B0F316C2D4730C84EAF1F3D34881", "F1C1B50AE5A20DD8030EC9F6BC24823DD367B5255759B4E71B61FCE9F7375D73", "F356BEA244B7A91EB35D53CA9AD7864ACE018E2D35D5F8F96DDF68A6F41AA474", "F9E67D336C51002AC054C632022D66DDA2E7E3FFF10AD061ED31D8BBB410CFB2", "FD73DAD31C644FF1B43BEF0CCDDA96710B9CD9875ECA7E31707AF3E96D522BBD", "FF856A2D251DCD88D36656F450126798CFABAADE40799C722DE4D2B5DB36A73A"]),

            symantec_roots: Self::strs_to_strings(&["B478B812250DF878635C2AA7EC7D155EAA625EE82916E2CD294361886CD1FBD4", "37D51006C512EAAB626421F1EC8C92013FC5F82AE98EE533EB4619B8DEB4D06C", "A0459B9F63B22559F5FA5D4C6DB3F9F72FF19342033578F073BF1D1B46CBB912", "A0234F3BC8527CA5628EEC81AD5D69895DA5680DC91D1CB8477F33F878B95B0B", "363F3C849EAB03B0A2A0F636D7B86D04D3AC7FCFE26A0A9121AB9795F6E176DF", "9D190B2E314566685BE8A889E27AA8C7D7AE1D8AADDBA3C1ECF9D24863CD34B9", "FE863D0822FE7A2353FA484D5924E875656D3DC9FB58771F6F616F9D571BC592", "CB627D18B58AD56DDE331A30456BC65C601A4E9B18DEDCEA08E7DAAA07815FF0", "8D722F81A9C113C0791DF136A2966DB26C950A971DB46B4199F4EA54B78BFB9F", "A4310D50AF18A6447190372A86AFAF8B951FFB431D837F1E5688B45971ED1557", "4B03F45807AD70F21BFC2CAE71C9FDE4604C064CF5FFB686BAE5DBAAD7FDD34C", "CBB5AF185E942A2402F9EACBC0ED5BB876EEA3C1223623D00447E4F3BA554B65", "92A9D9833FE1944DB366E8BFAE7A95B6480C2D6C6C2A1BE65D4236B608FCA1BB", "EB04CF5EB1F39AFA762F2BB120F296CBA520C1B97DB1589565B81CB9A17B7244", "69DDD7EA90BB57C93E135DC85EA6FCD5480B603239BDC454FC758B2A26CF7F79", "9ACFAB7E43C8D880D06B262A94DEEEE4B4659989C3D0CAF19BAF6405E41AB7DF", "2399561127A57125DE8CEFEA610DDF2FA078B5C8067F4E828290BFB860E84B3C"]),
            symantec_exceptions: Self::strs_to_strings(&["17F96609AC6AD0A2D6AB0A21B2D1B5B2946BD04DBF120703D1DEF6FB62F4B661", "3DB76D1DD7D3A759DCCC3F8FA7F68675C080CB095E4881063A6B850FDD68B8BC", "6115F06A338A649E61585210E76F2ECE3989BCA65A62B066040CD7C5F408EDD0", "904FB5A437754B1B32B80EBAE7416DB63D05F56A9939720B7C8E3DCC54F6A3D1", "AC2B922ECFD5E01711772FEA8ED372DE9D1E2245FCE3F57A9CDBEC77296A424B", "A4FE7C7F15155F3F0AEF7AAA83CF6E06DEB97CA3F909DF920AC1490882D488ED", "8BB593A93BE1D0E8A822BB887C547890C3E706AAD2DAB76254F97FB36B82FC26", "B94C198300CEC5C057AD0727B70BBE91816992256439A7B32F4598119DDA9C97", "C3F697A92A293D86F9A3EE7CCB970E20E0050B8728CC83ED1B996CE9005D4C36", "7CAC9A0FF315387750BA8BAFDB1C2BC29B3F0BBA16362CA93A90F84DA2DF5F3E", "AC50B5FB738AED6CB781CC35FBFFF7786F77109ADA7C08867C04A573FD5CF9EE"]),

            tubitak1_trusted: Self::strs_to_strings(&["46EDC3689046D53A453FB3104AB80DCAEC658B2660EA1629DD7E867990648716"]),
            tubitak1_domains: Self::strs_to_strings(&["*.gov.tr", "*.k12.tr", "*.pol.tr", "*.mil.tr", "*.tsk.tr", "*.kep.tr", "*.bel.tr", "*.edu.tr", "*.org.tr"]),

            anssi_trusted: Self::strs_to_strings(&["B9BEA7860A962EA3611DAB97AB6DA3E21C1068B97D55575ED0E11279C11C8932"]),
            anssi_domains: Self::strs_to_strings(&["*.fr", "*.gp", "*.gf", "*.mq", "*.re", "*.yt", "*.pm", "*.bl", "*.mf", "*.wf", "*.pf", "*.nc", "*.tf"]),
        })
    }

    // OpenSSL policy
    pub fn openssl(time: u64) -> policy::ExecPolicy {
        policy::ExecPolicy::OpenSSL(policy::ExecOpenSSLEnvironment {
            time,
        })
    }
}

}
