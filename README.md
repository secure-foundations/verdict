Verified X.509 Certificate Validation
---

Verdict is an end-to-end formally verified X.509 certificate validation library.
You can use Verdict to derive X.509 validators of your own policies, or use one of
our formal models of X.509 policies in Chrome, Firefox, or OpenSSL.

See also
- Our paper at USENIX Security 2025: [https://verdict.rs/paper](https://verdict.rs/paper).
- Documentation: [https://secure-foundations.github.io/verdict/verdict/index.html](https://secure-foundations.github.io/verdict/verdict/index.html).
- Benchmarking harnesses: [https://github.com/secure-foundations/verdict-bench](https://github.com/secure-foundations/verdict-bench).

## Dependencies

Build dependencies in Ubuntu 24.04 (other systems are similar):
- Cargo
- build-essential, git, unzip, curl

## Using Verdict as a library

To use the `verdict` in your Cargo crate:
```
cargo add verdict --git https://github.com/secure-foundations/verdict.git
```
Please see our [documentation](https://secure-foundations.github.io/verdict/verdict/index.html) for examples and more details.

## Using the CLI

### Verify and Build

To build, first run (Bash or Zsh)
```
. tools/activate.sh
```
This will first compile a vendored version of Verus and add relevant binaries to `PATH`.

To verify and build the entire project, run
```
cargo verus build --release
```
Then use `target/release/verdict` to validate certificate chains or run benchmarks.
See `target/release/verdict --help` for details.

By default, we use crypto primitives from [`AWS-LC`](https://github.com/aws/aws-lc).
However, some of the primitives are not formally verified on certain platforms (see [here](https://github.com/aws/aws-lc#formal-verification) for more details).
We also have a feature `verified-crypto` that selects only verified primitives
from [libcrux](https://github.com/cryspen/libcrux) and AWS-LC.
To use it, compile with
```
cargo verus build --release --features verified-crypto
```

To run some sanity checks
```
cargo test --workspace
```

### Build without verification

If your system does not support Verus, or for some reason Verus is not working,
an alternative is to just build the project without invoking Verus for formal verification.

To do this, simply run (without running `. tools/activate.sh`)
```
git submodule update --init
cargo build --release
```
which should work like in a normal Rust package, with all verification annotations stripped.

### Tracing

Use
```
cargo verus build [--release] --features trace
```
to build a version with tracing enabled.
This will print out every successfully parsed construct and the result of each predicate in the policy DSL.

## Project Structure

If you are considering using Verdict or any of its components, see these crates:
- `verdict` is the main verified X.509 validation library. It includes implementations of different policies (`verdict/src/policy`) as well as the policy-independent validation procedure (`verdict/src/validator.rs`).
- `verdict-bin` builds an executable front-end of Verdict that can, e.g., validate given certificate chains and run benchmarks against other X.509 validators.
  This crate is unverified and is used for calling the main validation procedure in `verdict`.
- `verdict-parser` contains the verified parsers and serializers of X.509 and various ASN.1 components.

Other crates include supporting tools and macros.
