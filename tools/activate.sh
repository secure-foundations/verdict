# Usage: source this script at the root of the repo

REPO_ROOT=$(pwd)

git submodule update --init

# Build verus
(cd deps/verus/source &&
rustup toolchain install &&
[ -f z3 ] || ./tools/get-z3.sh &&
source ../tools/activate &&
vargo build --release) || return 1

export PATH="$REPO_ROOT/deps/verus/source/target-verus/release:$PATH"
