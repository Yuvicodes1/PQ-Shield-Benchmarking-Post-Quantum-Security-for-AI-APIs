#!/usr/bin/env bash
# Builds liboqs from source, restricted to exactly the two mechanisms this
# project uses (ML-KEM-768, ML-DSA-65), and installs it under
# <repo-root>/oqs-prefix/. This minimal build compiles in well under a
# minute on a single core, versus several minutes for a full liboqs build
# with every supported algorithm -- deliberate, since CI/reviewer
# reproduction time matters for an open-source release.
#
# To point the project at a different liboqs build instead (e.g. a
# system-wide install, or a full build with every algorithm), skip this
# script and set PQ_SHIELD_OQS_LIB to the absolute path of your liboqs
# shared library.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${REPO_ROOT}/oqs-prefix"
SRC_DIR="${REPO_ROOT}/liboqs"

echo "==> Building liboqs (ML-KEM-768, ML-DSA-65 only) into ${PREFIX}"

if [ ! -d "${SRC_DIR}" ]; then
  git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git "${SRC_DIR}"
else
  echo "==> liboqs source already present at ${SRC_DIR}, skipping clone"
fi

mkdir -p "${SRC_DIR}/build"
cd "${SRC_DIR}/build"

cmake -GNinja \
  -DCMAKE_INSTALL_PREFIX="${PREFIX}" \
  -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65" \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DBUILD_SHARED_LIBS=ON \
  ..

ninja -j"$(nproc)"
ninja install

case "$(uname -s)" in
  Darwin) LIBOQS_EXT="dylib" ;;
  *) LIBOQS_EXT="so" ;;
esac
LIBOQS_LIB="${PREFIX}/lib/liboqs.${LIBOQS_EXT}"

echo "==> liboqs installed to ${PREFIX}/lib"
echo "==> Set this in your shell (or a .env file the project loads):"
echo "    export PQ_SHIELD_OQS_LIB=${LIBOQS_LIB}"
echo "==> Verifying the build with the project's own self-test..."

cd "${REPO_ROOT}"
PQ_SHIELD_OQS_LIB="${LIBOQS_LIB}" python3 -m crypto.oqs_adapter
