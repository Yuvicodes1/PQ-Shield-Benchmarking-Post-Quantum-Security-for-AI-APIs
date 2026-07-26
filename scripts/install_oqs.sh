#!/usr/bin/env bash
set -euo pipefail

# Minimal local liboqs build required by Configuration B. No system install.
root="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$root/work"
if [ ! -d "$root/work/liboqs/.git" ]; then
  git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git "$root/work/liboqs"
fi
cmake -S "$root/work/liboqs" -B "$root/work/liboqs-min-build" \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
  -DOQS_MINIMAL_BUILD=KEM_ml_kem_768 \
  -DCMAKE_INSTALL_PREFIX="$root/work/oqs-prefix"
cmake --build "$root/work/liboqs-min-build" --parallel 4
cmake --install "$root/work/liboqs-min-build"
