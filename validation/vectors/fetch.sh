#!/usr/bin/env bash
# Re-downloads the FULL upstream NIST ACVP vector files this project's
# trimmed validation/vectors/*.json were derived from, for independent
# verification that the trimming didn't cherry-pick or alter any test case.
#
# The trimmed files committed to this repo are exact subsets (whole
# testGroups, unmodified test entries) of what this script downloads --
# see each trimmed file's "_note" key for exactly which groups were kept
# and why. Diffing is the intended way to audit this:
#
#   ./validation/vectors/fetch.sh /tmp/nist_full
#   python3 -c "
#   import json
#   full = json.load(open('/tmp/nist_full/ML-KEM-keyGen-FIPS203.json'))
#   trimmed = json.load(open('validation/vectors/ml_kem_768_keygen.json'))
#   full_g = [g for g in full['testGroups'] if g['parameterSet']=='ML-KEM-768'][0]
#   assert full_g == trimmed['testGroups'][0], 'trimmed vectors do not match upstream'
#   print('OK: trimmed ML-KEM-768 keyGen group is byte-identical to upstream')
#   "
#
# Usage: ./validation/vectors/fetch.sh [output_dir]   (default: ./nist_full)

set -euo pipefail

OUT_DIR="${1:-nist_full}"
BASE="https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files"

mkdir -p "$OUT_DIR"

echo "Downloading full upstream ACVP vector files into $OUT_DIR/ ..."
curl -sL "$BASE/ML-KEM-keyGen-FIPS203/internalProjection.json"     -o "$OUT_DIR/ML-KEM-keyGen-FIPS203.json"
curl -sL "$BASE/ML-KEM-encapDecap-FIPS203/internalProjection.json" -o "$OUT_DIR/ML-KEM-encapDecap-FIPS203.json"
curl -sL "$BASE/ML-DSA-sigVer-FIPS204/internalProjection.json"     -o "$OUT_DIR/ML-DSA-sigVer-FIPS204.json"

for f in "$OUT_DIR"/*.json; do
    python3 -c "import json,sys; json.load(open(sys.argv[1])); print('OK:', sys.argv[1])" "$f"
done

echo
echo "Done. These are U.S. Government work (public domain, 17 U.S.C. 105)."
echo "See https://github.com/usnistgov/ACVP-Server for provenance and licensing."
