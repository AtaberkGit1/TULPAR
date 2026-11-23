#!/usr/bin/env bash
set -euo pipefail

# Builds libyolac_ffi.a for iOS device & simulator and packages YolacFfi.xcframework on macOS.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
OUT_DIR="${SCRIPT_DIR}/../Frameworks"

mkdir -p "${OUT_DIR}"
cd "${ROOT_DIR}/core"

cargo build --release --target aarch64-apple-ios -p yolac-ffi
cargo build --release --target aarch64-apple-ios-sim -p yolac-ffi

rm -rf "${OUT_DIR}/YolacFfi.xcframework"
xcodebuild -create-xcframework \
    -library "${ROOT_DIR}/core/target/aarch64-apple-ios/release/libyolac_ffi.a" \
    -headers "${ROOT_DIR}/core/crates/yolac-ffi/include" \
    -library "${ROOT_DIR}/core/target/aarch64-apple-ios-sim/release/libyolac_ffi.a" \
    -headers "${ROOT_DIR}/core/crates/yolac-ffi/include" \
    -output "${OUT_DIR}/YolacFfi.xcframework"

# Optionally populate YolacOfficialGithubRepo in Info.plist ONLY from real git remote origin / YOLAC_GITHUB_REPO
REPO_SLUG="${YOLAC_GITHUB_REPO:-}"
if [[ -z "${REPO_SLUG}" ]]; then
    ORIGIN_URL="$(git -C "${ROOT_DIR}" remote get-url origin 2>/dev/null || true)"
    if [[ "${ORIGIN_URL}" =~ github\.com[:/]([^/]+/[^/.]+)(\.git)?$ ]]; then
        REPO_SLUG="${BASH_REMATCH[1]}"
    fi
fi
if [[ -n "${REPO_SLUG}" ]] && command -v /usr/libexec/PlistBuddy >/dev/null 2>&1; then
    /usr/libexec/PlistBuddy -c "Set :YolacOfficialGithubRepo ${REPO_SLUG}" "${SCRIPT_DIR}/../YolacApp/Info.plist"
fi

echo "Created ${OUT_DIR}/YolacFfi.xcframework"
