#!/usr/bin/env bash
set -euo pipefail

# Builds libyolac_ffi.so for Android ABIs using cargo-ndk and places outputs in app/src/main/jniLibs/.
# Prerequisites: rustup targets (aarch64-linux-android armv7-linux-androideabi x86_64-linux-android) + cargo-ndk + Android NDK.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
JNI_DIR="${SCRIPT_DIR}/../app/src/main/jniLibs"

mkdir -p "${JNI_DIR}"
cd "${ROOT_DIR}/core"

cargo ndk \
    -t arm64-v8a \
    -t armeabi-v7a \
    -t x86_64 \
    -o "${JNI_DIR}" \
    build --release -p yolac-ffi --features android-jni

echo "Built Android JNI libraries into ${JNI_DIR}"
