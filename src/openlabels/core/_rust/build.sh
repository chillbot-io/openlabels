#!/bin/bash
# Build the Rust extension for OpenLabels.
#
# Prerequisites:
#   - Rust toolchain (rustup)
#   - maturin (pip install maturin)
#
# Usage:
#   ./build.sh           # Build for current platform
#   ./build.sh release   # Build optimized release

set -e

cd "$(dirname "$0")"

MODE="${1:-dev}"

echo "Building openlabels_matcher Rust extension..."

if [ "$MODE" = "release" ]; then
    echo "Building release..."
    maturin build --release
else
    echo "Building development..."
    maturin develop
fi

echo "Build complete!"
