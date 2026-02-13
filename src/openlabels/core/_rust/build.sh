#!/bin/bash
# Build the Rust extension for OpenLabels.
#
# Prerequisites:
#   - Rust toolchain (rustup)
#   - maturin (pip install maturin)
#
# Usage:
#   ./build.sh           # Editable dev install (debug)
#   ./build.sh release   # Editable dev install (optimized)

set -e

RUST_DIR="$(cd "$(dirname "$0")" && pwd)"

MODE="${1:-dev}"

echo "Building openlabels_matcher Rust extension..."

if [ "$MODE" = "release" ]; then
    echo "Building release (editable install)..."
    pip install -e "$RUST_DIR" --config-settings="build-args=--release"
else
    echo "Building development (editable install)..."
    pip install -e "$RUST_DIR"
fi

echo "Build complete!"
