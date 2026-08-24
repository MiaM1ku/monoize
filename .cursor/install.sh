#!/usr/bin/env bash
set -euo pipefail

# Idempotent bootstrap for the Monoize Cloud Agent development environment.
# Runs after the repository is checked out. Safe to run repeatedly.

# System build dependencies for the native image codecs pulled in by the backend
# (mozjpeg, oxipng, jxl-sys, webp, image). The cmake-based crates compile C++,
# and clang selects the gcc-14 toolchain here; libstdc++-14-dev supplies the
# unversioned libstdc++.so that the linker needs for `-lstdc++`, which is absent
# on the base image and otherwise breaks the jxl-sys build.
sudo apt-get update
sudo apt-get install --yes --no-install-recommends \
  build-essential \
  clang \
  cmake \
  nasm \
  pkg-config \
  libstdc++-14-dev

# Bun is the frontend package manager and is invoked by build.rs during release
# builds. Install it only when it is not already present.
if ! command -v bun >/dev/null 2>&1 && [ ! -x "${HOME}/.bun/bin/bun" ]; then
  curl -fsSL https://bun.sh/install | bash
fi
export PATH="${HOME}/.bun/bin:${PATH}"

# The crate uses Rust edition 2024 (requires >= 1.85). Pin 1.89.0 to match the
# release Dockerfile so local and container builds use the same compiler.
rustup toolchain install 1.89.0 --profile minimal --component clippy
rustup default 1.89.0

# Frontend dependencies.
(cd frontend && bun install --frozen-lockfile)

# Warm the backend build cache so the first `cargo run` in a terminal is fast.
cargo build
