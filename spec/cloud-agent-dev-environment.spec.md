# Cloud Agent Development Environment Specification

## 0. Status

- **Purpose:** Define the reproducible Cursor Cloud Agent development environment for Monoize.
- **Scope:** Applies to `.cursor/environment.json` and `.cursor/install.sh`.
- **Relation to other specs:** This environment runs the debug (non-embedded) build. Frontend embedding and the release container image remain governed by `frontend_delivery.spec.md` and `container-image.spec.md`.

## 1. Configuration source

CD-C1. The environment MUST be repository-managed through `.cursor/environment.json`.

CD-C2. `.cursor/environment.json` MUST run as user `ubuntu`.

CD-C3. `.cursor/environment.json` MUST set `install` to `bash .cursor/install.sh`.

## 2. Install phase invariants

The install phase runs `.cursor/install.sh` after repository checkout. It MUST be idempotent: a second run on an already-prepared machine MUST succeed and MUST NOT require manual intervention.

CD-I1. Install MUST provide these system executables and libraries: `cc`/`clang`, `c++`, `cmake`, `nasm`, `pkg-config`, and an unversioned `libstdc++.so` resolvable by the active C++ toolchain.

CD-I2. `libstdc++.so` availability is required because the backend depends on `jxl-sys`, `mozjpeg`, `oxipng`, `webp`, and `image`, whose cmake-based C++ compilation links `-lstdc++`. On the base image the active `c++` driver is clang using the gcc-14 toolchain, which lacks the unversioned symlink until `libstdc++-14-dev` is installed. Install MUST install `libstdc++-14-dev`.

CD-I3. Install MUST make the `bun` executable available at `${HOME}/.bun/bin/bun`. Install MUST NOT reinstall `bun` when it is already present.

CD-I4. Install MUST make Rust toolchain `1.89.0` the default. `1.89.0` is required because the crate uses edition 2024 (minimum 1.85) and matches the release build pinned by `container-image.spec.md` (CI-B1).

CD-I5. Install MUST run `bun install --frozen-lockfile` in `frontend/`.

CD-I6. Install MUST run `cargo build` (debug profile) to completion, producing `target/debug/monoize`.

## 3. Runtime phase invariants

The runtime phase starts one process per entry in `terminals`.

CD-R1. `.cursor/environment.json` MUST declare exactly two terminals named `backend` and `frontend`.

CD-R2. The `backend` terminal MUST run `cargo run`. With the debug profile the frontend is not embedded (see `build.rs`), so the backend binary serves only the API, metrics, and a plain-text root placeholder; the dashboard UI is served by the `frontend` terminal.

CD-R3. The `backend` process MUST listen on `0.0.0.0:8080` (the default `MONOIZE_LISTEN`) and MUST create and migrate the SQLite database at `./data/monoize.db` (the default `MONOIZE_DATABASE_DSN`) on startup.

CD-R4. The `frontend` terminal MUST run the Vite dev server (`bun run dev --host`) in `frontend/`, listening on port `5173`, with `${HOME}/.bun/bin` on `PATH`.

CD-R5. The Vite dev server MUST proxy `/api/*` to `http://127.0.0.1:8080` (consistent with `frontend_delivery.spec.md` FD-A2), so a request to `http://127.0.0.1:5173/api/v1/models` reaches the backend.

CD-R6. `.cursor/environment.json` MUST expose ports `8080` and `5173`.

## 4. End-to-end acceptance

CD-E1. `GET http://127.0.0.1:8080/metrics` MUST return HTTP `200`.

CD-E2. `GET http://127.0.0.1:8080/v1/models` without credentials MUST return HTTP `401`.

CD-E3. When no user exists, `POST http://127.0.0.1:8080/api/dashboard/auth/register` with a valid `{username, password}` body MUST return HTTP `200` and assign role `super_admin` to the created user.

CD-E4. The dashboard at `http://127.0.0.1:5173` MUST render the login page, MUST authenticate the registered account, and MUST render the authenticated dashboard views without client errors.
