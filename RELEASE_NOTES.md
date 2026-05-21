# Release Notes

## v4.1.2 (Current)

### Documentation
*   **DEPLOYMENT.md**: Rewritten GCP section — Cloud Run + Firestore (recommended) vs SQLite + GCS volume; environment variable reference.
*   **README.md**: Storage backends table and updated architecture diagram (database provider layer).
*   **CONTRIBUTING.md**, **THREAT_MODEL.md**, **SECURITY.md**, **LIMITATIONS.md**, **`.env.example`**: Aligned with pluggable SQLite/Firestore storage.

### Fixes
*   **Dockerfile**: Include `database-provider.ts` in the production image (required since v4.1.x for Docker and Cloud Run builds).

---

## v4.1.1

> Tag `v4.1.0` was not published: GitHub immutable-release rules blocked re-creating that tag after a failed first release attempt.

### Features
*   **Pluggable database layer**: New `database-provider.ts` with `IDatabaseProvider`, supporting **SQLite** (default, self-hosted) and **Firestore** (serverless / Cloud Run).
*   **Auto provider selection**: Uses Firestore when a valid `firebase-applet-config.json` is present or `DATABASE_PROVIDER=firestore`; otherwise SQLite. Placeholder values in config are ignored and the app safely falls back to SQLite.
*   **Firebase deployment artifacts**: `firebase-blueprint.json` and `firestore.rules` for Cloud Firestore setups.
*   **GCS FUSE mirroring**: SQLite provider can sync the local DB to a GCS-mounted path in container environments.

### Improvements
*   **Server refactor**: `server.ts` simplified around the database provider abstraction.
*   **Reverse proxy**: `trust proxy` enabled; rate limiters use default IP-based keying behind load balancers.
*   **SEO**: Enhanced `index.html` metadata (robots, canonical, JSON-LD).
*   **CLI documentation**: Reworked `cli/README.md` with clearer usage and `SECURESHARE_URL` examples.

### Security
*   **Firebase config out of Git**: `firebase-applet-config.json` is gitignored; credentials must stay local.
*   **Dependency updates**: Security patches including `uuid` 14, `ejs` 5, `vite`, `happy-dom`, `express-rate-limit`, and others.

### Infrastructure
*   **Dockerfile restored**: Multi-stage Docker build for self-hosted deployments (`docker compose up`, `docker build`).

### CLI Binaries (unchanged from v4.0.1)
Pre-built CLI binaries are attached to this release:
*   `secureshare-cli-linux`
*   `secureshare-cli-mac-arm64`
*   `secureshare-cli-mac-intel`
*   `secureshare-cli.exe`

---

## v4.0.1

### Auditor Improvements & Security Fixes
*   **Build Consistency**: Synchronized `package-lock.json` with `package.json` overrides to ensure deterministic and secure builds across Docker (`npm ci`) and local environments (`npm install`).
*   **Dependency Patching**: Resolved security vulnerabilities by enforcing patched versions of `flatted` and `express-rate-limit` across the entire dependency tree.
*   **Code Cleanup**: Removed dead code and obsolete commented-out middleware configurations in `server.ts` for better readability and maintainability.
*   **License Compliance**: Corrected the `SPDX-License-Identifier` header in `src/App.tsx` from Apache-2.0 to MIT to properly reflect the project's official license.

---

## v4.0.0

### Security Enhancements
*   **Argon2id Migration**: Completely removed legacy PBKDF2 support. All password hashing now uses the memory-hard Argon2id algorithm (via `hash-wasm`) for superior resistance against GPU-based cracking.
*   **Zero-Knowledge Architecture**: Re-verified and hardened the end-to-end encryption pipeline. The server never sees plaintext data or decryption keys.
*   **Dependency Updates**: Updated `express-rate-limit` and `flatted` to patch known vulnerabilities and improve stability.
*   **Strict CSP**: Hardened Content Security Policy to prevent XSS and data exfiltration.

### Features
*   **Proof of Work (PoW)**: Implemented a cryptographic Hashcash-style PoW system to prevent automated spam and DoS attacks during secret creation.
*   **Atomic Transactions**: Improved SQLite database operations with `IMMEDIATE` transactions to completely eliminate race conditions during secret access and deletion.
*   **Mobile Sharing**: Added QR code generation for easy and secure transfer of links to mobile devices.

### Documentation
*   Consolidated and cleaned up project documentation.
*   Added comprehensive `THREAT_MODEL.md` and `LIMITATIONS.md` to clearly define the security boundaries of the application.
*   Updated `DEPLOYMENT.md` with Docker and Cloud Run instructions.
*   Ensured all files correctly reference the MIT License.

---

## v3.x.x and earlier

*Legacy versions. Please upgrade to v4.0.0 for the latest security features and Argon2id support.*
