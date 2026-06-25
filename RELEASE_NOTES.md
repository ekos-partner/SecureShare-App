# Release Notes

## v4.2.0 (Current)

### Features
*   **Firebase via environment variables**: Firestore config from `FIREBASE_CONFIG` JSON or individual `FIREBASE_*` vars — ideal for GCP Cloud Run Secret Manager (no config file in Git).
*   **PWA support**: Web app manifest, service worker (`public/sw.js`), and installable icons.
*   **Health API**: `GET /api/health` returns active database provider (`sqlite` / `firestore`).
*   **Cloud Run UX warning**: Banner when SQLite fallback is detected on a non-local host (ephemeral storage on serverless).

### Fixes
*   **View password input**: Fixed controlled input (`value` instead of invalid `viewValue` prop).
*   **Production static serving**: Removed `ejs` runtime dependency; nonce injection via string replace in production.
*   **Firestore PoW**: Transactional nonce registration on Firestore provider.

### Documentation
*   **DEPLOYMENT.md**: Clear split — **SQLite + Docker for self-hosted** (recommended default), **Firestore for GCP Cloud Run only**.
*   **README.md**, **DEPLOYMENT.md**, **LIMITATIONS.md**: Self-hosted vs GCP guidance; **data persistence warnings** (when SQLite links are safe vs lost).
*   **`.env.example`**: Firebase variables documented as GCP-only (commented out by default).

### Dependencies
*   `express` 4.22.2, `qs` override; removed production dependency on `ejs`.

---

## v4.1.2

### Documentation
*   **DEPLOYMENT.md**: Cloud Run + Firestore vs SQLite + GCS volume; environment variable reference.
*   **README.md**: Storage backends and database provider architecture diagram.
*   Aligned **CONTRIBUTING**, **THREAT_MODEL**, **SECURITY**, **LIMITATIONS**, **`.env.example`** with pluggable storage.

### Fixes
*   **Dockerfile**: Include `database-provider.ts` in the production image.

---

## v4.1.1

> Tag `v4.1.0` was not published (GitHub immutable-release rules).

### Features
*   **Pluggable database layer**: `IDatabaseProvider` with **SQLite** (default) and **Firestore** (serverless / Cloud Run).
*   **Auto provider selection** with placeholder detection; safe SQLite fallback.
*   **Firebase deployment artifacts**: `firebase-blueprint.json`, `firestore.rules`.
*   **GCS FUSE mirroring** for SQLite in containers.
*   **Server refactor** around database provider; SEO metadata; CLI README updates.
*   **Firebase config gitignored**; restored Dockerfile for self-hosted builds.

---

## v4.0.1

### Auditor Improvements & Security Fixes
*   **Build Consistency**: Synchronized `package-lock.json` with `package.json` overrides.
*   **Dependency Patching**: Patched `flatted` and `express-rate-limit` across the dependency tree.
*   **Code Cleanup**: Removed dead code in `server.ts`.
*   **License Compliance**: SPDX header in `src/App.tsx` corrected to MIT.

---

## v4.0.0

### Security Enhancements
*   **Argon2id Migration**: Removed legacy PBKDF2 support.
*   **Zero-Knowledge Architecture**: Hardened E2EE pipeline.
*   **Strict CSP**: Hardened Content Security Policy.

### Features
*   **Proof of Work (PoW)**: Hashcash-style anti-spam.
*   **Atomic Transactions**: SQLite `IMMEDIATE` transactions.
*   **Mobile Sharing**: QR code generation.

### Documentation
*   `THREAT_MODEL.md`, `LIMITATIONS.md`, `DEPLOYMENT.md` updates.

---

## v3.x.x and earlier

*Legacy versions. Please upgrade to v4.0.0 or later.*
