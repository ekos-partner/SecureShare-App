# Release Notes

## v4.0.1 (Current)

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
