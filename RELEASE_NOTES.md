# 🚀 Release Notes - SecureShare v3.0.1

**Title: The Zero-Knowledge Refinement Update**

**Description:**
This maintenance release focuses on optimizing the core architecture for high-performance production environments. We have stripped away legacy administrative overhead to deliver a leaner, faster, and more secure secret-sharing experience. By transitioning to a pure Zero-Knowledge model with a dedicated CLI tool, SecureShare v3.0.1 ensures that your sensitive data remains private and your infrastructure stays lightweight.

---

### 🛠️ Key Improvements

*   **Optimized Production Build**: Refined the `Dockerfile` with multi-stage builds and `npm ci`, resulting in a significantly smaller image footprint and faster deployment cycles.
*   **Dependency Pruning**: Removed over 5MB of unused legacy packages (including `react-markdown`, `remark-gfm`, and `cookie-parser`), reducing the attack surface and improving application startup time.
*   **Enhanced System Monitoring**: Introduced the `npm run stats` utility, allowing administrators to securely query system health, secret counts, and logs directly from the server console without exposing an external API.
*   **Refined Security Documentation**: Updated all technical documentation and diagrams to reflect the new streamlined architecture, ensuring clear guidance for security audits and compliance.
*   **Mobile UI Stability**: Fixed critical layout issues in the informational modals to ensure a consistent experience across all mobile browsers and screen resolutions.

### 🛡️ Security & Integrity
*   **Web Crypto API**: Re-validated the AES-256-GCM implementation to ensure 100% client-side encryption.
*   **Argon2id KDF**: Fully migrated from PBKDF2 to Argon2id for password hashing, aligning with OWASP 2025 recommendations.
*   **Rate Limiting**: Fine-tuned the `express-rate-limit` configurations to better handle high-traffic scenarios while maintaining strict protection against brute-force attacks.

---
*For deployment instructions, please refer to the `DEPLOYMENT.md` file.*
