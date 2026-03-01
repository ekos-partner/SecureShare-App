# Threat Model - SecureShare

This document outlines the security assumptions, trust boundaries, and threat mitigations for the SecureShare application.

## 1. Assets to Protect
- **Secret Content**: The primary payload (passwords, notes, keys).
- **Access Passwords**: The optional secondary layer of protection.
- **System Availability**: Protection against DDoS and resource exhaustion.

## 2. Trust Boundaries
- **Client (Browser or CLI)**: Trusted to perform encryption and handle the decryption key.
- **Network**: Untrusted. Assumed to be subject to eavesdropping (mitigated by HTTPS and E2EE).
- **Server**: Partially trusted. Trusted to store encrypted blobs and enforce TTL/view limits, but NOT trusted with the decryption key.

## 3. Threat Actors & Mitigations

### A. Network Eavesdropper (Man-in-the-Middle)
- **Threat**: Intercepting data in transit.
- **Mitigation**: Mandatory HTTPS (TLS 1.2+), HSTS, and End-to-End Encryption.

### B. Malicious Server Administrator / Compromised Server
- **Threat**: Accessing the database to read secrets or modifying the application code.
- **Mitigation**: 
    - **Zero-Knowledge Storage**: The server never receives the decryption key (stored in URL fragment `#`). Ciphertexts are useless without the key.
    - **JS Integrity Risk**: We acknowledge that a compromised server could serve malicious JavaScript to intercept keys. We mitigate this via strict CSP, HSTS, and by keeping the client-side code minimal and auditable. This is a fundamental limitation of web-based E2EE.

### C. Brute-Force Attacker & Automated Spam (DoS)
- **Threat**: Guessing the access password for a known secret ID, or flooding the server with millions of secret creation requests to exhaust resources.
- **Mitigation**: 
    - **Cryptographic Proof of Work (PoW)**: All secret creation requests must solve a dynamic Hashcash challenge. This makes automated spam economically unfeasible.
    - **PoW Replay Protection**: Server-side nonce tracking prevents the reuse of pre-computed PoW solutions.
    - **Strict Rate Limiting**: IP-based limits enforced on all server endpoints.
    - **Burn-on-Fail Policy**: The secret is permanently deleted after 3 failed password attempts.
    - PBKDF2 with 100,000 iterations for key derivation.

### D. Link Enumerator / Scraper
- **Threat**: Guessing secret IDs to find valid secrets.
- **Mitigation**: 
    - UUID v4 for secret IDs (virtually impossible to guess).
    - Opaque error messages (404 for both non-existent and expired secrets).

### E. Cross-Site Scripting (XSS)
- **Threat**: Injecting malicious scripts to steal the decryption key from the URL fragment.
- **Mitigation**: 
    - **XSS**: Strict Content Security Policy (CSP) with Nonce-based script execution. No `unsafe-inline` or `unsafe-eval` allowed.

### F. Race Condition (Double Read)
- **Threat**: Two users accessing a "one-time" secret simultaneously, both receiving the content before the first one is deleted.
- **Mitigation**: 
    - **Atomic Transactions**: We use `IMMEDIATE` database transactions in SQLite. This locks the database for writing at the start of the read operation, ensuring that the "Check -> Verify -> Delete" sequence is truly atomic and race-condition free.

## 4. What we do NOT guarantee
- **Endpoint Security**: We cannot protect against keyloggers, screen scrapers, or compromised browsers on the user's device.
- **Social Engineering**: We cannot prevent a user from sharing a link with the wrong person.
- **Recipient Trust**: Once a recipient decrypts the secret, they can copy or screenshot it.
