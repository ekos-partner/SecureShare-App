# Security Policy

## Supported Versions

Currently, the following versions of SecureShare are supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 4.x.x   | :white_check_mark: |
| < 4.0.0 | :x:                |

## Reporting a Vulnerability

We take the security of SecureShare very seriously. If you discover a security vulnerability, please report it immediately.

**Please DO NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them to the maintainers privately via the contact information provided at `/.well-known/security.txt` or `/security.txt` on any deployed instance, or by emailing the repository owner directly.

Please provide the following information in your report:

*   A description of the vulnerability.
*   The steps required to reproduce the vulnerability.
*   The impact of the vulnerability.
*   Any possible mitigations or workarounds.

We will acknowledge receipt of your vulnerability report within 48 hours and strive to send you regular updates about our progress. If you have not received a reply to your email within 48 hours, please follow up to ensure we received your original message.

## Security Architecture

SecureShare is built on a Zero-Knowledge architecture:

1.  **Client-Side Encryption**: All encryption and decryption happen exclusively in the user's browser using the Web Crypto API (AES-256-GCM).
2.  **Key Isolation**: The decryption key is generated on the client and stored in the URL fragment (`#key`). The URL fragment is never sent to the server.
3.  **Strong Key Derivation**: We use Argon2id (via `hash-wasm`) for deriving keys from optional passwords.
4.  **Anti-Abuse**: We employ a cryptographic Proof of Work (PoW) system to prevent DoS attacks and spam.

For a detailed breakdown of our security model, please refer to the [Threat Model](THREAT_MODEL.md) and [Limitations](LIMITATIONS.md) documents.
