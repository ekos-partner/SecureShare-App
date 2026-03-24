# Threat Model

This document outlines the threat model for SecureShare, detailing the specific attacks the system is designed to mitigate and the assumptions made about the operating environment.

## 🛡️ What SecureShare Protects Against

SecureShare is designed to provide high-security, zero-knowledge sharing of sensitive information. It specifically mitigates the following threats:

### 1. Network Eavesdropping (Man-in-the-Middle)
- **Threat**: An attacker intercepts traffic between the sender and the SecureShare server, or between the server and the recipient.
- **Mitigation**: All data is encrypted *before* it leaves the sender's browser using AES-256-GCM. Even if TLS/SSL is compromised, the attacker only sees ciphertext. The decryption key is never transmitted over the network; it is passed via the URL fragment (`#key`), which browsers do not send to servers.

### 2. Server Compromise (Zero-Knowledge)
- **Threat**: The SecureShare server is hacked, or the database is leaked/stolen.
- **Mitigation**: The server only stores the encrypted blob (ciphertext + IV) and a cryptographic salt. It **never** receives or stores the decryption key or plaintext passwords. A compromised database yields no usable information without the unique URL fragments held by the recipients.

### 3. Automated Abuse & DoS (Denial of Service)
- **Threat**: Bots flood the server with requests to create secrets, exhausting database storage or compute resources.
- **Mitigation**: A cryptographic Proof of Work (PoW) system (Hashcash) requires the client to solve a computationally expensive SHA-256 challenge before a secret can be created. This makes automated spamming economically and computationally unviable.

### 4. Brute-Force Password Attacks
- **Threat**: An attacker attempts to guess the optional access password for a secret.
- **Mitigation**: 
  - **Argon2id**: Passwords are hashed using the memory-hard Argon2id algorithm, making offline cracking extremely slow and expensive.
  - **Auto-Destruction**: The server permanently deletes the encrypted blob after 3 failed password attempts, preventing online brute-forcing.

### 5. Race Conditions (Simultaneous Access)
- **Threat**: Two users click a "one-time view" link at the exact same millisecond, potentially allowing both to read a secret meant for only one.
- **Mitigation**: Database reads and deletions are wrapped in strict `IMMEDIATE` SQLite transactions. This guarantees atomic operations, ensuring that only the first request succeeds and subsequent requests fail.

## ⚠️ What SecureShare DOES NOT Protect Against

It is crucial to understand the limitations of any security system. SecureShare cannot protect against the following threats:

### 1. Endpoint Compromise
- **Threat**: The sender's or recipient's device is infected with malware (e.g., keyloggers, screen scrapers, malicious browser extensions).
- **Limitation**: If the device itself is compromised, the plaintext secret can be captured before encryption or after decryption. SecureShare assumes the endpoints are secure.

### 2. Malicious Server Operator (Active Attack)
- **Threat**: The person hosting the SecureShare instance maliciously modifies the JavaScript served to users.
- **Limitation**: While a passive server compromise (stealing the database) is mitigated by E2EE, an *active* attacker who controls the server can serve modified frontend code that steals the plaintext secret or the decryption key before encryption occurs. Users must trust the operator of the SecureShare instance not to serve malicious code.

### 3. Social Engineering & Phishing
- **Threat**: A user is tricked into sharing the secure link (including the `#key` fragment) with an unintended recipient.
- **Limitation**: SecureShare cannot verify the identity of the person clicking the link. If the link falls into the wrong hands, the secret can be accessed (unless protected by an additional, out-of-band password).

### 4. Shoulder Surfing
- **Threat**: Someone physically looks at the sender's or recipient's screen while the plaintext secret is visible.
- **Limitation**: SecureShare provides a "hide/reveal" toggle for passwords, but cannot prevent physical observation.

## Conclusion

SecureShare provides robust protection against network-level and server-level threats through client-side encryption and zero-knowledge architecture. However, it relies on the security of the endpoints and the trustworthiness of the server operator serving the frontend code.
