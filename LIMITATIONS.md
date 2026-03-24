# Security Limitations

SecureShare is designed to be a highly secure, zero-knowledge platform. However, no system is perfectly secure. This document outlines the known limitations and boundaries of SecureShare's security model.

## 1. Endpoint Security

SecureShare **cannot** protect your data if the device you are using is compromised.

*   **Keyloggers:** If a keylogger is installed on your computer or phone, it can capture the secret as you type it, before SecureShare has a chance to encrypt it.
*   **Screen Scrapers/Malware:** Malicious software can read the contents of your screen, capturing the plaintext secret after it has been decrypted by the recipient.
*   **Browser Extensions:** Malicious or overly permissive browser extensions can read data from the DOM (the webpage structure) or intercept network requests before encryption occurs.

**Mitigation:** Ensure both the sender and recipient are using trusted, malware-free devices and modern, updated web browsers.

## 2. Trust in the Server Operator (Active Attacks)

While SecureShare's Zero-Knowledge architecture protects against a *passive* server compromise (e.g., someone stealing the database), it **cannot** fully protect against an *active* attacker who controls the server hosting the application.

*   **Malicious JavaScript:** The server operator could modify the frontend code (the HTML/JS sent to your browser) to silently steal your plaintext secret or the decryption key *before* the encryption process happens.
*   **Targeted Attacks:** An active attacker could serve the malicious code only to specific IP addresses or users, making detection difficult.

**Mitigation:** You must trust the person or organization hosting the SecureShare instance. If you require absolute certainty, you should host your own instance of SecureShare and verify the source code.

## 3. Link Interception (Without Passwords)

If you share a SecureShare link (which includes the `#key` fragment) over an insecure channel (e.g., unencrypted email, SMS, or a compromised chat app), anyone who intercepts that link can view the secret.

*   **The Link IS the Key:** For secrets without an additional password, possessing the full URL is sufficient to decrypt the data.

**Mitigation:**
1.  Share the link over a secure, end-to-end encrypted channel (like Signal or WhatsApp).
2.  **Always use the optional password feature** for highly sensitive information. Share the password via a *different* channel than the link (e.g., send the link via email, and the password via SMS).

## 4. Technical Limits

To prevent abuse and ensure system stability, SecureShare enforces the following hard limits:

*   **Maximum Secret Size:** 1MB (Megabyte) of encrypted data. Attempting to encrypt larger files or text blocks will fail.
*   **Maximum Views:** A secret can be viewed a maximum of 10 times before it is permanently deleted.
*   **Maximum Expiration Time:** Secrets can be stored for a maximum of 7 days (168 hours). After this time, they are automatically purged from the database.
*   **Rate Limiting:** Strict IP-based rate limits are enforced to prevent brute-force attacks and denial-of-service (DoS) attempts.

## 5. Metadata

While the *content* of your secret is encrypted and unreadable by the server, certain metadata is inevitably exposed:

*   **Size:** The server knows the approximate size of the encrypted blob.
*   **Timing:** The server knows when a secret was created and when it was accessed.
*   **IP Addresses:** The server logs the IP addresses of both the creator and the viewer (though these logs may be configured to rotate or anonymize depending on the deployment).
*   **Access Patterns:** The server knows how many times a secret has been viewed and if password attempts have failed.

This metadata cannot be used to decrypt the secret, but it could potentially be used for traffic analysis.
