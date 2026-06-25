# 🛡️ SecureShare: Share Secrets Securely

**A simple way to send sensitive information with end-to-end encryption. What you share is for the recipient's eyes only.**

![SecureShare Screenshot](screenshot.png)

## What is SecureShare?

Have you ever needed to send a password, API key, or private note and felt uneasy doing it over email or chat? SecureShare solves this problem.

It's a simple tool that lets you create a **secure, one-time link** for your sensitive data. The link automatically expires after the first access or after a set time, ensuring your information doesn't stay on the internet forever.

### Key Features (in simple terms):

-   **🔒 The Client-Side Advantage (Zero-Knowledge)**: Unlike many other "secure" sharing tools that encrypt data on their servers, SecureShare performs all encryption **locally in your browser**. We never see your plaintext data, and we never see your decryption keys.
-   **🔥 Self-Destructing Links**: Links are automatically deleted from the server after they are used or expire.
-   **🛡️ Anti-Spam Protection**: Built-in Proof of Work (Hashcash) prevents automated bots from flooding the service.
-   **🔑 Password Protection**: Add an extra layer of security with a password (also hashed locally).
-   **📱 Easy Mobile Sharing**: Generate a QR code to securely transfer the link to your mobile device.

---

## For the Technically Curious: Security Architecture

SecureShare is a high-security, zero-knowledge platform for sharing sensitive information. It is designed with a "Privacy by Design" approach, ensuring that even the server hosting the data cannot access the content.

### 🔐 Core Security Principles

#### 1. End-to-End Encryption (E2EE) & Zero-Knowledge
All encryption and decryption happen exclusively in the user's browser.
- **Algorithm**: AES-256-GCM (Authenticated Encryption with Associated Data).
- **Key Storage**: The unique decryption key is generated on the client and stored in the URL fragment (the part after the `#`). 
- **Zero-Knowledge**: Per W3C standards, the URL fragment is **never sent to the server**. Our infrastructure only sees the encrypted blob, never the key.

#### 2. Advanced Anti-DoS & Anti-Spam (Proof of Work)
To ensure high availability and prevent automated abuse, SecureShare implements a robust, cryptographic Proof of Work (PoW) system.
- **Hashcash Implementation**: Every secret creation request requires the client to solve a computationally expensive SHA-256 challenge.
- **Dynamic Difficulty**: The challenge difficulty is dynamically adjusted by the server.
- **Replay Protection**: A server-side nonce store (SQLite or Firestore, depending on deployment) guarantees that a PoW solution can only be used exactly once.
- **Strict Expiry**: Challenges are cryptographically salted with a timestamp and expire strictly after 10 minutes, preventing pre-computation attacks.

#### 3. Strong Key Derivation (KDF)
When an optional access password is set, we don't use it directly as a key.
- **Mechanism**: Argon2id (OWASP 2025 recommended).
  - Memory: 19 MiB
  - Iterations: 2
  - Parallelism: 1
- **Salt**: Every secret has a unique, cryptographically secure random salt generated on the client.

#### 4. Brute-Force Protection & Auto-Destruction
To prevent automated guessing and unauthorized access:
- **Auto-Destruction**: A secret is **permanently deleted** from the database after 3 failed password attempts.
- **Rate Limiting**: Strict IP-based and global rate limits are enforced on all server endpoints.
- **Atomic Operations**: Secret reads, view-count updates, and deletions are atomic at the storage layer (SQLite `IMMEDIATE` transactions or Firestore transactions), eliminating race conditions when two recipients open a one-time link at the same time.

### 🗄️ Storage Backends

| Backend | When to use | Configuration |
| :--- | :--- | :--- |
| **SQLite** (default) | **Self-hosted**, Docker, VPS, dev, most PaaS with a disk | Nothing extra — or `DATABASE_PROVIDER=sqlite` |
| **Cloud Firestore** | **GCP Cloud Run** (serverless) only | `FIREBASE_CONFIG` / `FIREBASE_*` env vars or gitignored `firebase-applet-config.json` |

- **Self-hosting?** Use **Docker + SQLite** — no Firebase account needed. See [DEPLOYMENT.md](./DEPLOYMENT.md).
- **Cloud Run?** Use **Firestore** — SQLite inside the container is ephemeral and links expire after idle sleep.

> **⚠️ Data persistence (read this before deploying)**  
> - **Self-hosted SQLite is safe** when `secrets.db` lives on **persistent storage** (e.g. Docker volume `./data`, VPS disk). Links remain valid until they expire or hit view limits — **not** because the server restarts.  
> - **Links become invalid early** only if the database file is **lost**: no volume mount, ephemeral PaaS disk, Cloud Run without Firestore, or deleting `data/secrets.db`.  
> - The web UI shows a warning banner if it detects SQLite on a public host (typical misconfiguration on serverless).

### 🏛️ Architecture

The application is designed with a security-first, zero-knowledge architecture. Self-hosted and GCP deployments share the same server code; only the storage backend differs.

```mermaid
graph TD
    subgraph "User's Browser (Client-Side)"
        A[1. User Enters Secret] --> B{Web Crypto API};
        B -- "Generates" --> C(Decryption Key);
        B -- "Encrypts Secret" --> D(Encrypted Data Blob);
    end

    subgraph "SecureShare Server (Node.js + Express)"
        E[Express Server] --> P[Database Provider];
        P -->|"self-host (default)"| F[(SQLite file)];
        P -->|"GCP Cloud Run"| G[(Cloud Firestore)];
    end

    D -->|2. Send Blob to Server| E;
    E -->|3. Store Blob & Return ID| P;
    F -->|4. Returns Secret ID| E;
    G -->|4. Returns Secret ID| E;
    E -->|5. Send ID to Browser| A;

    subgraph "Link Generation"
        C -- "Combined in Browser" --> I(Generated Secure Link);
        A -- "Combined in Browser" --> I;
        I -- "Example: /s/uuid#key" --> J{Share with Recipient};
    end

    J --> K[Recipient Opens Link];

    subgraph "Recipient's Browser (Client-Side)"
        K -- "6. Fetches Blob by ID" --> E;
        E --> P;
        P --> F;
        P --> G;
        F --> E;
        G --> E;
        E --> L(Encrypted Data Blob);
        K -- "7. Key is in URL Fragment (#)" --> M{Web Crypto API};
        L --> M;
        M -->|8. Decrypts Locally| N[Secret Revealed];
    end

    style P fill:#e8f4fc,stroke:#333,stroke-width:2px
    style F fill:#f9f,stroke:#333,stroke-width:2px
    style G fill:#fef3e8,stroke:#333,stroke-width:2px
```

## 🚀 Deployment
For detailed instructions on deploying to GCP, Azure, VPS, or using Docker with HTTPS, see the [Deployment Guide](./DEPLOYMENT.md).

**IMPORTANT**: Before deploying, read the [Security Limitations](./LIMITATIONS.md) and [Threat Model](./THREAT_MODEL.md) to understand what this app protects against and what it does not.

### Quick Docker Start (Local)

The recommended way to run SecureShare on **any system** is using **Docker Compose**:

```bash
# Start the application (Universal for Linux, macOS, and Windows)
docker compose up -d
```

> **Tip (self-hosted):** Docker + SQLite creates a `data/` folder with `secrets.db`. **No Firebase configuration is required.**

For **GCP Cloud Run**, use Firestore instead — see [DEPLOYMENT.md](./DEPLOYMENT.md).

#### Manual Docker Commands

If you prefer to use standard Docker commands, first build the image:

```bash
docker build -t secureshare .
```

Then run the container using the command for your specific system:

| System / Shell | Command |
| :--- | :--- |
| **Linux / macOS / Git Bash** | `docker run -d -p 3000:3000 -v $(pwd)/data:/app/data secureshare` |
| **Windows (PowerShell)** | `docker run -d -p 3000:3000 -v "${PWD}/data:/app/data" secureshare` |
| **Windows (Command Prompt)** | `docker run -d -p 3000:3000 -v "%cd%/data:/app/data" secureshare` |

## 🧪 Development & Testing
```bash
# Install dependencies
npm install

# Start development server (Express + Vite)
npm run dev

# Run unit and integration tests
npm test

# Lint the codebase
npm run lint
```

## 💡 Choosing Your Interface: GUI or CLI?

SecureShare offers two ways to interact with the system, each designed for different needs.

| Interface | Best For... | Use Case Example |
| :--- | :--- | :--- |
| **🌐 GUI (Web App)** | **Manual, one-off sharing.** Ideal for all users, including non-technical ones. | Quickly sending a password to a colleague. |
| **💻 CLI (Command Line)** | **Developers & Admins.** Perfect for scripting and terminal-based workflows. | A bash script that generates a temporary key and shares it. |

---

## 🛡️ Security Features Overview
-   **AES-256-GCM Encryption**: Authenticated encryption using the native Web Crypto API.
-   **Cryptographic Proof of Work (PoW)**: Hashcash-style Anti-DoS protection with replay prevention and strict TTL.
-   **Atomic Storage Operations**: Prevents race conditions (SQLite transactions or Firestore transactions).
-   **Zero-Knowledge Architecture**: The server never sees the decryption key or plaintext data.

## 🛡️ Security by Design

SecureShare is built with a "Security by Design" philosophy, ensuring that security is not an afterthought but a core component of the architecture.

- **Zero-Knowledge**: Client-side encryption ensures the server never sees your plaintext data.

## 💻 CLI Tool
A command-line interface (CLI) is provided for easy terminal-based sharing.

- **[CLI Guide](./cli/README.md)**: Installation and usage instructions for the CLI.

## 🛠️ Technology Stack
- **Frontend**: React 19, Tailwind CSS 4, Motion.
- **Backend**: Node.js (Express) with `helmet` and `express-rate-limit`.
- **Database**: **SQLite** by default (self-hosted). **Firestore** optional for GCP Cloud Run only.
- **Encryption**: Web Crypto API (AES-256-GCM, SHA-256) and hash-wasm (Argon2id).

## 📋 Compliance & Standards
- **RFC 9116**: `security.txt` is implemented at `/.well-known/security.txt` and `/security.txt`.
- **Security Policy**: Publicly accessible at `/security-policy`. See [SECURITY.md](./SECURITY.md).
- **Opaque Errors**: Prevents enumeration attacks.

## ⚙️ Technical Limits
- **Secret Size**: Maximum 1MB of encrypted data per secret.
- **View Limit**: Maximum 10 views per secret.
- **Expiration**: Maximum 7 days (168 hours).

## 🤝 Contributing
Please see [CONTRIBUTING.md](./CONTRIBUTING.md) and our [Code of Conduct](./CODE_OF_CONDUCT.md) for details on how to contribute to this project.

## 📝 Release Notes
For a detailed list of changes, see the [Release Notes](./RELEASE_NOTES.md).
