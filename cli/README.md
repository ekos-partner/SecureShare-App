# SecureShare CLI

A command-line interface for SecureShare, written in Go. This tool allows you to encrypt and share secrets directly from your terminal, without using a browser.

## Features

- **Client-Side Encryption**: Uses AES-256-GCM locally. The server never sees the raw secret or the key.
- **Strong Key Derivation**: Uses Argon2id for password hashing, matching the web app's security standards.
- **Cross-Platform**: Compiles to a single binary for Windows, macOS, and Linux.
- **Pipe Support**: Can read secrets from stdin (e.g., `cat file.txt | secureshare-cli`).
- **Secure Defaults**: Generates strong random keys and IVs.

## Installation

### Prerequisites

- [Go](https://go.dev/dl/) 1.21 or later.

### Quick Start by OS

Download the appropriate binary for your system and follow these steps:

#### 🍎 macOS (Apple Silicon / M1 / M2 / M3)
1.  **Grant permissions**: `chmod +x secureshare-cli-mac-arm64`
2.  **Bypass Gatekeeper**: `xattr -d com.apple.quarantine secureshare-cli-mac-arm64`
3.  **Run**: `./secureshare-cli-mac-arm64`

#### 🍎 macOS (Intel)
1.  **Grant permissions**: `chmod +x secureshare-cli-mac-intel`
2.  **Bypass Gatekeeper**: `xattr -d com.apple.quarantine secureshare-cli-mac-intel`
3.  **Run**: `./secureshare-cli-mac-intel`

#### 🐧 Linux
1.  **Grant permissions**: `chmod +x secureshare-cli-linux`
2.  **Run**: `./secureshare-cli-linux`

#### 🪟 Windows
1.  **Run**: `.\secureshare-cli.exe`

---

### Building from Source

1.  Navigate to the `cli` directory:
    ```bash
    cd cli
    ```

2.  Initialize dependencies and build:
    ```bash
    go mod tidy
    go build .
    ```
    This will create a binary named `secureshare-cli` (or `secureshare-cli.exe` on Windows).

### Cross-Compilation

You can build binaries for other platforms from your current machine.

**For Windows (64-bit):**
```bash
GOOS=windows GOARCH=amd64 go build -o secureshare-cli.exe .
```

**For Linux (64-bit):**
```bash
GOOS=linux GOARCH=amd64 go build -o secureshare-cli-linux .
```

**For macOS (Apple Silicon):**
```bash
GOOS=darwin GOARCH=arm64 go build -o secureshare-cli-mac-arm64 .
```

**For macOS (Intel):**
```bash
GOOS=darwin GOARCH=amd64 go build -o secureshare-cli-mac-intel .
```

### Troubleshooting Build Errors

If you encounter an error like `open secureshare-cli: no such file or directory`, try cleaning the directory first:

```bash
rm -f secureshare-cli secureshare-cli.exe secureshare-cli-linux secureshare-cli-mac-arm64 secureshare-cli-mac-intel
go build .
```

If that fails, try specifying a different output name:
```bash
go build -o app .
```

**For Linux (64-bit):**
```bash
GOOS=linux GOARCH=amd64 go build -o secureshare-cli-linux .
```

**For macOS (Apple Silicon):**
```bash
GOOS=darwin GOARCH=arm64 go build -o secureshare-cli-mac .
```

## Usage

### 1. Configuring the Default Server URL (Recommended)

By default, the CLI attempts to connect to a local server (`http://localhost:3000`). To avoid typing your server's address every time, set the `SECURESHARE_URL` environment variable to your instance's URL (e.g., `https://secureshare.example.com`).

**🪟 Windows (PowerShell):**
```powershell
$env:SECURESHARE_URL="https://secureshare.example.com"
```
*(To set this permanently, add `SECURESHARE_URL` to your system Environment Variables).*

**🍎 macOS / 🐧 Linux:**
```bash
export SECURESHARE_URL="https://secureshare.example.com"
```
*(To set this permanently, add the line above to your `~/.bashrc` or `~/.zshrc` file).*

---

### 2. Creating a Secret (Generating a Secure Link)

You can pass your secret directly as an argument in quotes, or use pipes (`|`), which is ideal for encrypting and sending the contents of entire files.

*Note: The examples below assume you have set the `SECURESHARE_URL` environment variable. If not, you must add the `-url https://secureshare.example.com` flag to each command.*

**🪟 Windows:**
```powershell
# Direct argument:
.\secureshare-cli.exe "My secret password is: SuperSecret123!"

# Using pipes (e.g., sending file contents):
Get-Content secret_file.txt | .\secureshare-cli.exe
```

**🍎 macOS / 🐧 Linux:**
```bash
# Direct argument:
./secureshare-cli "My secret password is: SuperSecret123!"

# Using pipes (e.g., sending file contents):
cat secret_file.txt | ./secureshare-cli
```

**Expected Output:**
The program will generate and return a ready-to-use, secure link:
`https://secureshare.example.com/s/12345678-abcd-efgh-ijkl-1234567890ab#Base64EncryptionKeyHere`

---

### 3. Retrieving and Decrypting a Secret

To read and decrypt a secret directly in your terminal without opening a browser, use the `get` command and paste the full link. **Always wrap the link in quotes** so your terminal correctly interprets the `#` character.

**🪟 Windows:**
```powershell
.\secureshare-cli.exe get "https://secureshare.example.com/s/12345678-abcd-efgh-ijkl-1234567890ab#Base64EncryptionKeyHere"
```

**🍎 macOS / 🐧 Linux:**
```bash
./secureshare-cli get "https://secureshare.example.com/s/12345678-abcd-efgh-ijkl-1234567890ab#Base64EncryptionKeyHere"
```

---

### 4. Advanced Options

When creating a secret, you can use additional flags to precisely control its parameters:

- `-password "YourPassword"` – Sets an additional password required for decryption (protects against link interception).
- `-views 5` – Sets the maximum number of views (default: 1).
- `-expire 24` – Sets the expiration time in hours (default: 24).
- `-url "..."` – Manually specify the server URL if the environment variable is not set.

**Example using flags (macOS/Linux):**
```bash
./secureshare-cli -expire 2 -views 1 -password "RequiredPassword123" "Very secret data"
```

**Example with manual URL (Windows):**
```powershell
.\secureshare-cli.exe -url "https://secureshare.example.com" -password "MyPassword" "Secret text"
```

## Security Note

The CLI generates the encryption key locally and includes it in the URL fragment (after `#`). This fragment is **never sent to the server**. The server only receives the encrypted blob (IV + Ciphertext).
