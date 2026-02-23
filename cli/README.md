# SecureShare CLI

A command-line interface for SecureShare, written in Go. This tool allows you to encrypt and share secrets directly from your terminal, without using a browser.

## Features

- **Client-Side Encryption**: Uses AES-256-GCM locally. The server never sees the raw secret or the key.
- **Cross-Platform**: Compiles to a single binary for Windows, macOS, and Linux.
- **Pipe Support**: Can read secrets from stdin (e.g., `cat file.txt | secureshare-cli`).
- **Secure Defaults**: Generates strong random keys and IVs.

## Installation

### Prerequisites

- [Go](https://go.dev/dl/) 1.21 or later.

### Building from Source

1.  Navigate to the `cli` directory:
    ```bash
    cd cli
    ```

2.  Initialize dependencies:
    ```bash
    go mod tidy
    ```

3.  Build the binary:
    ```bash
    go build -o secureshare-cli main.go
    ```

### Cross-Compilation

You can build binaries for other platforms from your current machine (e.g., macOS).

**For Windows (64-bit):**
```bash
GOOS=windows GOARCH=amd64 go build -o secureshare-cli.exe main.go
```

**For Linux (64-bit):**
```bash
GOOS=linux GOARCH=amd64 go build -o secureshare-cli-linux main.go
```

**For macOS (Apple Silicon):**
```bash
GOOS=darwin GOARCH=arm64 go build -o secureshare-cli-mac main.go
```

## Usage

### Basic Usage

Encrypt a string and get a shareable link:

```bash
./secureshare-cli "My secret message"
```

Output:
```
https://your-instance.com/secret/uuid-here#base64-key
```

### Using Pipes

Encrypt the contents of a file:

```bash
cat id_rsa | ./secureshare-cli
```

### Options

-   `-url`: URL of the SecureShare instance (default: `http://localhost:3000`).
-   `-expire`: Expiration time in hours (default: 24).
-   `-views`: View limit (default: 1).
-   `-password`: Optional password for extra protection.

Example:
```bash
./secureshare-cli -url https://secureshare.example.com -expire 1 -views 1 -password "correct-horse-battery-staple" "Top Secret"
```

## Security Note

The CLI generates the encryption key locally and includes it in the URL fragment (after `#`). This fragment is **never sent to the server**. The server only receives the encrypted blob (IV + Ciphertext).
