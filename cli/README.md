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

### Troubleshooting Build Errors

If you encounter an error like `open secureshare-cli: no such file or directory`, try cleaning the directory first:

```bash
rm -f secureshare-cli secureshare-cli.exe
go build .
```

If that fails, try specifying a different output name:
```bash
go build -o app .
```

**For macOS (Apple Silicon):**
```bash
GOOS=darwin GOARCH=arm64 go build -o secureshare-cli-mac .
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
