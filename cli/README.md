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

### Creating a Secret

There are two ways to create a secret using the CLI:

#### 1. Direct Argument
Pass the secret content as a command-line argument:

```bash
# Linux/macOS
./secureshare-cli -url https://secureshare.example.com "My secret message"

# Windows
.\secureshare-cli.exe -url https://secureshare.example.com "My secret message"
```

#### 2. Using Pipes (stdin)
Pipe the content from another command (ideal for files or multi-line text):

```bash
# Linux/macOS
echo "Top Secret" | ./secureshare-cli -url https://secureshare.example.com

# Windows
echo "Top Secret" | .\secureshare-cli.exe -url https://secureshare.example.com
```

Output:
```
https://secureshare.example.com/s/uuid-here#base64-key
```

### Retrieving a Secret

You can retrieve and decrypt a secret directly in your terminal:

```bash
# Linux/macOS
./secureshare-cli get https://secureshare.example.com/s/uuid-here#base64-key

# Windows
.\secureshare-cli.exe get https://secureshare.example.com/s/uuid-here#base64-key
```

If the secret is password-protected, the CLI will prompt you for it, or you can provide it via a flag:

```bash
./secureshare-cli get https://secureshare.example.com/s/uuid-here#base64-key -password "my-password"
```

### Help and Options

For a full list of options for each command, use the `--help` flag:

```bash
./secureshare-cli create --help
./secureshare-cli get --help
```

### Environment Variables

You can set the default server URL using the `SECURESHARE_URL` environment variable to avoid passing the `-url` flag every time. This is highly recommended for production instances.

**Example:**
```bash
# Linux/macOS
export SECURESHARE_URL=https://secureshare.example.com
./secureshare-cli "My secret message"

# Windows (PowerShell)
$env:SECURESHARE_URL="https://secureshare.example.com"
.\secureshare-cli.exe "My secret message"
```

> **Tip**: Always use the full URL including `https://` for secure production environments.

### Options (for Creation)

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
