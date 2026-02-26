# API Reference - SecureShare

The SecureShare API enables automated, secure sharing of sensitive data. It follows a **Zero-Knowledge** principle: the server never receives the decryption key.

## 🔐 Authentication

All API requests must include an API key in the `X-API-Key` header.

```http
X-API-Key: your_key_id.your_secret_key
```

*API keys are managed in the [Admin Dashboard](./ADMIN_GUIDE.md).*

---

## 🚀 Endpoints

### 1. Create a Secret
`POST /api/secrets`

Creates a new encrypted secret.

**Request Body (JSON):**
| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `encryptedData` | `string` | Yes | Format: `base64_iv:base64_ciphertext` |
| `expirationHours` | `number` | No | Hours until deletion (Default: 24, Max: 168) |
| `viewLimit` | `number` | No | Max views before deletion (Default: 1, Max: 10) |
| `passwordHash` | `string` | No | SHA-256 hash of the access password (if used) |
| `salt` | `string` | No | Base64 salt used for password derivation |

**Response (201 Created):**
```json
{
  "id": "uuid-v4-string",
  "expiresAt": "2026-02-26T12:00:00.000Z"
}
```

### 2. Get Secret Metadata
`GET /api/secrets/:id/meta`

Check if a secret exists and get its configuration without consuming a "view".

**Response (200 OK):**
```json
{
  "id": "uuid-v4-string",
  "hasPassword": true,
  "salt": "base64_salt_string",
  "expiresAt": "2026-02-26T12:00:00.000Z",
  "remainingViews": 1
}
```

---

## 🛠️ Integration Examples

### Python (End-to-End Encrypted)
This script encrypts data locally using AES-256-GCM before sending it to the server.

```python
import requests
import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def share_secret(api_url, api_key, plaintext):
    # 1. Generate local key (NEVER sent to server)
    key = AESGCM.generate_key(bit_length=256)
    key_b64 = base64.urlsafe_b64encode(key).decode('utf-8')
    
    # 2. Encrypt locally
    aesgcm = AESGCM(key)
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, plaintext.encode(), None)
    
    # 3. Format payload
    encrypted_payload = f"{base64.b64encode(iv).decode()}:{base64.b64encode(ciphertext).decode()}"
    
    # 4. API Call
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    payload = {"encryptedData": encrypted_payload, "expirationHours": 1}
    
    response = requests.post(f"{api_url}/api/secrets", json=payload, headers=headers)
    data = response.json()
    
    # 5. Build the E2EE Link
    return f"{api_url}/s/{data['id']}#{key_b64}"

# Usage
link = share_secret("https://secureshare.example.com", "my_api_key", "Top Secret Data")
print(f"Secure Link: {link}")
```

### Node.js / TypeScript
```typescript
import crypto from 'crypto';

async function createSecret(apiUrl: string, apiKey: string, text: string) {
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  
  const ciphertext = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  
  const encryptedData = `${iv.toString('base64')}:${Buffer.concat([ciphertext, authTag]).toString('base64')}`;
  
  const res = await fetch(`${apiUrl}/api/secrets`, {
    method: 'POST',
    headers: { 'X-API-Key': apiKey, 'Content-Type': 'application/json' },
    body: JSON.stringify({ encryptedData })
  });
  
  const { id } = await res.json();
  return `${apiUrl}/s/${id}#${key.toString('base64url')}`;
}
```

---

## 💡 Use Cases & Scenarios

The SecureShare API is ideal for any workflow that requires the secure, automated transfer of ephemeral secrets.

- **CI/CD Pipelines**: Inject production credentials (database passwords, API tokens) into a build step. The link can be consumed by the deployment script and immediately invalidated.
- **Onboarding New Employees**: Securely send initial login credentials or VPN keys. The link ensures the secret is only seen once.
- **Customer Support**: Share a temporary password reset link or a one-time access token with a customer.
- **Inter-Service Communication**: A service can generate a short-lived token, create a secure link, and pass it to another service for a single, authenticated operation.

---

## ⚠️ Security Warning
The server is designed to be "dumb". It stores whatever you send it. If you send plaintext data to the API, you are bypassing the Zero-Knowledge protection. **Always encrypt client-side.**
