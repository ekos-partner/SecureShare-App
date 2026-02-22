/**
 * Modern Cryptography Module using Web Crypto API (AES-GCM)
 * 
 * SECURITY ARCHITECTURE:
 * - Algorithm: AES-GCM (Galois/Counter Mode) - provides Authenticated Encryption (confidentiality + integrity).
 * - Key Length: 256 bits.
 * - IV (Nonce): 12 bytes (96 bits), unique per encryption.
 * - KDF: PBKDF2-SHA-256 with 100,000 iterations for password-derived keys.
 * 
 * This replaces the legacy crypto-js implementation.
 */

// Helper to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

// Helper to convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary_string = window.atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}

// Helper to convert string to ArrayBuffer
function stringToArrayBuffer(str: string): ArrayBuffer {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}

// Helper to convert ArrayBuffer to string
function arrayBufferToString(buffer: ArrayBuffer): string {
  const decoder = new TextDecoder();
  return decoder.decode(buffer);
}

const AES_GCM_IV_LENGTH = 12; // 96 bits is recommended for AES-GCM
const PBKDF2_ITERATIONS = 100000;
const AES_KEY_LENGTH = 256;

/**
 * Generates a cryptographically secure random salt/IV.
 */
function generateRandomBytes(length: number): Uint8Array {
  const array = new Uint8Array(length);
  window.crypto.getRandomValues(array);
  return array;
}

/**
 * Derives an AES-GCM key from a raw key material (or password) using PBKDF2.
 */
async function deriveKey(keyMaterial: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterialBuffer = enc.encode(keyMaterial);

  const importedKey = await window.crypto.subtle.importKey(
    "raw",
    keyMaterialBuffer,
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    importedKey,
    { name: "AES-GCM", length: AES_KEY_LENGTH },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Imports a raw key string (from URL) directly as an AES-GCM key.
 * Used when no password is set.
 */
async function importRawKey(rawKeyStr: string): Promise<CryptoKey> {
  // The key in URL is base64 encoded 32 bytes
  const keyBuffer = base64ToArrayBuffer(rawKeyStr);
  return window.crypto.subtle.importKey(
    "raw",
    keyBuffer,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypts a string using AES-GCM.
 * Returns:
 * - encryptedData: Base64 string containing "IV:Ciphertext"
 * - key: Base64 string of the raw key (to be put in URL)
 * - salt: Base64 string (if password used)
 */
export async function encryptSecret(text: string, password?: string): Promise<{ encryptedData: string; key: string; salt?: string }> {
  const iv = generateRandomBytes(AES_GCM_IV_LENGTH);
  const dataBuffer = stringToArrayBuffer(text);
  
  let key: CryptoKey;
  let keyStr: string;
  let salt: Uint8Array | undefined;
  let saltStr: string | undefined;

  if (password) {
    // Password-based encryption
    salt = generateRandomBytes(16);
    saltStr = arrayBufferToBase64(salt.buffer);
    // We generate a random "base key" for the URL, and mix it with password
    // Actually, to keep it simple and consistent with previous logic:
    // If password exists, we derive the key from (RandomKey + Password).
    // The URL fragment holds the RandomKey.
    
    const randomKeyBytes = generateRandomBytes(32);
    keyStr = arrayBufferToBase64(randomKeyBytes.buffer);
    
    // Combine RandomKey + Password for derivation
    const combinedSecret = keyStr + password;
    key = await deriveKey(combinedSecret, salt);
  } else {
    // Key-based encryption (no password)
    // Generate a random 256-bit key
    key = await window.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
    const exported = await window.crypto.subtle.exportKey("raw", key);
    keyStr = arrayBufferToBase64(exported);
  }

  const encryptedBuffer = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    key,
    dataBuffer
  );

  // Pack IV and Ciphertext together: "IV_BASE64:CIPHERTEXT_BASE64"
  const ivBase64 = arrayBufferToBase64(iv.buffer);
  const ciphertextBase64 = arrayBufferToBase64(encryptedBuffer);
  const packedData = `${ivBase64}:${ciphertextBase64}`;

  return {
    encryptedData: packedData,
    key: keyStr,
    salt: saltStr
  };
}

/**
 * Decrypts a string using AES-GCM.
 */
export async function decryptSecret(encryptedDataPacked: string, keyStr: string, password?: string, saltStr?: string): Promise<string> {
  try {
    // Unpack IV and Ciphertext
    const parts = encryptedDataPacked.split(':');
    if (parts.length !== 2) throw new Error("Invalid data format");
    
    const iv = base64ToArrayBuffer(parts[0]);
    const ciphertext = base64ToArrayBuffer(parts[1]);

    let key: CryptoKey;

    if (password && saltStr) {
      const salt = base64ToArrayBuffer(saltStr);
      const combinedSecret = keyStr + password;
      key = await deriveKey(combinedSecret, new Uint8Array(salt));
    } else {
      key = await importRawKey(keyStr);
    }

    const decryptedBuffer = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: new Uint8Array(iv)
      },
      key,
      ciphertext
    );

    return arrayBufferToString(decryptedBuffer);
  } catch (e) {
    console.error("Decryption failed:", e);
    throw new Error("Decryption failed. Invalid key, password, or data integrity check failed.");
  }
}

/**
 * Hashes a password for server-side verification (SHA-256).
 */
export async function hashPassword(password: string, saltStr: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + saltStr);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
  return arrayBufferToBase64(hashBuffer);
}
