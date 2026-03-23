import { argon2id } from 'hash-wasm';

/**
 * Modern Cryptography Module using Web Crypto API (AES-GCM)
 * 
 * SECURITY ARCHITECTURE & ZERO-KNOWLEDGE IMPLEMENTATION:
 * 
 * This module is the core of SecureShare's Zero-Knowledge architecture. It ensures that 
 * all sensitive data is encrypted *before* it ever leaves the user's device. The server
 * only receives opaque, authenticated ciphertexts.
 * 
 * Cryptographic Primitives Used (2025 Standards):
 * - Algorithm: AES-256-GCM (Galois/Counter Mode).
 * - Key Derivation Function (KDF): Argon2id (OWASP 2025 recommended).
 *   - Memory: 19 MiB
 *   - Iterations: 2
 *   - Parallelism: 1
 * 
 * NOTE: Legacy PBKDF2 support has been removed. Only Argon2id is supported.
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

const AES_GCM_IV_LENGTH = 12; 

// KDF Configurations
export interface KDFConfig {
  algorithm: 'argon2id';
  iterations: number;
  memorySize: number; // in KiB
  parallelism: number;
}

// Default config for new secrets (OWASP 2025 Argon2id)
export const DEFAULT_KDF_CONFIG: KDFConfig = {
  algorithm: 'argon2id',
  iterations: 2,
  memorySize: 19456, // 19 MiB
  parallelism: 1
};

/**
 * Generates a cryptographically secure random salt/IV.
 */
function generateRandomBytes(length: number): Uint8Array {
  const array = new Uint8Array(length);
  window.crypto.getRandomValues(array);
  return array;
}

/**
 * Derives an AES-GCM key from a raw key material (or password) using Argon2id.
 */
async function deriveKey(keyMaterial: string, salt: Uint8Array, config?: KDFConfig): Promise<CryptoKey> {
  const kdf = config || DEFAULT_KDF_CONFIG;

  const hash = await argon2id({
    password: keyMaterial,
    salt: salt,
    iterations: kdf.iterations,
    memorySize: kdf.memorySize,
    parallelism: kdf.parallelism,
    hashLength: 32,
    outputType: 'binary',
  });
  
  return window.crypto.subtle.importKey(
    "raw",
    hash,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Imports a raw key string (from URL) directly as an AES-GCM key.
 */
async function importRawKey(rawKeyStr: string): Promise<CryptoKey> {
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
 */
export async function encryptSecret(text: string, password?: string): Promise<{ encryptedData: string; key: string; salt?: string; kdfConfig?: string }> {
  const iv = generateRandomBytes(AES_GCM_IV_LENGTH);
  const dataBuffer = stringToArrayBuffer(text);
  
  let key: CryptoKey;
  let keyStr: string;
  let saltStr: string | undefined;
  let kdfConfigStr: string | undefined;

  if (password) {
    const salt = generateRandomBytes(16);
    saltStr = arrayBufferToBase64(salt.buffer);
    
    const randomKeyBytes = generateRandomBytes(32);
    keyStr = arrayBufferToBase64(randomKeyBytes.buffer);
    
    const combinedSecret = keyStr + password;
    key = await deriveKey(combinedSecret, salt, DEFAULT_KDF_CONFIG);
    kdfConfigStr = JSON.stringify(DEFAULT_KDF_CONFIG);
  } else {
    key = await window.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
    const exported = await window.crypto.subtle.exportKey("raw", key);
    keyStr = arrayBufferToBase64(exported);
  }

  const encryptedBuffer = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    dataBuffer
  );

  const ivBase64 = arrayBufferToBase64(iv.buffer);
  const ciphertextBase64 = arrayBufferToBase64(encryptedBuffer);
  const packedData = `${ivBase64}:${ciphertextBase64}`;

  return {
    encryptedData: packedData,
    key: keyStr,
    salt: saltStr,
    kdfConfig: kdfConfigStr
  };
}

/**
 * Decrypts a string using AES-GCM.
 */
export async function decryptSecret(encryptedDataPacked: string, keyStr: string, password?: string, saltStr?: string, kdfConfigStr?: string): Promise<string> {
  try {
    const parts = encryptedDataPacked.split(':');
    if (parts.length !== 2) throw new Error("Invalid data format");
    
    const iv = base64ToArrayBuffer(parts[0]);
    const ciphertext = base64ToArrayBuffer(parts[1]);

    let key: CryptoKey;

    if (password && saltStr) {
      const salt = base64ToArrayBuffer(saltStr);
      const combinedSecret = keyStr + password;
      const kdfConfig = kdfConfigStr ? JSON.parse(kdfConfigStr) : DEFAULT_KDF_CONFIG;
      key = await deriveKey(combinedSecret, new Uint8Array(salt), kdfConfig);
    } else {
      key = await importRawKey(keyStr);
    }

    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(iv) },
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
 * Hashes a password for server-side verification using Argon2id.
 */
export async function hashPassword(password: string, saltStr: string, kdfConfigStr?: string): Promise<string> {
  const salt = base64ToArrayBuffer(saltStr);
  const kdf = kdfConfigStr ? JSON.parse(kdfConfigStr) : DEFAULT_KDF_CONFIG;

  const hash = await argon2id({
    password: password,
    salt: new Uint8Array(salt),
    iterations: kdf.iterations,
    memorySize: kdf.memorySize,
    parallelism: kdf.parallelism,
    hashLength: 32,
    outputType: 'binary',
  });
  return arrayBufferToBase64(hash.buffer);
}
