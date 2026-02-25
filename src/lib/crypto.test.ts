import { describe, it, expect } from 'vitest';
import { encryptSecret, decryptSecret, hashPassword } from './crypto';

describe('Cryptography Module (crypto.ts)', () => {

  // --- SCENARIO 1: Passwordless Encryption (Key in URL) ---
  describe('Passwordless Mode (Standard)', () => {
    it('should encrypt and decrypt correctly', async () => {
      const secretMessage = "This is a top secret message 123 🚀";
      
      // 1. Encrypt
      const result = await encryptSecret(secretMessage);
      
      // Verify structure
      expect(result).toHaveProperty('encryptedData');
      expect(result).toHaveProperty('key');
      expect(result.salt).toBeUndefined(); // No salt expected in passwordless mode
      expect(result.encryptedData).toContain('.'); // Format verification: IV.CIPHERTEXT

      // 2. Decrypt
      const decrypted = await decryptSecret(result.encryptedData, result.key);
      
      expect(decrypted).toBe(secretMessage);
    });

    it('should fail to decrypt with an invalid key', async () => {
      const { encryptedData } = await encryptSecret("Secret Data");
      
      // Generate a random, mismatched AES key
      const fakeKey = await crypto.subtle.exportKey(
        "raw",
        await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])
      ).then(buf => {
          // Convert to base64 as expected by the decrypt function
          let binary = '';
          const bytes = new Uint8Array(buf);
          for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
          return btoa(binary);
      });

      // Expect decryption to fail
      await expect(decryptSecret(encryptedData, fakeKey))
        .rejects.toThrow(/Decryption failed/);
    });
  });

  // --- SCENARIO 2: Password-Protected Encryption (PBKDF2) ---
  describe('Password-Protected Mode (PBKDF2)', () => {
    it('should encrypt and decrypt with the correct password', async () => {
      const secretMessage = "Protected by password";
      const password = "StrongPassword123!";

      // 1. Encrypt
      const result = await encryptSecret(secretMessage, password);

      expect(result).toHaveProperty('salt'); // Salt is required for PBKDF2
      expect(result.key).toBeDefined(); 

      // 2. Decrypt
      const decrypted = await decryptSecret(
        result.encryptedData, 
        result.key, 
        password, 
        result.salt
      );

      expect(decrypted).toBe(secretMessage);
    });

    it('should fail to decrypt with a wrong password', async () => {
      const secretMessage = "Test Data";
      const password = "CorrectPassword";
      const result = await encryptSecret(secretMessage, password);

      await expect(decryptSecret(
        result.encryptedData, 
        result.key, 
        "WrongPassword", // Intentional error
        result.salt
      )).rejects.toThrow();
    });
  });

  // --- SCENARIO 3: Password Hashing ---
  describe('hashPassword()', () => {
    it('should generate deterministic hashes for the same input', async () => {
      const password = "admin";
      const salt = "c29s"; // base64 for "sol"

      const hash1 = await hashPassword(password, salt);
      const hash2 = await hashPassword(password, salt);

      expect(hash1).toBe(hash2);
      expect(typeof hash1).toBe('string');
      expect(hash1.length).toBeGreaterThan(10);
    });
  });

});