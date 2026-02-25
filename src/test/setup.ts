import { beforeAll } from 'vitest';
import { webcrypto } from 'node:crypto';

beforeAll(() => {
  // Polyfill for Web Crypto API in Node.js environment
  if (!globalThis.crypto) {
    Object.defineProperty(globalThis, 'crypto', {
      value: webcrypto,
      writable: true,
      configurable: true,
    });
  }

  // Polyfill for TextEncoder
  if (!globalThis.TextEncoder) {
    globalThis.TextEncoder = TextEncoder;
  }

  // Polyfill for TextDecoder
  // FIX: Cast to the correct type instead of 'any' to satisfy ESLint
  if (!globalThis.TextDecoder) {
    globalThis.TextDecoder = TextDecoder as typeof globalThis.TextDecoder;
  }
});