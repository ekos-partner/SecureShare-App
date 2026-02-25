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

  // Polyfill for TextEncoder/TextDecoder (sometimes missing in jsdom/node interaction)
  if (!globalThis.TextEncoder) {
    globalThis.TextEncoder = TextEncoder;
  }
  if (!globalThis.TextDecoder) {
    globalThis.TextDecoder = TextDecoder as any;
  }
});