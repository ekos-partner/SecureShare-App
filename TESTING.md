# 🧪 Testing Guide for SecureShare

This document outlines the testing strategy, tools, and commands used to ensure the security and stability of the SecureShare application.

Since SecureShare is a privacy-first application dealing with encryption, testing is critical to prevent data leaks and ensure cryptographic correctness.

## 🛠️ Tech Stack

We use modern testing tools compatible with our Vite + TypeScript ecosystem:

* **[Vitest](https://vitest.dev/):** Main test runner (faster replacement for Jest).
* **[JSDOM](https://github.com/jsdom/jsdom):** Simulates a browser environment to test the Web Crypto API logic.
* **[Supertest](https://github.com/ladjs/supertest):** For HTTP assertions on backend API endpoints (Phase 2).

## 🚀 Quick Start

### 1. Install Dependencies
Ensure you have all development dependencies installed:

```bash
npm install
2. Run All Tests

To execute the full test suite once:

Bash
npm test
# OR directly:
npx vitest run
3. Watch Mode (Development)

To run tests automatically whenever you change a file (TDD style):

Bash
npx vitest
4. Check Coverage (Optional)

To see how much of the code is covered by tests:

Bash
npx vitest run --coverage
📂 Test Structure
We follow a co-location strategy for unit tests (tests sit next to the code they test).

Path	Description
src/lib/*.test.ts	Unit Tests (Cryptography). These test the crypto.ts logic directly. They verify encryption, decryption, PBKDF2 hashing, and salt generation.
src/test/setup.ts	Test Environment Setup. Polyfills for window.crypto, TextEncoder, and other browser-specific APIs required by Node.js during testing.
vitest.config.ts	Configuration. Tells Vitest to use the jsdom environment.
🔐 What We Test
1. Cryptography Module (crypto.ts)

Since we rely on Zero-Knowledge Architecture, the client-side encryption is the most critical part. We verify:

Encryption: Ensures data is actually transformed and IVs (Initialization Vectors) are unique per operation.

Decryption: Verifies that encrypted data can be restored using the correct key.

Key Derivation: Checks that PBKDF2 generates deterministic keys from passwords and salts.

Negative Testing: We deliberately try to decrypt with wrong keys/passwords to ensure the system throws correct errors.

Note: We do not roll our own crypto algorithms. We test the implementation and usage of the standard Web Crypto API.

🤝 How to Add New Tests
Create a file ending in .test.ts next to the component or function you want to test.

Import describe, it, and expect from vitest.

If you need browser APIs (like window or crypto), the environment is already set up to support them.

Example:

TypeScript
import { describe, it, expect } from 'vitest';
import { myFunction } from './myFunction';

describe('myFunction', () => {
  it('should return true', () => {
    expect(myFunction()).toBe(true);
  });
});
🐛 Troubleshooting
ReferenceError: crypto is not defined
This happens if the test environment is not correctly mocking the Web Crypto API. Ensure vitest.config.ts includes setupFiles: ['./src/test/setup.ts'].

TextEncoder is not defined
Our setup file includes a polyfill for TextEncoder. If you see this, check if src/test/setup.ts is loading correctly.
