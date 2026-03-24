# Contributing to SecureShare

First off, thank you for considering contributing to SecureShare! It's people like you that make SecureShare such a great tool.

## Code of Conduct

This project and everyone participating in it is governed by the [SecureShare Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## License

By contributing to SecureShare, you agree that your contributions will be licensed under its **MIT License**.

## How Can I Contribute?

### Reporting Bugs

This section guides you through submitting a bug report for SecureShare. Following these guidelines helps maintainers and the community understand your report, reproduce the behavior, and find related reports.

*   **Use a clear and descriptive title** for the issue to identify the problem.
*   **Describe the exact steps which reproduce the problem** in as many details as possible.
*   **Provide specific examples to demonstrate the steps**. Include links to files or GitHub projects, or copy/pasteable snippets, which you use in those examples.
*   **Describe the behavior you observed after following the steps** and point out what exactly is the problem with that behavior.
*   **Explain which behavior you expected to see instead and why.**

### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion for SecureShare, including completely new features and minor improvements to existing functionality.

*   **Use a clear and descriptive title** for the issue to identify the suggestion.
*   **Provide a step-by-step description of the suggested enhancement** in as many details as possible.
*   **Provide specific examples to demonstrate the steps**.
*   **Describe the current behavior** and **explain which behavior you expected to see instead** and why.
*   **Explain why this enhancement would be useful** to most SecureShare users.

### Pull Requests

*   Fill in the required template
*   Do not include issue numbers in the PR title
*   Include screenshots and animated GIFs in your pull request whenever possible.
*   Follow the [TypeScript](https://www.typescriptlang.org/docs/handbook/typescript-in-5-minutes.html) styleguide.
*   Document new code based on the [JSDoc](https://jsdoc.app/) style.
*   End all files with a newline.

## Development Setup

1.  Clone the repository.
2.  Run `npm install` to install dependencies.
3.  Run `npm run dev` to start the development server.
4.  Run `npm test` to run tests.
5.  Run `npm run lint` to check for linting errors.

## Architecture & Tech Stack

*   **Frontend**: React 19, Tailwind CSS 4, Motion.
*   **Backend**: Node.js (Express) with `helmet` and `express-rate-limit`.
*   **Database**: SQLite with indexed TTL (Time-To-Live).
*   **Encryption**: Web Crypto API (AES-256-GCM, SHA-256) and hash-wasm (Argon2id).

Please ensure any new features align with our Zero-Knowledge architecture. The server must never see plaintext data or decryption keys.
