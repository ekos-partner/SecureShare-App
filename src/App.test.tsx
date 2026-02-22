import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import App from './App';

import { webcrypto } from 'node:crypto';

// Mock crypto API for testing
Object.defineProperty(global, 'crypto', {
  value: {
    getRandomValues: (arr: Uint8Array) => webcrypto.getRandomValues(arr),
    subtle: {
      generateKey: vi.fn(),
      exportKey: vi.fn(),
      importKey: vi.fn(),
      encrypt: vi.fn(),
      decrypt: vi.fn(),
      digest: vi.fn(),
    },
  },
});

describe('SecureShare App', () => {
  it('renders the main heading', () => {
    render(<App />);
    expect(screen.getByText('SecureShare')).toBeInTheDocument();
  });

  it('shows the create secret form by default', () => {
    render(<App />);
    expect(screen.getByPlaceholderText(/Paste your password, API token, or message here/i)).toBeInTheDocument();
    expect(screen.getByText('Generate Secure Link')).toBeInTheDocument();
  });

  it('allows entering a secret', () => {
    render(<App />);
    const textarea = screen.getByPlaceholderText(/Paste your password, API token, or message here/i);
    fireEvent.change(textarea, { target: { value: 'My secret message' } });
    expect(textarea).toHaveValue('My secret message');
  });

  it('shows password strength indicator when password is typed', () => {
    render(<App />);
    const passwordInput = screen.getByPlaceholderText(/Set a password for the recipient/i);
    fireEvent.change(passwordInput, { target: { value: 'password' } });
    expect(screen.getByText(/Strength: Weak/i)).toBeInTheDocument();
    
    fireEvent.change(passwordInput, { target: { value: 'StrongP@ssw0rd123!' } });
    expect(screen.getByText(/Strength: Strong/i)).toBeInTheDocument();
  });
});
