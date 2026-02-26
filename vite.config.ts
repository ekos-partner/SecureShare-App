/// <reference types="vitest" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import typography from '@tailwindcss/typography';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss({ plugins: [typography] })],
  test: {
    globals: true,
    environment: 'happy-dom',
    setupFiles: ['./src/setupTests.ts'],
  },
});
