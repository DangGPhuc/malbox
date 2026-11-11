import fs from 'node:fs';
import { resolve } from 'node:path';
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  define: {
    __INDEX_CSS_RAW__: JSON.stringify(
      fs.readFileSync(resolve(__dirname, 'src/index.css'), 'utf-8')
    ),
    __STATIC_CSS_RAW__: JSON.stringify(
      fs.readFileSync(resolve(__dirname, 'src/pages/StaticAnalysis.css'), 'utf-8')
    ),
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/__tests__/**/*.test.{ts,tsx}'],
    globals: false,
  },
});
