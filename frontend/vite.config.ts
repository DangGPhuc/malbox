import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const configDir = dirname(fileURLToPath(import.meta.url));
const rootDir = resolve(configDir, '..');

function parseStrictPort(raw: string | undefined, fallback: number, name: string): number {
  const val = (raw ?? '').trim();
  if (!val) return fallback;
  if (!/^\d+$/.test(val)) {
    throw new Error(`Invalid ${name}='${raw}': must be an integer between 1 and 65535.`);
  }
  const num = Number(val);
  if (num < 1 || num > 65535) {
    throw new Error(`Invalid ${name}=${num}: must be between 1 and 65535.`);
  }
  return num;
}

export default defineConfig(({ mode }) => {
  const rootEnv = loadEnv(mode, rootDir, 'MALBOX_');
  const localEnv = loadEnv(mode, configDir, 'MALBOX_');
  const merged = { ...rootEnv, ...localEnv, ...process.env };

  const backendHostRaw = (merged.MALBOX_HOST || '127.0.0.1').trim();
  const proxyHost =
    backendHostRaw === '0.0.0.0' || backendHostRaw === '::' || !backendHostRaw
      ? '127.0.0.1'
      : backendHostRaw;

  const backendPort = parseStrictPort(merged.MALBOX_PORT, 8000, 'MALBOX_PORT');
  const frontendPort = parseStrictPort(merged.MALBOX_FRONTEND_PORT, 5173, 'MALBOX_FRONTEND_PORT');

  if (backendPort === frontendPort) {
    throw new Error(`Port collision: MALBOX_PORT and MALBOX_FRONTEND_PORT cannot both be ${backendPort}.`);
  }

  return {
    plugins: [react()],
    server: {
      port: frontendPort,
      proxy: {
        '/api': {
          target: `http://${proxyHost}:${backendPort}`,
          changeOrigin: true,
        },
      },
    },
  };
});
