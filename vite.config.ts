import { defineConfig } from 'vite';
import path from 'node:path';

export default defineConfig({
  root: '.',
  publicDir: false,
  resolve: {
    alias: {
      'node:zlib': path.resolve(__dirname, 'client/shims/zlib.ts'),
      zlib: path.resolve(__dirname, 'client/shims/zlib.ts'),
    },
  },
  build: {
    outDir: 'public/emulation',
    emptyOutDir: true,
    sourcemap: true,
    target: 'es2022',
    commonjsOptions: {
      transformMixedEsModules: true,
    },
    rollupOptions: {
      input: {
        'linux-lab': path.resolve(__dirname, 'client/linux-lab.ts'),
        'powershell-lab': path.resolve(__dirname, 'client/powershell-lab.ts'),
        'windows-lab': path.resolve(__dirname, 'client/windows-lab.ts'),
      },
      output: {
        entryFileNames: '[name].js',
        chunkFileNames: 'chunks/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
  },
  optimizeDeps: {
    exclude: ['just-bash'],
  },
});
