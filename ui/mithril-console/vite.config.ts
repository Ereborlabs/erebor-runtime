import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [react()],
  build: {
    commonjsOptions: { include: [/node_modules/, /src\/generated/] },
    rolldownOptions: {
      input: { index: 'index.html', administrative: 'src/administrative.tsx' },
      output: {
        entryFileNames: (chunk) => chunk.name === 'administrative' ? 'assets/administrative.js' : 'assets/[name]-[hash].js',
        assetFileNames: (asset) => asset.names.includes('administrative.css') ? 'assets/administrative.css' : 'assets/[name]-[hash][extname]',
      },
    },
  },
  test: {
    include: ['src/**/*.test.ts'],
  },
});
