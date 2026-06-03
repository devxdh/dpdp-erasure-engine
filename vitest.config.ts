import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: {
      '@': new URL('./src', import.meta.url).pathname,
      '@modules': new URL('./src/modules', import.meta.url).pathname,
    },
  },
  test: {
    fileParallelism: false,
  },
});