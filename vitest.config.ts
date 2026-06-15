import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.spec.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: [
        'src/cosmic-crypt.ts',
        'src/cli/index.ts',
        'src/test/**'
      ],
      thresholds: {
        lines: 99,
        statements: 99,
        functions: 99,
        branches: 99
      },
      reporter: ['text-summary', 'html', 'lcov'],
      all: true
    }
  }
});
