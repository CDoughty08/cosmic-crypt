import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'cli/index': 'src/cli/index.ts',
  },
  platform: 'node',
  target: 'node24',
  format: ['esm'],
  dts: true,
  clean: true,
  sourcemap: false,
});
