// jest.config.cjs
// The package is published as ESM ("type": "module"), and some source files
// rely on ESM-only features such as `import.meta.url` (see src/sarif.ts).
// Run ts-jest in ESM mode so tests exercise the same module semantics as the
// shipped build. (Requires Node's --experimental-vm-modules flag; see the
// "test" script in package.json.)
module.exports = {
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',
  testMatch: ['**/__tests__/**/*.test.ts'],
  extensionsToTreatAsEsm: ['.ts'],
  moduleNameMapper: {
    // Strip .js extensions so ts-jest can resolve .ts source files
    '^(\\.\\.?/.*)\\.js$': '$1',
  },
  transform: {
    // isolatedModules silences the hybrid-module-kind warning emitted when
    // ts-jest compiles the NodeNext tsconfig per-file.
    '^.+\\.tsx?$': ['ts-jest', { useESM: true, isolatedModules: true }],
  },
};
