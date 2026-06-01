// jest.config.cjs
// Run tests as ESM so the test environment matches the NodeNext ESM build
// (src/sarif.ts uses `import.meta.url`, which is invalid under CommonJS).
// Requires the `node --experimental-vm-modules` flag set by the test script.
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
    '^.+\\.tsx?$': [
      'ts-jest',
      { useESM: true, tsconfig: { module: 'ESNext' } },
    ],
  },
};
