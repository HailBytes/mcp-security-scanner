// jest.config.cjs
module.exports = {
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',
  extensionsToTreatAsEsm: ['.ts'],
  testMatch: ['**/__tests__/**/*.test.ts'],
  moduleNameMapper: {
    // Strip .js extensions so ts-jest can resolve .ts source files
    '^(\\.\\.?/.*)\\.js$': '$1',
  },
  transform: {
    // Compile as ES modules so `import.meta` (used in src/sarif.ts) is supported.
    '^.+\\.tsx?$': [
      'ts-jest',
      { useESM: true, tsconfig: { module: 'ESNext', moduleResolution: 'node' } },
    ],
  },
};
