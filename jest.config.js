module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'jsdom',
  moduleNameMapper: {
    '\\.(css|less|scss)$': 'identity-obj-proxy'
  },
  setupFilesAfterEnv: ['<rootDir>/jest.setup.ts'],
  collectCoverage: true,
  collectCoverageFrom: ['src/**/*.{ts,tsx}', '!src/**/*.d.ts'],
  coveragePathIgnorePatterns: [
    '<rootDir>/src/background.ts',
    '<rootDir>/src/alert.ts',
    '<rootDir>/src/content.ts',
    '<rootDir>/src/settings/',
    '<rootDir>/src/index.ts',
    '<rootDir>/src/types.ts',
    '<rootDir>/src/Popup.tsx',
    '<rootDir>/src/components/'
  ],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 85,
      statements: 85
    }
  }
};
