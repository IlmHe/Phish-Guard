// jest.setup.ts
import '@testing-library/jest-dom';

jest.mock('webextension-polyfill', () => ({
  storage: { sync: { get: jest.fn(), set: jest.fn() } },
  runtime: { sendMessage: jest.fn(), onMessage: { addListener: jest.fn() } },
}));

// 2) make sure there’s a #root container before any React.createRoot calls
beforeAll(() => {
  const root = document.createElement('div')
  root.id = 'root'
  document.body.appendChild(root)
})
